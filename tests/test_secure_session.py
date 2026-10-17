import asyncio
import ssl
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from overlay_node.identity import NodeIdentity
from overlay_node.secure_session import (
    ReplayGuard,
    ReplayRejected,
    SecureSessionError,
    SECURE_ENVELOPE_TYPE,
    SESSION_HEADER,
    create_tls_contexts,
    node_id_from_certificate,
    read_secure_frame,
)
from overlay_node.transport.frame import Frame, PROTOCOL_VERSION, encode_frame


def test_tls_contexts_require_mutual_tls13_and_bind_certificate_to_node_id(tmp_path):
    identity = NodeIdentity.load_or_create(tmp_path / "identity")
    server_context, client_context = create_tls_contexts(
        identity,
        ca_directory=tmp_path / "authority",
        cert_directory=tmp_path / "certificates",
    )
    certificate_path = tmp_path / "certificates" / f"{identity.node_id.hex()}.crt"
    certificate = x509.load_pem_x509_certificate(certificate_path.read_bytes())

    assert server_context.minimum_version == ssl.TLSVersion.TLSv1_3
    assert server_context.maximum_version == ssl.TLSVersion.TLSv1_3
    assert client_context.minimum_version == ssl.TLSVersion.TLSv1_3
    assert client_context.maximum_version == ssl.TLSVersion.TLSv1_3
    assert server_context.verify_mode == ssl.CERT_REQUIRED
    assert server_context.options & ssl.OP_NO_TICKET
    assert node_id_from_certificate(
        certificate.public_bytes(serialization.Encoding.DER)
    ) == identity.node_id


def test_certificate_with_substituted_node_id_is_rejected(tmp_path):
    identity = NodeIdentity.load_or_create(tmp_path / "identity")
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    wrong_id = b"x" * 32
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "forged")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "forged")]))
        .public_key(identity.private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("overlay-node"),
                x509.UniformResourceIdentifier(f"urn:overlay:node:{wrong_id.hex()}"),
            ]),
            critical=False,
        )
        .sign(identity.private_key, algorithm=None)
    )
    with pytest.raises(SecureSessionError, match="does not match its public key"):
        node_id_from_certificate(certificate.public_bytes(serialization.Encoding.DER))


def test_tls12_only_client_cannot_connect_to_tls13_overlay(tmp_path):
    async def scenario():
        identity = NodeIdentity.load_or_create(tmp_path / "identity")
        server_context, client_context = create_tls_contexts(
            identity,
            ca_directory=tmp_path / "authority",
            cert_directory=tmp_path / "certificates",
        )

        async def handle(_reader, writer):
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(
            handle,
            "127.0.0.1",
            0,
            ssl=server_context,
            ssl_handshake_timeout=2,
        )
        port = server.sockets[0].getsockname()[1]
        client_context.minimum_version = ssl.TLSVersion.TLSv1_2
        client_context.maximum_version = ssl.TLSVersion.TLSv1_2
        try:
            with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
                await asyncio.wait_for(
                    asyncio.open_connection(
                        "127.0.0.1",
                        port,
                        ssl=client_context,
                        server_hostname="overlay-node",
                        ssl_handshake_timeout=2,
                    ),
                    timeout=3,
                )
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())


def test_tls_rejects_altered_ciphertext_without_releasing_plaintext(tmp_path):
    client_identity = NodeIdentity.load_or_create(tmp_path / "client")
    server_identity = NodeIdentity.load_or_create(tmp_path / "server")
    ca_dir = tmp_path / "authority"
    cert_dir = tmp_path / "certificates"
    _client_server_contexts, client_context = create_tls_contexts(
        client_identity, ca_dir, cert_dir
    )
    server_context, _server_client_contexts = create_tls_contexts(
        server_identity, ca_dir, cert_dir
    )

    client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = client_context.wrap_bio(
        client_in, client_out, server_side=False, server_hostname="overlay-node"
    )
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    client_done = server_done = False

    for _ in range(20):
        if not client_done:
            try:
                client.do_handshake()
                client_done = True
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass
        client_bytes = client_out.read()
        if client_bytes:
            server_in.write(client_bytes)

        if not server_done:
            try:
                server.do_handshake()
                server_done = True
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass
        server_bytes = server_out.read()
        if server_bytes:
            client_in.write(server_bytes)
        if client_done and server_done:
            break
    assert client_done and server_done, "TLS 1.3 mutual-auth handshake did not complete"

    client.write(b"sensitive application payload")
    ciphertext = bytearray(client_out.read())
    assert ciphertext
    ciphertext[-1] ^= 0x01
    server_in.write(ciphertext)
    with pytest.raises(ssl.SSLError):
        server.read(1024)


def test_replay_guard_rejects_duplicate_in_current_and_completed_sessions():
    guard = ReplayGuard(window_seconds=60, max_entries=10)
    peer_id = b"p" * 32
    session_id = b"s" * 16
    message_id = b"m" * 16

    guard.accept(peer_id, session_id, message_id, counter=0, now=10)
    with pytest.raises(ReplayRejected):
        guard.accept(peer_id, session_id, message_id, counter=0, now=11)
    with pytest.raises(ReplayRejected):
        guard.accept(peer_id, b"n" * 16, message_id, counter=0, now=12)


def test_replay_guard_requires_contiguous_counter_and_expires_entries():
    guard = ReplayGuard(window_seconds=10, max_entries=10)
    peer_id = b"p" * 32
    session_id = b"s" * 16
    with pytest.raises(ReplayRejected):
        guard.accept(peer_id, session_id, b"a" * 16, counter=1, now=10)
    guard.accept(peer_id, session_id, b"a" * 16, counter=0, now=10)
    guard.accept(peer_id, session_id, b"b" * 16, counter=1, now=11)
    guard.accept(peer_id, session_id, b"a" * 16, counter=0, now=21)


def test_secure_envelope_rejects_message_id_mismatch():
    async def scenario():
        inner = Frame(PROTOCOL_VERSION, 1, 0, b"i" * 16, b"payload")
        outer = Frame(
            PROTOCOL_VERSION,
            SECURE_ENVELOPE_TYPE,
            0,
            b"o" * 16,
            SESSION_HEADER.pack(b"s" * 16, 0) + encode_frame(inner),
        )
        reader = asyncio.StreamReader()
        reader.feed_data(encode_frame(outer))
        reader.feed_eof()
        with pytest.raises(SecureSessionError, match="message_id"):
            await read_secure_frame(reader, b"p" * 32, None)

    asyncio.run(scenario())
