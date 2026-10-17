"""TLS 1.3 mutual authentication and application-level replay protection."""

from __future__ import annotations

import asyncio
import os
import secrets
import ssl
import struct
import tempfile
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.x509.oid import NameOID

from overlay_node.identity import NodeIdentity, node_id_from_public_key
from overlay_node.transport.frame import (
    HEADER_SIZE,
    MAX_FRAME_PAYLOAD,
    PROTOCOL_VERSION,
    Frame,
    FrameError,
    decode_header,
    encode_frame,
)
from overlay_node.transport.tcp import read_frame, write_frame

TLS_DNS_NAME = "overlay-node"
SECURE_ENVELOPE_TYPE = 254
SESSION_HEADER = struct.Struct("!16sQ")
DEFAULT_CA_DIRECTORY = Path(os.environ.get("OVERLAY_CA_DIR", ".state/authority"))
DEFAULT_CERT_DIRECTORY = Path(".state/tls")
REPLAY_WINDOW_SECONDS = 600.0
MAX_REPLAY_ENTRIES = 100_000


class SecureSessionError(ValueError):
    """A TLS identity, protected envelope, or session check failed."""


class ReplayRejected(SecureSessionError):
    """A session counter or message identifier was seen before."""


@dataclass(frozen=True)
class SecureEnvelope:
    session_id: bytes
    counter: int
    frame: Frame


class ReplayGuard:
    """Bounded replay cache keyed by authenticated node ID and message ID."""

    def __init__(
        self,
        window_seconds: float = REPLAY_WINDOW_SECONDS,
        max_entries: int = MAX_REPLAY_ENTRIES,
    ) -> None:
        if window_seconds <= 0 or max_entries < 1:
            raise ValueError("ReplayGuard window and capacity must be positive")
        self.window_seconds = window_seconds
        self.max_entries = max_entries
        self._session_counters: OrderedDict[tuple[bytes, bytes], tuple[int, float]] = OrderedDict()
        self._message_ids: OrderedDict[tuple[bytes, bytes], float] = OrderedDict()

    def _expire(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._session_counters:
            _key, (_counter, seen_at) = next(iter(self._session_counters.items()))
            if seen_at > cutoff:
                break
            self._session_counters.popitem(last=False)
        while self._message_ids:
            _key, seen_at = next(iter(self._message_ids.items()))
            if seen_at > cutoff:
                break
            self._message_ids.popitem(last=False)

    def accept(
        self,
        peer_node_id: bytes,
        session_id: bytes,
        message_id: bytes,
        counter: int,
        now: float | None = None,
    ) -> None:
        if len(peer_node_id) != 32 or len(session_id) != 16 or len(message_id) != 16:
            raise SecureSessionError("Invalid NodeID, session_id, or message_id length")
        if not 0 <= counter <= 0xFFFFFFFFFFFFFFFF:
            raise SecureSessionError("Message counter is out of range")
        current_time = time.monotonic() if now is None else now
        self._expire(current_time)

        session_key = (peer_node_id, session_id)
        previous = self._session_counters.get(session_key)
        expected_counter = 0 if previous is None else previous[0] + 1
        if counter != expected_counter:
            raise ReplayRejected(
                f"Replay/out-of-order message: expected counter {expected_counter}, got {counter}"
            )

        message_key = (peer_node_id, message_id)
        if message_key in self._message_ids:
            raise ReplayRejected("Duplicate message_id from authenticated peer")
        if len(self._message_ids) >= self.max_entries:
            raise ReplayRejected("Replay cache is full; refusing messages fail-closed")

        self._session_counters[session_key] = (counter, current_time)
        self._session_counters.move_to_end(session_key)
        self._message_ids[message_key] = current_time
        self._message_ids.move_to_end(message_key)


_CONTEXT_CACHE: dict[tuple[bytes, str, str], tuple[ssl.SSLContext, ssl.SSLContext]] = {}


def _write_private_key(path: Path, key: Ed25519PrivateKey) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def _load_or_create_ca(ca_directory: Path) -> tuple[Ed25519PrivateKey, Path]:
    ca_directory.mkdir(parents=True, exist_ok=True)
    key_path = ca_directory / "coursework_ca_ed25519.key"
    cert_path = ca_directory / "coursework_ca_ed25519.crt"

    ca_key: Ed25519PrivateKey | None = None
    if key_path.exists():
        try:
            ca_key = Ed25519PrivateKey.from_private_bytes(key_path.read_bytes())
        except (ValueError, TypeError):
            ca_key = None

    if ca_key is None:
        ca_key = Ed25519PrivateKey.generate()
        _write_private_key(key_path, ca_key)

    if cert_path.exists():
        try:
            existing = x509.load_pem_x509_certificate(cert_path.read_bytes())
            existing_key = existing.public_key()
            subject_key_id = existing.extensions.get_extension_for_class(
                x509.SubjectKeyIdentifier
            ).value.digest
            authority_key_id = existing.extensions.get_extension_for_class(
                x509.AuthorityKeyIdentifier
            ).value.key_identifier
            expected_key_id = x509.SubjectKeyIdentifier.from_public_key(
                ca_key.public_key()
            ).digest
            if isinstance(existing_key, Ed25519PublicKey) and existing_key.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ) == ca_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ) and subject_key_id == expected_key_id and authority_key_id == expected_key_id:
                return ca_key, cert_path
        except (ValueError, TypeError, x509.ExtensionNotFound, AttributeError):
            pass

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Overlay P2P Coursework Test CA")])
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(ca_key, algorithm=None)
    )
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return ca_key, cert_path


def _node_certificate(
    identity: NodeIdentity,
    ca_key: Ed25519PrivateKey,
    ca_certificate_path: Path,
    certificate_path: Path,
) -> Path:
    certificate_path.parent.mkdir(parents=True, exist_ok=True)
    expected_public_key = identity.public_key_bytes
    expected_node_id = identity.node_id
    if certificate_path.exists():
        try:
            current = x509.load_pem_x509_certificate(certificate_path.read_bytes())
            public_key = current.public_key()
            san = current.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            if (
                isinstance(public_key, Ed25519PublicKey)
                and public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                == expected_public_key
                and f"urn:overlay:node:{expected_node_id.hex()}" in san.get_values_for_type(x509.UniformResourceIdentifier)
                and current.not_valid_after_utc > datetime.now(timezone.utc)
                and current.extensions.get_extension_for_class(
                    x509.AuthorityKeyIdentifier
                ).value.key_identifier
                == x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()).digest
                and current.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier
                ).value.digest
                == x509.SubjectKeyIdentifier.from_public_key(
                    identity.private_key.public_key()
                ).digest
            ):
                return certificate_path
        except (ValueError, TypeError, x509.ExtensionNotFound, AttributeError):
            pass

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, expected_node_id.hex())])
    ca_certificate = x509.load_pem_x509_certificate(ca_certificate_path.read_bytes())
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)
        .public_key(identity.private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(identity.private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(TLS_DNS_NAME),
                x509.UniformResourceIdentifier(f"urn:overlay:node:{expected_node_id.hex()}"),
            ]),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(ca_key, algorithm=None)
    )
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return certificate_path


def _load_identity_certificate(
    context: ssl.SSLContext,
    certificate_path: Path,
    identity: NodeIdentity,
) -> None:
    private_key_pem = identity.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with tempfile.NamedTemporaryFile(
        mode="wb", prefix="overlay-tls-key-", suffix=".pem", delete=False
    ) as temporary_key:
        temporary_key.write(private_key_pem)
        key_path = Path(temporary_key.name)
    try:
        context.load_cert_chain(str(certificate_path), str(key_path))
    finally:
        key_path.unlink(missing_ok=True)


def create_tls_contexts(
    identity: NodeIdentity,
    ca_directory: str | Path = DEFAULT_CA_DIRECTORY,
    cert_directory: str | Path = DEFAULT_CERT_DIRECTORY,
) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    """Return (server, client) TLS 1.3 contexts with mandatory client certs."""
    ca_directory = Path(ca_directory).resolve()
    cert_directory = Path(cert_directory).resolve()
    cache_key = (identity.node_id, str(ca_directory), str(cert_directory))
    cached = _CONTEXT_CACHE.get(cache_key)
    if cached is not None:
        return cached

    ca_key, ca_cert_path = _load_or_create_ca(ca_directory)
    node_cert_path = _node_certificate(
        identity,
        ca_key,
        ca_cert_path,
        cert_directory / f"{identity.node_id.hex()}.crt",
    )

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_3
    server_context.maximum_version = ssl.TLSVersion.TLSv1_3
    server_context.verify_mode = ssl.CERT_REQUIRED
    server_context.load_verify_locations(cafile=str(ca_cert_path))
    if hasattr(ssl, "OP_NO_TICKET"):
        server_context.options |= ssl.OP_NO_TICKET
    _load_identity_certificate(server_context, node_cert_path, identity)

    client_context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH,
        cafile=str(ca_cert_path),
    )
    client_context.minimum_version = ssl.TLSVersion.TLSv1_3
    client_context.maximum_version = ssl.TLSVersion.TLSv1_3
    client_context.check_hostname = True
    if hasattr(ssl, "OP_NO_TICKET"):
        client_context.options |= ssl.OP_NO_TICKET
    _load_identity_certificate(client_context, node_cert_path, identity)

    contexts = (server_context, client_context)
    _CONTEXT_CACHE[cache_key] = contexts
    return contexts


async def start_tls_server(
    client_connected_cb,
    host: str,
    port: int,
    identity: NodeIdentity,
    ca_directory: str | Path = DEFAULT_CA_DIRECTORY,
    cert_directory: str | Path = DEFAULT_CERT_DIRECTORY,
):
    server_context, _client_context = create_tls_contexts(
        identity, ca_directory, cert_directory
    )
    return await asyncio.start_server(
        client_connected_cb,
        host,
        port,
        ssl=server_context,
        ssl_handshake_timeout=5.0,
    )


def node_id_from_certificate(certificate_der: bytes) -> bytes:
    try:
        certificate = x509.load_der_x509_certificate(certificate_der)
        public_key = certificate.public_key()
        if not isinstance(public_key, Ed25519PublicKey):
            raise SecureSessionError("TLS certificate must use Ed25519")
        raw_public_key = public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        node_id = node_id_from_public_key(raw_public_key)
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except (ValueError, TypeError, x509.ExtensionNotFound) as exc:
        raise SecureSessionError("TLS peer certificate is invalid") from exc
    if TLS_DNS_NAME not in san.get_values_for_type(x509.DNSName):
        raise SecureSessionError("TLS certificate has an unexpected DNS identity")
    if f"urn:overlay:node:{node_id.hex()}" not in san.get_values_for_type(x509.UniformResourceIdentifier):
        raise SecureSessionError("TLS certificate NodeID SAN does not match its public key")
    return node_id


def peer_node_id(writer: asyncio.StreamWriter) -> bytes:
    ssl_object = writer.get_extra_info("ssl_object")
    if ssl_object is None:
        raise SecureSessionError("Overlay RPC requires an encrypted TLS session")
    if ssl_object.version() != "TLSv1.3":
        raise SecureSessionError("Only TLS 1.3 sessions are accepted")
    certificate = ssl_object.getpeercert(binary_form=True)
    if not certificate:
        raise SecureSessionError("TLS peer did not provide an identity certificate")
    return node_id_from_certificate(certificate)


async def open_tls_connection(
    host: str,
    port: int,
    identity: NodeIdentity,
    expected_node_id: bytes | None = None,
    timeout: float = 5.0,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, bytes]:
    _server_context, client_context = create_tls_contexts(identity)
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(
            host,
            port,
            ssl=client_context,
            server_hostname=TLS_DNS_NAME,
            ssl_handshake_timeout=timeout,
        ),
        timeout=timeout,
    )
    try:
        responder_node_id = peer_node_id(writer)
        if expected_node_id is not None and responder_node_id != expected_node_id:
            raise SecureSessionError("TLS peer certificate NodeID differs from expected contact")
        return reader, writer, responder_node_id
    except Exception:
        writer.close()
        await writer.wait_closed()
        raise


def _decode_inner_frame(encoded: bytes) -> Frame:
    if len(encoded) < HEADER_SIZE:
        raise FrameError("Secure envelope has a truncated inner frame")
    version, message_type, flags, request_id, payload_length = decode_header(encoded[:HEADER_SIZE])
    if version != PROTOCOL_VERSION:
        raise FrameError(f"Unsupported inner frame version: {version}")
    if payload_length > MAX_FRAME_PAYLOAD:
        raise FrameError("Inner frame payload exceeds configured maximum")
    if len(encoded) != HEADER_SIZE + payload_length:
        raise FrameError("Secure envelope contains trailing or truncated inner-frame bytes")
    return Frame(version, message_type, flags, request_id, encoded[HEADER_SIZE:])


async def write_secure_frame(
    writer: asyncio.StreamWriter,
    frame: Frame,
    session_id: bytes,
    counter: int,
    timeout: float = 5.0,
) -> None:
    if len(session_id) != 16:
        raise SecureSessionError("session_id must be 16 bytes")
    if not 0 <= counter <= 0xFFFFFFFFFFFFFFFF:
        raise SecureSessionError("Message counter is out of range")
    payload = SESSION_HEADER.pack(session_id, counter) + encode_frame(frame)
    if len(payload) > MAX_FRAME_PAYLOAD:
        raise FrameError("Secure envelope exceeds maximum frame payload")
    await write_frame(
        writer,
        Frame(PROTOCOL_VERSION, SECURE_ENVELOPE_TYPE, 0, frame.request_id, payload),
        timeout=timeout,
    )


async def read_secure_frame(
    reader: asyncio.StreamReader,
    peer_id: bytes,
    replay_guard: ReplayGuard | None,
    expected_session_id: bytes | None = None,
    expected_counter: int | None = None,
    timeout: float = 5.0,
) -> SecureEnvelope:
    outer = await read_frame(reader, timeout=timeout)
    if outer.message_type != SECURE_ENVELOPE_TYPE or outer.flags != 0:
        raise SecureSessionError("Expected a protected session envelope")
    minimum_size = SESSION_HEADER.size + HEADER_SIZE
    if len(outer.payload) < minimum_size:
        raise SecureSessionError("Protected session envelope is truncated")
    session_id, counter = SESSION_HEADER.unpack_from(outer.payload)
    inner = _decode_inner_frame(outer.payload[SESSION_HEADER.size:])
    if inner.request_id != outer.request_id:
        raise SecureSessionError("Envelope message_id does not match inner request_id")
    if expected_session_id is not None and session_id != expected_session_id:
        raise SecureSessionError("Response belongs to a different TLS application session")
    if expected_counter is not None and counter != expected_counter:
        raise SecureSessionError("Unexpected secure-session message counter")
    if replay_guard is not None:
        replay_guard.accept(peer_id, session_id, inner.request_id, counter)
    return SecureEnvelope(session_id, counter, inner)


def new_session_id() -> bytes:
    return secrets.token_bytes(16)
