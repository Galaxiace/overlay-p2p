import asyncio
import uuid
from types import SimpleNamespace

import pytest

from overlay_node.demo import _handle_client, request_find_node
from overlay_node.identity import NodeIdentity
from overlay_node.protocol import FindNodeRequest, MessageType
from overlay_node import rpc
from overlay_node.routing import RoutingTable
from overlay_node.secure_session import (
    new_session_id,
    open_tls_connection,
    start_tls_server,
    write_secure_frame,
    SecureSessionError,
)
from overlay_node.transport.frame import Frame, PROTOCOL_VERSION


def test_ping_rejects_response_with_mismatched_request_id(tmp_path, monkeypatch):
    class DummyWriter:
        def close(self):
            pass

        async def wait_closed(self):
            pass

    async def scenario():
        identity = NodeIdentity.load_or_create(tmp_path / "requester")
        writer = DummyWriter()
        peer_id = b"p" * 32

        async def fake_open_tls_connection(*args, **kwargs):
            return asyncio.StreamReader(), writer, peer_id

        async def fake_write_secure_frame(*args, **kwargs):
            return None

        async def fake_read_secure_frame(*args, **kwargs):
            return SimpleNamespace(
                frame=Frame(
                    PROTOCOL_VERSION,
                    MessageType.PONG,
                    0,
                    b"x" * 16,
                    b"PONG",
                )
            )

        monkeypatch.setattr(rpc, "open_tls_connection", fake_open_tls_connection)
        monkeypatch.setattr(rpc, "write_secure_frame", fake_write_secure_frame)
        monkeypatch.setattr(rpc, "read_secure_frame", fake_read_secure_frame)

        with pytest.raises(ValueError, match="request_id"):
            await rpc.request_ping("127.0.0.1", 9000, identity)

    asyncio.run(scenario())


def test_find_node_rpc_returns_verified_peer_and_contact(tmp_path):
    async def scenario():
        responder = NodeIdentity.load_or_create(tmp_path / "responder")
        requester = NodeIdentity.load_or_create(tmp_path / "requester")
        table = RoutingTable(responder.node_id)

        async def handle(reader, writer):
            port = writer.get_extra_info("sockname")[1]
            await _handle_client(
                reader,
                writer,
                responder,
                table,
                ("127.0.0.1", port),
            )

        server = await start_tls_server(handle, "127.0.0.1", 0, responder)
        port = server.sockets[0].getsockname()[1]
        try:
            with pytest.raises(SecureSessionError, match="expected contact"):
                await request_find_node(
                    "127.0.0.1", port, requester, responder.node_id,
                    expected_node_id=b"z" * 32,
                )
            response = await request_find_node(
                "127.0.0.1", port, requester, responder.node_id
            )
            assert response.responder_node_id == responder.node_id
            assert any(contact.node_id == responder.node_id for contact in response.contacts)
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())


def test_tls_authenticated_node_cannot_claim_another_node_id(tmp_path):
    async def scenario():
        responder = NodeIdentity.load_or_create(tmp_path / "responder")
        authenticated_client = NodeIdentity.load_or_create(tmp_path / "client-a")
        substituted_identity = NodeIdentity.load_or_create(tmp_path / "client-b")
        table = RoutingTable(responder.node_id)

        async def handle(reader, writer):
            await _handle_client(
                reader,
                writer,
                responder,
                table,
                ("127.0.0.1", writer.get_extra_info("sockname")[1]),
                verbose=False,
            )

        server = await start_tls_server(handle, "127.0.0.1", 0, responder)
        port = server.sockets[0].getsockname()[1]
        reader, writer, peer_id = await open_tls_connection(
            "127.0.0.1", port, authenticated_client,
            expected_node_id=responder.node_id,
        )
        request_id = uuid.uuid4().bytes
        forged_request = FindNodeRequest.for_identity(
            substituted_identity, responder.node_id
        )
        try:
            await write_secure_frame(
                writer,
                Frame(
                    PROTOCOL_VERSION,
                    MessageType.FIND_NODE_REQUEST,
                    0,
                    request_id,
                    forged_request.to_payload(),
                ),
                new_session_id(),
                counter=0,
            )
            # The authenticated certificate says client A; payload claims client B.
            assert await asyncio.wait_for(reader.read(1), timeout=2) == b""
        finally:
            writer.close()
            await writer.wait_closed()
            server.close()
            await server.wait_closed()
        assert authenticated_client.node_id != substituted_identity.node_id
        assert peer_id == responder.node_id

    asyncio.run(scenario())
