"""Client-side RPC helpers for peer-to-peer protocol messages."""

from __future__ import annotations

import uuid

from overlay_node.config import CONFIG
from overlay_node.identity import NodeIdentity
from overlay_node.protocol import (
    FindNodeRequest,
    FindNodeResponse,
    FindValueRequest,
    FindValueResponse,
    MessageType,
    StoreResponse,
)
from overlay_node.records import NodeRecord
from overlay_node.secure_session import (
    new_session_id,
    open_tls_connection,
    read_secure_frame,
    write_secure_frame,
)
from overlay_node.transport.frame import Frame, PROTOCOL_VERSION

RPC_TIMEOUT_SECONDS = CONFIG["rpc_timeout_seconds"]
PING_TIMEOUT_SECONDS = CONFIG["ping_timeout_seconds"]


async def request_ping(
    host: str,
    port: int,
    identity: NodeIdentity,
    timeout: float = PING_TIMEOUT_SECONDS,
    expected_node_id: bytes | None = None,
    message: bytes = b"bootstrap",
) -> None:
    """Send a PING and require a matching PONG before using a bootstrap peer."""
    reader, writer, peer_id = await open_tls_connection(
        host, port, identity, expected_node_id=expected_node_id, timeout=timeout
    )
    request_id = uuid.uuid4().bytes
    session_id = new_session_id()
    try:
        await write_secure_frame(
            writer,
            Frame(PROTOCOL_VERSION, MessageType.PING, 0, request_id, message),
            session_id,
            counter=0,
            timeout=timeout,
        )
        response = (
            await read_secure_frame(
                reader, peer_id, None, session_id, expected_counter=1, timeout=timeout
            )
        ).frame
        if response.request_id != request_id:
            raise ValueError("Ответ PONG содержит другой request_id")
        if response.message_type != MessageType.PONG:
            raise ValueError(
                f"Ожидался PONG, получен тип {response.message_type}"
            )
    finally:
        writer.close()
        await writer.wait_closed()


async def request_find_node(
    host: str,
    port: int,
    identity: NodeIdentity,
    target_node_id: bytes,
    sender_listen_port: int | None = None,
    expected_node_id: bytes | None = None,
) -> FindNodeResponse:
    """Send one FIND_NODE RPC and validate its request and peer identity."""
    reader, writer, peer_id = await open_tls_connection(
        host,
        port,
        identity,
        expected_node_id=expected_node_id,
        timeout=RPC_TIMEOUT_SECONDS,
    )
    request_id = uuid.uuid4().bytes
    session_id = new_session_id()
    request = Frame(
        PROTOCOL_VERSION,
        MessageType.FIND_NODE_REQUEST,
        0,
        request_id,
        FindNodeRequest.for_identity(
            identity, target_node_id, sender_listen_port=sender_listen_port
        ).to_payload(),
    )
    try:
        await write_secure_frame(writer, request, session_id, 0, timeout=RPC_TIMEOUT_SECONDS)
        response = (
            await read_secure_frame(
                reader, peer_id, None, session_id, 1, timeout=RPC_TIMEOUT_SECONDS
            )
        ).frame
        if response.request_id != request_id:
            raise ValueError("Ответ содержит другой request_id")
        if response.message_type == MessageType.ERROR:
            raise ValueError(
                f"Узел отклонил запрос: {response.payload.decode('utf-8', errors='replace')}"
            )
        if response.message_type != MessageType.FIND_NODE_RESPONSE:
            raise ValueError(
                f"Ожидался FIND_NODE_RESPONSE, получен тип {response.message_type}"
            )
        result = FindNodeResponse.from_payload(response.payload)
        if result.responder_node_id != peer_id:
            raise ValueError("FIND_NODE responder NodeID does not match its TLS certificate")
        if expected_node_id is not None and result.responder_node_id != expected_node_id:
            raise ValueError("Ответивший NodeID не совпадает с ожидаемым контактом")
        return result
    finally:
        writer.close()
        await writer.wait_closed()


async def request_store(
    host: str,
    port: int,
    record: NodeRecord,
    identity: NodeIdentity,
    timeout: float = RPC_TIMEOUT_SECONDS,
    expected_node_id: bytes | None = None,
) -> StoreResponse:
    """Отправить подписанную запись хранителю и получить подтверждение."""
    reader, writer, peer_id = await open_tls_connection(
        host,
        port,
        identity,
        expected_node_id=expected_node_id,
        timeout=timeout,
    )
    request_id = uuid.uuid4().bytes
    session_id = new_session_id()
    try:
        await write_secure_frame(
            writer,
            Frame(PROTOCOL_VERSION, MessageType.STORE_REQUEST, 0, request_id, record.to_payload()),
            session_id,
            counter=0,
            timeout=timeout,
        )
        response = (
            await read_secure_frame(
                reader, peer_id, None, session_id, expected_counter=1, timeout=timeout
            )
        ).frame
        if response.request_id != request_id:
            raise ValueError("Ответ STORE содержит другой request_id")
        if response.message_type == MessageType.ERROR:
            raise ValueError(response.payload.decode("utf-8", errors="replace"))
        if response.message_type != MessageType.STORE_RESPONSE:
            raise ValueError(f"Ожидался STORE_RESPONSE, получен тип {response.message_type}")
        return StoreResponse.from_payload(response.payload)
    finally:
        writer.close()
        await writer.wait_closed()


async def request_find_value(
    host: str,
    port: int,
    identity: NodeIdentity,
    dht_key: bytes,
    sender_listen_port: int | None = None,
    expected_node_id: bytes | None = None,
    timeout: float = RPC_TIMEOUT_SECONDS,
) -> FindValueResponse:
    """Запросить значение или ближайшие контакты у одного узла."""
    reader, writer, peer_id = await open_tls_connection(
        host,
        port,
        identity,
        expected_node_id=expected_node_id,
        timeout=timeout,
    )
    request_id = uuid.uuid4().bytes
    session_id = new_session_id()
    payload = FindValueRequest.for_identity(
        identity, dht_key, sender_listen_port=sender_listen_port
    ).to_payload()
    try:
        await write_secure_frame(
            writer,
            Frame(PROTOCOL_VERSION, MessageType.FIND_VALUE_REQUEST, 0, request_id, payload),
            session_id,
            counter=0,
            timeout=timeout,
        )
        response = (
            await read_secure_frame(
                reader, peer_id, None, session_id, expected_counter=1, timeout=timeout
            )
        ).frame
        if response.request_id != request_id:
            raise ValueError("Ответ FIND_VALUE содержит другой request_id")
        if response.message_type == MessageType.ERROR:
            raise ValueError(response.payload.decode("utf-8", errors="replace"))
        if response.message_type != MessageType.FIND_VALUE_RESPONSE:
            raise ValueError(
                f"Ожидался FIND_VALUE_RESPONSE, получен тип {response.message_type}"
            )
        result = FindValueResponse.from_payload(response.payload)
        if result.responder_node_id != peer_id:
            raise ValueError("FIND_VALUE responder NodeID does not match its TLS certificate")
        if result.dht_key != dht_key:
            raise ValueError("Ответ относится к другому DHT key")
        if expected_node_id is not None and result.responder_node_id != expected_node_id:
            raise ValueError("Ответивший NodeID не совпадает с ожидаемым контактом")
        return result
    finally:
        writer.close()
        await writer.wait_closed()
