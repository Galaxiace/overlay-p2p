"""Передача кадров поверх TCP без потери границ сообщений."""

from __future__ import annotations

import asyncio
from asyncio import StreamReader, StreamWriter

from overlay_node.config import CONFIG
from overlay_node.transport.frame import (
    HEADER_SIZE,
    MAX_FRAME_PAYLOAD,
    PROTOCOL_VERSION,
    Frame,
    FrameError,
    decode_header,
    encode_frame,
)

FRAME_TIMEOUT_SECONDS = CONFIG["frame_timeout_seconds"]


class PeerClosed(ConnectionError):
    """Удалённый узел закрыл соединение между кадрами."""


async def read_frame(reader: StreamReader, timeout: float = FRAME_TIMEOUT_SECONDS) -> Frame:
    """Читает один кадр, даже если TCP передаёт его частями."""
    try:
        header_bytes = await asyncio.wait_for(reader.readexactly(HEADER_SIZE), timeout)
    except asyncio.IncompleteReadError as exc:
        if not exc.partial:
            raise PeerClosed("Удалённый узел закрыл соединение") from exc
        raise FrameError("Соединение оборвалось внутри заголовка кадра") from exc
    except asyncio.TimeoutError as exc:
        raise TimeoutError("Истекло время ожидания заголовка кадра") from exc

    version, message_type, flags, request_id, payload_length = decode_header(header_bytes)
    if version != PROTOCOL_VERSION:
        raise FrameError(f"Неподдерживаемая версия протокола: {version}")
    if payload_length > MAX_FRAME_PAYLOAD:
        raise FrameError(
            f"payload_length={payload_length} превышает лимит {MAX_FRAME_PAYLOAD}"
        )

    try:
        payload = await asyncio.wait_for(reader.readexactly(payload_length), timeout)
    except asyncio.IncompleteReadError as exc:
        raise FrameError("Соединение оборвалось внутри payload кадра") from exc
    except asyncio.TimeoutError as exc:
        raise TimeoutError("Истекло время ожидания payload кадра") from exc

    return Frame(version, message_type, flags, request_id, payload)


async def write_frame(
    writer: StreamWriter, frame: Frame, timeout: float = FRAME_TIMEOUT_SECONDS
) -> None:
    """Отправляет полный кадр и дожидается передачи данных в TCP-поток."""
    writer.write(encode_frame(frame))
    try:
        await asyncio.wait_for(writer.drain(), timeout)
    except asyncio.TimeoutError as exc:
        raise TimeoutError("Истекло время отправки кадра") from exc
