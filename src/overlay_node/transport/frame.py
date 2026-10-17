"""Кодирование кадров и декодирование TCP-потока.

Формат заголовка из ТЗ (24 байта, сетевой порядок байтов):
version:1 | type:1 | flags:2 | request_id:16 | payload_length:4
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from overlay_node.config import CONFIG

HEADER = struct.Struct("!BBH16sI")
HEADER_SIZE = HEADER.size
MAX_FRAME_PAYLOAD = CONFIG["max_frame_payload"]
PROTOCOL_VERSION = CONFIG["protocol_version"]


def decode_header(header_bytes: bytes) -> tuple[int, int, int, bytes, int]:
    """Разбирает полный заголовок кадра без чтения payload."""
    if len(header_bytes) != HEADER_SIZE:
        raise FrameError(f"заголовок должен иметь длину {HEADER_SIZE} байт")
    return HEADER.unpack(header_bytes)


class FrameError(ValueError):
    """Некорректный кадр или поток кадров."""


@dataclass(frozen=True)
class Frame:
    version: int
    message_type: int
    flags: int
    request_id: bytes
    payload: bytes

    def __post_init__(self) -> None:
        if not 0 <= self.version <= 0xFF:
            raise FrameError("version должен помещаться в 1 байт")
        if not 0 <= self.message_type <= 0xFF:
            raise FrameError("message_type должен помещаться в 1 байт")
        if not 0 <= self.flags <= 0xFFFF:
            raise FrameError("flags должны помещаться в 2 байта")
        if len(self.request_id) != 16:
            raise FrameError("request_id должен иметь длину 16 байт")
        if len(self.payload) > MAX_FRAME_PAYLOAD:
            raise FrameError("payload превышает MAX_FRAME_PAYLOAD")


def encode_frame(frame: Frame) -> bytes:
    """Сериализует один кадр в байтовую последовательность."""
    header = HEADER.pack(
        frame.version,
        frame.message_type,
        frame.flags,
        frame.request_id,
        len(frame.payload),
    )
    return header + frame.payload


class FrameDecoder:
    """Накапливает произвольные TCP-фрагменты и выдаёт готовые кадры."""

    def __init__(self, max_payload: int = MAX_FRAME_PAYLOAD) -> None:
        if not 0 <= max_payload <= MAX_FRAME_PAYLOAD:
            raise ValueError("max_payload должен быть от 0 до 65 536")
        self._max_payload = max_payload
        self._buffer = bytearray()

    def feed(self, data: bytes) -> list[Frame]:
        """Добавляет часть потока и возвращает все полностью собранные кадры."""
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data должен быть байтовой последовательностью")
        self._buffer.extend(data)
        frames: list[Frame] = []

        while len(self._buffer) >= HEADER_SIZE:
            version, message_type, flags, request_id, payload_length = HEADER.unpack_from(self._buffer)
            # Проверяем длину до ожидания или копирования payload.
            if payload_length > self._max_payload:
                self._buffer.clear()
                raise FrameError(
                    f"payload_length={payload_length} превышает лимит {self._max_payload}"
                )
            frame_size = HEADER_SIZE + payload_length
            if len(self._buffer) < frame_size:
                break

            payload = bytes(self._buffer[HEADER_SIZE:frame_size])
            del self._buffer[:frame_size]
            frames.append(Frame(version, message_type, flags, request_id, payload))

        return frames
