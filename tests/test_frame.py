import random

import pytest

from overlay_node.transport.frame import (
    HEADER_SIZE,
    MAX_FRAME_PAYLOAD,
    Frame,
    FrameDecoder,
    FrameError,
    encode_frame,
)


def make_frame(index: int) -> Frame:
    return Frame(
        version=1,
        message_type=index % 256,
        flags=index % 4,
        request_id=index.to_bytes(16, "big"),
        payload=(f"message-{index}".encode("ascii")),
    )


def test_header_is_24_bytes_and_round_trip():
    frame = make_frame(42)
    encoded = encode_frame(frame)
    assert HEADER_SIZE == 24
    assert FrameDecoder().feed(encoded) == [frame]


def test_decoder_handles_100_frames_with_random_tcp_fragmentation():
    frames = [make_frame(i) for i in range(100)]
    stream = b"".join(map(encode_frame, frames))
    rng = random.Random(2026)
    decoder = FrameDecoder()
    decoded = []
    offset = 0
    while offset < len(stream):
        step = rng.randint(1, 47)
        decoded.extend(decoder.feed(stream[offset : offset + step]))
        offset += step
    assert decoded == frames


def test_decoder_waits_for_partial_header_and_payload():
    frame = make_frame(7)
    encoded = encode_frame(frame)
    decoder = FrameDecoder()
    assert decoder.feed(encoded[:9]) == []
    assert decoder.feed(encoded[9:HEADER_SIZE + 2]) == []
    assert decoder.feed(encoded[HEADER_SIZE + 2:]) == [frame]


def test_decoder_returns_multiple_frames_in_one_feed():
    frames = [make_frame(1), make_frame(2), make_frame(3)]
    assert FrameDecoder().feed(b"".join(map(encode_frame, frames))) == frames


def test_oversized_payload_is_rejected_from_header():
    decoder = FrameDecoder(max_payload=8)
    header_with_oversized_length = (
        b"\x01\x01\x00\x00" + b"0" * 16 + (9).to_bytes(4, "big")
    )
    with pytest.raises(FrameError, match="превышает лимит"):
        decoder.feed(header_with_oversized_length)


def test_frame_rejects_payload_larger_than_protocol_limit():
    with pytest.raises(FrameError, match="превышает"):
        Frame(1, 1, 0, b"0" * 16, b"x" * (MAX_FRAME_PAYLOAD + 1))
