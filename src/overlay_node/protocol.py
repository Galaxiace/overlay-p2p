"""Типы сообщений и JSON-сообщения управляющего протокола."""

import json
from dataclasses import dataclass
from enum import IntEnum

from overlay_node.identity import PUBLIC_KEY_SIZE as NODE_ID_SIZE
from overlay_node.identity import NodeIdentity, verify_node_id
from overlay_node.records import NodeRecord
from overlay_node.routing import Contact, RoutingError


class MessageType(IntEnum):
    PING = 1
    PONG = 2
    FIND_NODE_REQUEST = 3
    FIND_NODE_RESPONSE = 4
    STORE_REQUEST = 5
    STORE_RESPONSE = 6
    FIND_VALUE_REQUEST = 7
    FIND_VALUE_RESPONSE = 8
    ERROR = 255


def _encode_json(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _decode_json(payload: bytes) -> dict:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Payload должен содержать корректный JSON в UTF-8") from exc
    if not isinstance(value, dict):
        raise ValueError("Корневое значение JSON должно быть объектом")
    return value


def _read_hex(data: dict, field: str, expected_length: int) -> bytes:
    value = data.get(field)
    if not isinstance(value, str):
        raise ValueError(f"Поле {field} должно быть hex-строкой")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"Поле {field} содержит некорректный hex") from exc
    if len(decoded) != expected_length:
        raise ValueError(f"Поле {field} должно занимать {expected_length} байт")
    return decoded


@dataclass(frozen=True)
class FindNodeRequest:
    sender_node_id: bytes
    sender_public_key: bytes
    target_node_id: bytes
    sender_listen_port: int | None = None

    def __post_init__(self) -> None:
        if len(self.sender_node_id) != NODE_ID_SIZE or len(self.target_node_id) != NODE_ID_SIZE:
            raise ValueError(f"NodeID должен занимать {NODE_ID_SIZE} байт")
        if not verify_node_id(self.sender_public_key, self.sender_node_id):
            raise ValueError("sender_node_id не соответствует sender_public_key")
        if self.sender_listen_port is not None and not 1 <= self.sender_listen_port <= 65535:
            raise ValueError("sender_listen_port должен быть от 1 до 65535")

    @classmethod
    def for_identity(
        cls,
        identity: NodeIdentity,
        target_node_id: bytes,
        sender_listen_port: int | None = None,
    ) -> "FindNodeRequest":
        return cls(identity.node_id, identity.public_key_bytes, target_node_id, sender_listen_port)

    def to_payload(self) -> bytes:
        return _encode_json({
            "sender_node_id": self.sender_node_id.hex(),
            "sender_public_key": self.sender_public_key.hex(),
            "sender_listen_port": self.sender_listen_port,
            "target_node_id": self.target_node_id.hex(),
        })

    @classmethod
    def from_payload(cls, payload: bytes) -> "FindNodeRequest":
        data = _decode_json(payload)
        listen_port = data.get("sender_listen_port")
        if listen_port is not None and (
            not isinstance(listen_port, int) or isinstance(listen_port, bool)
        ):
            raise ValueError("sender_listen_port должен быть целым числом")
        return cls(
            sender_node_id=_read_hex(data, "sender_node_id", NODE_ID_SIZE),
            sender_public_key=_read_hex(data, "sender_public_key", NODE_ID_SIZE),
            target_node_id=_read_hex(data, "target_node_id", NODE_ID_SIZE),
            sender_listen_port=listen_port,
        )


@dataclass(frozen=True)
class FindNodeResponse:
    responder_node_id: bytes
    responder_public_key: bytes
    contacts: tuple[Contact, ...]

    def __post_init__(self) -> None:
        if not verify_node_id(self.responder_public_key, self.responder_node_id):
            raise ValueError("responder_node_id не соответствует responder_public_key")

    def to_payload(self) -> bytes:
        return _encode_json({
            "responder_node_id": self.responder_node_id.hex(),
            "responder_public_key": self.responder_public_key.hex(),
            "contacts": [
                {
                    "node_id": contact.node_id.hex(),
                    "host": contact.address[0],
                    "port": contact.address[1],
                }
                for contact in self.contacts
            ],
        })

    @classmethod
    def from_payload(cls, payload: bytes) -> "FindNodeResponse":
        data = _decode_json(payload)
        raw_contacts = data.get("contacts")
        if not isinstance(raw_contacts, list):
            raise ValueError("Поле contacts должно быть списком")
        contacts: list[Contact] = []
        try:
            for raw_contact in raw_contacts:
                if not isinstance(raw_contact, dict):
                    raise ValueError("Каждый контакт должен быть JSON-объектом")
                node_id = _read_hex(raw_contact, "node_id", NODE_ID_SIZE)
                host = raw_contact.get("host")
                port = raw_contact.get("port")
                if not isinstance(host, str) or not isinstance(port, int) or isinstance(port, bool):
                    raise ValueError("Контакт должен содержать host и числовой port")
                contacts.append(Contact(node_id, (host, port)))
        except RoutingError as exc:
            raise ValueError(f"Некорректный контакт в FIND_NODE_RESPONSE: {exc}") from exc

        return cls(
            responder_node_id=_read_hex(data, "responder_node_id", NODE_ID_SIZE),
            responder_public_key=_read_hex(data, "responder_public_key", NODE_ID_SIZE),
            contacts=tuple(contacts),
        )


@dataclass(frozen=True)
class StoreResponse:
    accepted: bool
    highest_sequence: int
    reason: str = ""

    def to_payload(self) -> bytes:
        return _encode_json({
            "accepted": self.accepted,
            "highest_sequence": self.highest_sequence,
            "reason": self.reason,
        })

    @classmethod
    def from_payload(cls, payload: bytes) -> "StoreResponse":
        data = _decode_json(payload)
        accepted = data.get("accepted")
        sequence = data.get("highest_sequence")
        reason = data.get("reason", "")
        if not isinstance(accepted, bool):
            raise ValueError("accepted должен быть логическим значением")
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < -1:
            raise ValueError("highest_sequence должен быть целым числом не меньше -1")
        if not isinstance(reason, str):
            raise ValueError("reason должен быть строкой")
        return cls(accepted, sequence, reason)


@dataclass(frozen=True)
class FindValueRequest:
    sender_node_id: bytes
    sender_public_key: bytes
    dht_key: bytes
    sender_listen_port: int | None = None

    def __post_init__(self) -> None:
        if len(self.dht_key) != NODE_ID_SIZE:
            raise ValueError("DHT key должен занимать 32 байта")
        if not verify_node_id(self.sender_public_key, self.sender_node_id):
            raise ValueError("sender_node_id не соответствует sender_public_key")
        if self.sender_listen_port is not None and not 1 <= self.sender_listen_port <= 65535:
            raise ValueError("sender_listen_port должен быть от 1 до 65535")

    @classmethod
    def for_identity(
        cls, identity: NodeIdentity, dht_key: bytes, sender_listen_port: int | None = None
    ) -> "FindValueRequest":
        return cls(identity.node_id, identity.public_key_bytes, dht_key, sender_listen_port)

    def to_payload(self) -> bytes:
        return _encode_json({
            "dht_key": self.dht_key.hex(),
            "sender_listen_port": self.sender_listen_port,
            "sender_node_id": self.sender_node_id.hex(),
            "sender_public_key": self.sender_public_key.hex(),
        })

    @classmethod
    def from_payload(cls, payload: bytes) -> "FindValueRequest":
        data = _decode_json(payload)
        listen_port = data.get("sender_listen_port")
        if listen_port is not None and (
            not isinstance(listen_port, int) or isinstance(listen_port, bool)
        ):
            raise ValueError("sender_listen_port должен быть целым числом")
        return cls(
            _read_hex(data, "sender_node_id", NODE_ID_SIZE),
            _read_hex(data, "sender_public_key", NODE_ID_SIZE),
            _read_hex(data, "dht_key", NODE_ID_SIZE),
            listen_port,
        )


@dataclass(frozen=True)
class FindValueResponse:
    responder_node_id: bytes
    responder_public_key: bytes
    dht_key: bytes
    record: NodeRecord | None
    contacts: tuple[Contact, ...]

    def __post_init__(self) -> None:
        if not verify_node_id(self.responder_public_key, self.responder_node_id):
            raise ValueError("responder_node_id не соответствует responder_public_key")
        if len(self.dht_key) != NODE_ID_SIZE:
            raise ValueError("DHT key должен занимать 32 байта")
        if self.record is not None and self.record.dht_key != self.dht_key:
            raise ValueError("NodeRecord не соответствует искомому DHT key")

    def to_payload(self) -> bytes:
        return _encode_json({
            "contacts": [
                {"node_id": c.node_id.hex(), "host": c.address[0], "port": c.address[1]}
                for c in self.contacts
            ],
            "dht_key": self.dht_key.hex(),
            "record": self.record.to_payload().decode("ascii") if self.record else None,
            "responder_node_id": self.responder_node_id.hex(),
            "responder_public_key": self.responder_public_key.hex(),
        })

    @classmethod
    def from_payload(cls, payload: bytes) -> "FindValueResponse":
        data = _decode_json(payload)
        raw_contacts = data.get("contacts")
        if not isinstance(raw_contacts, list):
            raise ValueError("Поле contacts должно быть списком")
        contacts = []
        for item in raw_contacts:
            if not isinstance(item, dict):
                raise ValueError("Каждый контакт должен быть JSON-объектом")
            node_id = _read_hex(item, "node_id", NODE_ID_SIZE)
            host, port = item.get("host"), item.get("port")
            if not isinstance(host, str) or not isinstance(port, int) or isinstance(port, bool):
                raise ValueError("Контакт должен содержать host и числовой port")
            try:
                contacts.append(Contact(node_id, (host, port)))
            except RoutingError as exc:
                raise ValueError(f"Некорректный контакт: {exc}") from exc
        raw_record = data.get("record")
        record = None
        if raw_record is not None:
            if not isinstance(raw_record, str):
                raise ValueError("record должен быть JSON-строкой или null")
            record = NodeRecord.from_payload(raw_record.encode("ascii"))
        return cls(
            _read_hex(data, "responder_node_id", NODE_ID_SIZE),
            _read_hex(data, "responder_public_key", NODE_ID_SIZE),
            _read_hex(data, "dht_key", NODE_ID_SIZE),
            record,
            tuple(contacts),
        )
