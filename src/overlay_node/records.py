"""Подписанные адресные записи, размещаемые в DHT."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
from dataclasses import dataclass

from overlay_node.config import CONFIG
from overlay_node.identity import PUBLIC_KEY_SIZE, NodeIdentity, verify_node_id, verify_signature

RECORD_DOMAIN = b"overlay-p2p/node-record/v1\x00"
DHT_KEY_DOMAIN = b"node:"
MIN_TTL_SECONDS = CONFIG["dht_min_ttl_seconds"]
MAX_TTL_SECONDS = CONFIG["dht_max_ttl_seconds"]
DEFAULT_TTL_SECONDS = CONFIG["dht_ttl_seconds"]
MAX_RECORD_BYTES = CONFIG["max_record_bytes"]
MAX_ADDRESSES = CONFIG["max_node_addresses"]


class RecordError(ValueError):
    """Некорректная или недопустимая DHT-запись."""


def _canonical_json(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def node_record_key(node_id: bytes) -> bytes:
    if len(node_id) != 32:
        raise RecordError("NodeID должен занимать 32 байта")
    return hashlib.sha256(DHT_KEY_DOMAIN + node_id).digest()


def _valid_host(host: str) -> bool:
    if not host or len(host) > 253 or host.strip() != host or any(c.isspace() for c in host):
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    if host.lower() == "localhost":
        return True
    labels = host.rstrip(".").split(".")
    return all(
        1 <= len(label) <= 63
        and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label) is not None
        for label in labels
    )


@dataclass(frozen=True)
class NodeRecord:
    """Адрес владельца, заверенный долговременным ключом Ed25519."""

    node_id: bytes
    identity_public_key: bytes
    addresses: tuple[tuple[str, int], ...]
    sequence_number: int
    issued_at: int
    expires_at: int
    signature: bytes

    def unsigned_fields(self) -> dict:
        return {
            "addresses": [{"host": host, "port": port} for host, port in self.addresses],
            "expires_at": self.expires_at,
            "identity_public_key": self.identity_public_key.hex(),
            "issued_at": self.issued_at,
            "node_id": self.node_id.hex(),
            "sequence_number": self.sequence_number,
        }

    def signing_bytes(self) -> bytes:
        return RECORD_DOMAIN + _canonical_json(self.unsigned_fields())

    @property
    def dht_key(self) -> bytes:
        return node_record_key(self.node_id)

    def to_payload(self) -> bytes:
        fields = self.unsigned_fields()
        fields["signature"] = self.signature.hex()
        payload = _canonical_json(fields)
        if len(payload) > MAX_RECORD_BYTES:
            raise RecordError(f"Размер NodeRecord превышает {MAX_RECORD_BYTES} байт")
        return payload

    def validate(self, now: int | None = None) -> None:
        current_time = int(time.time()) if now is None else int(now)
        if len(self.node_id) != 32 or len(self.identity_public_key) != PUBLIC_KEY_SIZE:
            raise RecordError("NodeID и открытый ключ должны занимать 32 байта")
        if not verify_node_id(self.identity_public_key, self.node_id):
            raise RecordError("NodeID не соответствует открытому ключу записи")
        if len(self.signature) != 64 or not verify_signature(
            self.identity_public_key, self.signing_bytes(), self.signature
        ):
            raise RecordError("Подпись NodeRecord недействительна")
        if (
            not isinstance(self.sequence_number, int)
            or isinstance(self.sequence_number, bool)
            or self.sequence_number < 0
        ):
            raise RecordError("sequence_number должен быть неотрицательным целым числом")
        if (
            not isinstance(self.issued_at, int)
            or isinstance(self.issued_at, bool)
            or not isinstance(self.expires_at, int)
            or isinstance(self.expires_at, bool)
        ):
            raise RecordError("Временные метки должны быть целыми числами")
        if self.expires_at <= self.issued_at:
            raise RecordError("expires_at должен быть больше issued_at")
        ttl = self.expires_at - self.issued_at
        if not MIN_TTL_SECONDS <= ttl <= MAX_TTL_SECONDS:
            raise RecordError(f"TTL должен быть от {MIN_TTL_SECONDS} до {MAX_TTL_SECONDS} секунд")
        if self.issued_at > current_time + 30:
            raise RecordError("Запись имеет время выпуска из будущего")
        if self.expires_at <= current_time:
            raise RecordError("Срок действия NodeRecord истёк")
        if not 1 <= len(self.addresses) <= MAX_ADDRESSES:
            raise RecordError(f"Запись должна содержать от 1 до {MAX_ADDRESSES} адресов")
        if any(
            not isinstance(address, tuple)
            or len(address) != 2
            or not isinstance(address[0], str)
            or not isinstance(address[1], int)
            or isinstance(address[1], bool)
            for address in self.addresses
        ):
            raise RecordError("Адрес должен быть парой host и целочисленного TCP-порта")
        if len(set(self.addresses)) != len(self.addresses):
            raise RecordError("Адреса в записи не должны повторяться")
        for host, port in self.addresses:
            if not _valid_host(host) or isinstance(port, bool) or not 1 <= port <= 65535:
                raise RecordError("Некорректный host или TCP-порт в адресе")
        if len(self.to_payload()) > MAX_RECORD_BYTES:
            raise RecordError(f"Размер NodeRecord превышает {MAX_RECORD_BYTES} байт")

    @classmethod
    def create(
        cls,
        identity: NodeIdentity,
        addresses: tuple[tuple[str, int], ...],
        sequence_number: int,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        now: int | None = None,
    ) -> "NodeRecord":
        if not MIN_TTL_SECONDS <= ttl_seconds <= MAX_TTL_SECONDS:
            raise RecordError(f"TTL должен быть от {MIN_TTL_SECONDS} до {MAX_TTL_SECONDS} секунд")
        issued_at = int(time.time()) if now is None else int(now)
        normalized_addresses = tuple(sorted(set(addresses)))
        unsigned = cls(
            node_id=identity.node_id,
            identity_public_key=identity.public_key_bytes,
            addresses=normalized_addresses,
            sequence_number=sequence_number,
            issued_at=issued_at,
            expires_at=issued_at + ttl_seconds,
            signature=b"\x00" * 64,
        )
        record = cls(
            node_id=unsigned.node_id,
            identity_public_key=unsigned.identity_public_key,
            addresses=unsigned.addresses,
            sequence_number=unsigned.sequence_number,
            issued_at=unsigned.issued_at,
            expires_at=unsigned.expires_at,
            signature=identity.sign(unsigned.signing_bytes()),
        )
        record.validate(now=issued_at)
        return record

    @classmethod
    def from_payload(cls, payload: bytes, now: int | None = None) -> "NodeRecord":
        if len(payload) > MAX_RECORD_BYTES:
            raise RecordError(f"Размер NodeRecord превышает {MAX_RECORD_BYTES} байт")
        try:
            data = json.loads(payload.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RecordError("NodeRecord должен быть корректным JSON ASCII") from exc
        if not isinstance(data, dict):
            raise RecordError("NodeRecord должен быть JSON-объектом")
        try:
            raw_addresses = data["addresses"]
            if not isinstance(raw_addresses, list):
                raise TypeError
            addresses = tuple((item["host"], item["port"]) for item in raw_addresses)
            record = cls(
                node_id=bytes.fromhex(data["node_id"]),
                identity_public_key=bytes.fromhex(data["identity_public_key"]),
                addresses=addresses,
                sequence_number=data["sequence_number"],
                issued_at=data["issued_at"],
                expires_at=data["expires_at"],
                signature=bytes.fromhex(data["signature"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RecordError("NodeRecord имеет отсутствующие или некорректные поля") from exc
        record.validate(now=now)
        return record
