"""Kademlia routing table with fixed-capacity LRU-like k-buckets."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable

from overlay_node.config import CONFIG

NODE_ID_SIZE = 32
ID_BITS = NODE_ID_SIZE * 8
K_BUCKET_SIZE = CONFIG["k_bucket_size"]


class RoutingError(ValueError):
    """Invalid NodeID or routing table configuration."""


def xor_distance(left: bytes, right: bytes) -> int:
    """Return the Kademlia XOR distance between two 256-bit NodeIDs."""
    if len(left) != NODE_ID_SIZE or len(right) != NODE_ID_SIZE:
        raise RoutingError(f"NodeID must be exactly {NODE_ID_SIZE} bytes")
    return int.from_bytes(left, "big") ^ int.from_bytes(right, "big")


def bucket_index(local_node_id: bytes, remote_node_id: bytes) -> int:
    """Map a nonzero XOR distance to a bucket index in [0, 255]."""
    distance = xor_distance(local_node_id, remote_node_id)
    if distance == 0:
        raise RoutingError("A node cannot add itself to its routing table")
    return distance.bit_length() - 1


@dataclass(frozen=True)
class Contact:
    """A peer known to this node; address is an underlay host and TCP port."""

    node_id: bytes
    address: tuple[str, int]
    last_seen: float = 0.0

    def __post_init__(self) -> None:
        if len(self.node_id) != NODE_ID_SIZE:
            raise RoutingError(f"NodeID must be exactly {NODE_ID_SIZE} bytes")
        host, port = self.address
        if not host:
            raise RoutingError("Contact host cannot be empty")
        if not 1 <= port <= 65535:
            raise RoutingError("Contact port must be between 1 and 65535")


PingContact = Callable[[Contact], Awaitable[bool]]


class RoutingTable:
    """A 256-bucket Kademlia table; each bucket keeps at most ``k`` contacts.

    Contacts are ordered from least recently seen to most recently seen.
    When a bucket is full, its oldest contact is pinged before it can be
    replaced. A responsive old contact is retained and moved to the end.
    """

    def __init__(self, local_node_id: bytes, k: int = K_BUCKET_SIZE) -> None:
        if len(local_node_id) != NODE_ID_SIZE:
            raise RoutingError(f"NodeID must be exactly {NODE_ID_SIZE} bytes")
        if k < 1:
            raise RoutingError("k must be at least 1")
        self.local_node_id = local_node_id
        self.k = k
        self._buckets: list[list[Contact]] = [[] for _ in range(ID_BITS)]

    def add_contact(self, contact: Contact, now: float = 0.0) -> bool:
        """Insert/update a contact if its bucket has room; return whether added.

        A full bucket is intentionally not changed here. Call
        ``add_contact_with_probe`` to perform the required LRU ping first.
        """
        index = bucket_index(self.local_node_id, contact.node_id)
        bucket = self._buckets[index]
        for position, existing in enumerate(bucket):
            if existing.node_id == contact.node_id:
                bucket.pop(position)
                bucket.append(replace(contact, last_seen=now))
                return False
        if len(bucket) >= self.k:
            return False
        bucket.append(replace(contact, last_seen=now))
        return True

    async def add_contact_with_probe(
        self, contact: Contact, ping_contact: PingContact, now: float = 0.0
    ) -> bool:
        """Insert a peer, pinging the least-recent contact before eviction.

        Returns True when the new contact is inserted and False when it is
        already known or an existing responsive contact is kept.
        """
        index = bucket_index(self.local_node_id, contact.node_id)
        bucket = self._buckets[index]
        for position, existing in enumerate(bucket):
            if existing.node_id == contact.node_id:
                bucket.pop(position)
                bucket.append(replace(contact, last_seen=now))
                return False

        if len(bucket) < self.k:
            bucket.append(replace(contact, last_seen=now))
            return True

        oldest = bucket[0]
        try:
            is_alive = await ping_contact(oldest)
        except (TimeoutError, ConnectionError):
            is_alive = False
        if is_alive:
            bucket.pop(0)
            bucket.append(replace(oldest, last_seen=now))
            return False

        bucket.pop(0)
        bucket.append(replace(contact, last_seen=now))
        return True

    def remove_contact(self, node_id: bytes) -> bool:
        """Remove a peer by ID; return True if it was present."""
        index = bucket_index(self.local_node_id, node_id)
        bucket = self._buckets[index]
        for position, contact in enumerate(bucket):
            if contact.node_id == node_id:
                bucket.pop(position)
                return True
        return False

    def get_bucket(self, index: int) -> tuple[Contact, ...]:
        if not 0 <= index < ID_BITS:
            raise IndexError(f"bucket index must be in [0, {ID_BITS - 1}]")
        return tuple(self._buckets[index])

    def closest(self, target_node_id: bytes, count: int | None = None) -> list[Contact]:
        """Return known contacts ordered by XOR distance to the target."""
        if len(target_node_id) != NODE_ID_SIZE:
            raise RoutingError(f"NodeID must be exactly {NODE_ID_SIZE} bytes")
        if count is not None and count < 0:
            raise RoutingError("count cannot be negative")
        contacts = [contact for bucket in self._buckets for contact in bucket]
        contacts.sort(key=lambda contact: xor_distance(contact.node_id, target_node_id))
        return contacts if count is None else contacts[:count]

    @property
    def contact_count(self) -> int:
        return sum(len(bucket) for bucket in self._buckets)

    def snapshot(self) -> dict[int, tuple[Contact, ...]]:
        """Return only nonempty buckets for diagnostics and later metrics."""
        return {
            index: tuple(bucket)
            for index, bucket in enumerate(self._buckets)
            if bucket
        }

    def export_json(self, path: str | Path) -> Path:
        """Write the current routing table, including bucket membership, as JSON."""
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        buckets = [
            {
                "index": index,
                "contacts": [
                    {
                        "node_id": contact.node_id.hex(),
                        "host": contact.address[0],
                        "port": contact.address[1],
                        "last_seen": contact.last_seen,
                    }
                    for contact in contacts
                ],
            }
            for index, contacts in self.snapshot().items()
        ]
        document = {
            "format_version": 1,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "local_node_id": self.local_node_id.hex(),
            "k": self.k,
            "bucket_count_total": ID_BITS,
            "bucket_count_nonempty": len(buckets),
            "contact_count": self.contact_count,
            "buckets": buckets,
        }
        destination.write_text(
            json.dumps(document, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return destination
