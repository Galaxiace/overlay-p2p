"""Репликация и итеративный FIND_VALUE для учебной DHT."""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass

from overlay_node.config import CONFIG
from overlay_node.dht_store import DHTStore
from overlay_node.identity import NodeIdentity, verify_node_id
from overlay_node.lookup import iterative_find_node
from overlay_node.records import NodeRecord
from overlay_node.routing import Contact, RoutingTable, xor_distance
from overlay_node.rpc import request_find_value, request_store

REPLICATION_FACTOR = CONFIG["replication_factor"]
STORE_QUORUM = CONFIG["store_quorum"]
ALPHA = CONFIG["alpha"]
MAX_HOPS = CONFIG["lookup_max_hops"]
LOOKUP_POOL_SIZE = CONFIG["lookup_pool_size"]


@dataclass(frozen=True)
class StoreResult:
    record_key: bytes
    selected_node_ids: tuple[str, ...]
    acknowledged_node_ids: tuple[str, ...]
    errors: tuple[str, ...]
    success: bool


@dataclass(frozen=True)
class ValueLookupResult:
    lookup_id: str
    dht_key: bytes
    record: NodeRecord | None
    iterations: tuple[tuple[str, ...], ...]
    rpc_count: int
    errors: tuple[str, ...]
    duration_ms: float


async def replicate_record(
    record: NodeRecord,
    identity: NodeIdentity,
    routing_table: RoutingTable,
    local_store: DHTStore | None,
    local_address: tuple[str, int],
    bootstrap_addresses: tuple[tuple[str, int], ...] = (),
    listen_port: int | None = None,
    replication_factor: int = REPLICATION_FACTOR,
    quorum: int = STORE_QUORUM,
) -> StoreResult:
    """Разместить запись на R ближайших доступных узлах, включая локальный."""
    record.validate()
    if record.node_id != identity.node_id:
        raise ValueError("Публиковать можно только запись собственной идентичности")
    if replication_factor < 1 or not 1 <= quorum <= replication_factor:
        raise ValueError("Некорректные параметры репликации или quorum")

    if bootstrap_addresses:
        # Lookup обновляет локальный пул кандидатов и находит ближайших соседей.
        await iterative_find_node(
            target_node_id=record.dht_key,
            identity=identity,
            routing_table=routing_table,
            bootstrap_addresses=bootstrap_addresses,
            listen_port=listen_port,
        )

    local_contact = Contact(identity.node_id, local_address)
    candidates = {contact.node_id: contact for contact in routing_table.closest(record.dht_key)}
    candidates[identity.node_id] = local_contact
    ordered = sorted(
        candidates.values(), key=lambda c: xor_distance(c.node_id, record.dht_key)
    )

    selected: list[str] = []
    acknowledged: list[str] = []
    errors: list[str] = []
    # Continue past unreachable candidates so R means R responsive replicas.
    for contact in ordered:
        if len(acknowledged) >= replication_factor:
            break
        selected.append(contact.node_id.hex())
        if contact.node_id == identity.node_id and local_store is not None:
            decision = local_store.put(record)
            if decision.accepted:
                acknowledged.append(contact.node_id.hex())
            else:
                errors.append(f"{contact.node_id.hex()}: {decision.reason}")
            continue
        try:
            response = await request_store(
                contact.address[0],
                contact.address[1],
                record,
                identity,
                expected_node_id=contact.node_id,
            )
            if response.accepted:
                acknowledged.append(contact.node_id.hex())
            else:
                errors.append(
                    f"{contact.node_id.hex()}: {response.reason} "
                    f"(текущая версия {response.highest_sequence})"
                )
        except (OSError, ConnectionError, TimeoutError, ValueError) as exc:
            errors.append(f"{contact.node_id.hex()} {contact.address}: {exc}")

    return StoreResult(
        record_key=record.dht_key,
        selected_node_ids=tuple(selected),
        acknowledged_node_ids=tuple(acknowledged),
        errors=tuple(errors),
        success=len(acknowledged) >= quorum,
    )


async def iterative_find_value(
    dht_key: bytes,
    identity: NodeIdentity,
    routing_table: RoutingTable,
    local_store: DHTStore,
    bootstrap_addresses: tuple[tuple[str, int], ...] = (),
    listen_port: int | None = None,
    alpha: int = ALPHA,
    max_hops: int = MAX_HOPS,
) -> ValueLookupResult:
    """Искать запись, переходя к ближайшим контактам из ответов без значения."""
    if len(dht_key) != 32:
        raise ValueError("DHT key должен занимать 32 байта")
    if alpha < 1:
        raise ValueError("alpha должен быть положительным")
    if max_hops < 1:
        raise ValueError("max_hops должен быть положительным")
    started = time.perf_counter()
    lookup_id = uuid.uuid4().hex
    local_record = local_store.get(dht_key)
    if local_record is not None:
        return ValueLookupResult(lookup_id, dht_key, local_record, (), 0, (), 0.0)

    candidates = {
        contact.node_id: contact
        for contact in routing_table.closest(dht_key)
        if contact.node_id != identity.node_id
    }

    def trim_candidates() -> None:
        if len(candidates) > LOOKUP_POOL_SIZE:
            nearest = sorted(
                candidates.values(), key=lambda c: xor_distance(c.node_id, dht_key)
            )[:LOOKUP_POOL_SIZE]
            candidates.clear()
            candidates.update((contact.node_id, contact) for contact in nearest)

    trim_candidates()
    queried: set[bytes] = set()
    iterations: list[tuple[str, ...]] = []
    errors: list[str] = []
    rpc_count = 0
    record: NodeRecord | None = None

    def remember(responder_id: bytes, public_key: bytes, address: tuple[str, int], contacts):
        if not verify_node_id(public_key, responder_id):
            raise ValueError("Ответивший узел объявил несоответствующий открытый ключ")
        if responder_id != identity.node_id:
            contact = Contact(responder_id, address, time.monotonic())
            candidates[responder_id] = contact
            routing_table.add_contact(contact, now=contact.last_seen)
        for contact in contacts:
            if contact.node_id == identity.node_id:
                continue
            candidates[contact.node_id] = contact
            routing_table.add_contact(contact, now=time.monotonic())
        trim_candidates()

    unique_bootstrap = tuple(dict.fromkeys(bootstrap_addresses))
    for offset in range(0, len(unique_bootstrap), alpha):
        batch = unique_bootstrap[offset:offset + alpha]
        responses = await asyncio.gather(*(
            request_find_value(
                host, port, identity, dht_key, sender_listen_port=listen_port
            ) for host, port in batch
        ), return_exceptions=True)
        rpc_count += len(batch)
        round_ids: list[str] = []
        for endpoint, result in zip(batch, responses):
            if isinstance(result, asyncio.CancelledError):
                raise result
            if isinstance(result, Exception):
                errors.append(f"{endpoint[0]}:{endpoint[1]}: {result}")
                continue
            responder = Contact(result.responder_node_id, endpoint, time.monotonic())
            queried.add(responder.node_id)
            round_ids.append(responder.node_id.hex())
            remember(result.responder_node_id, result.responder_public_key, endpoint, result.contacts)
            if result.record is not None:
                result.record.validate()
                if result.record.dht_key != dht_key:
                    raise ValueError("Найденная запись не соответствует DHT key")
                record = result.record
                break
        iterations.append(tuple(round_ids))
        if record is not None:
            break

    hop_count = 0
    while record is None and hop_count < max_hops:
        shortlist = sorted(candidates.values(), key=lambda c: xor_distance(c.node_id, dht_key))[
            :routing_table.k
        ]
        batch = [contact for contact in shortlist if contact.node_id not in queried][:alpha]
        if not batch:
            break
        hop_count += 1
        responses = await asyncio.gather(*(
            request_find_value(
                contact.address[0],
                contact.address[1],
                identity,
                dht_key,
                sender_listen_port=listen_port,
                expected_node_id=contact.node_id,
            ) for contact in batch
        ), return_exceptions=True)
        rpc_count += len(batch)
        round_ids = []
        for contact, result in zip(batch, responses):
            queried.add(contact.node_id)
            round_ids.append(contact.node_id.hex())
            if isinstance(result, asyncio.CancelledError):
                raise result
            if isinstance(result, Exception):
                errors.append(f"{contact.address[0]}:{contact.address[1]}: {result}")
                continue
            remember(
                result.responder_node_id,
                result.responder_public_key,
                contact.address,
                result.contacts,
            )
            if result.record is not None:
                result.record.validate()
                if result.record.dht_key != dht_key:
                    errors.append("Найденная запись не соответствует запрошенному DHT key")
                    continue
                record = result.record
                break
        iterations.append(tuple(round_ids))

    return ValueLookupResult(
        lookup_id=lookup_id,
        dht_key=dht_key,
        record=record,
        iterations=tuple(iterations),
        rpc_count=rpc_count,
        errors=tuple(errors),
        duration_ms=(time.perf_counter() - started) * 1000,
    )
