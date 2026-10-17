"""Iterative Kademlia FIND_NODE lookup with bounded parallel queries."""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass

from overlay_node.config import CONFIG
from overlay_node.identity import NodeIdentity
from overlay_node.protocol import FindNodeResponse
from overlay_node.routing import Contact, RoutingTable, xor_distance
from overlay_node.rpc import request_find_node

ALPHA = CONFIG["alpha"]
MAX_HOPS = CONFIG["lookup_max_hops"]
LOOKUP_POOL_SIZE = CONFIG["lookup_pool_size"]


@dataclass(frozen=True)
class LookupResult:
    lookup_id: str
    initiator_node_id: bytes
    target_node_id: bytes
    found: Contact | None
    iterations: tuple[tuple[str, ...], ...]
    queried_node_ids: tuple[str, ...]
    rpc_count: int
    errors: tuple[str, ...]
    duration_ms: float
    initial_table_size: int


async def iterative_find_node(
    target_node_id: bytes,
    identity: NodeIdentity,
    routing_table: RoutingTable,
    bootstrap_addresses: tuple[tuple[str, int], ...] = (),
    listen_port: int | None = None,
    alpha: int = ALPHA,
    max_hops: int = MAX_HOPS,
) -> LookupResult:
    """Search for a target by repeatedly querying up to ``alpha`` peers.

    Bootstrap addresses have no known NodeID, so they are queried in the
    initial round. Later rounds query the closest unqueried contacts from the
    routing table and contacts returned by earlier peers.
    """
    if len(target_node_id) != 32:
        raise ValueError("target_node_id должен занимать 32 байта")
    if alpha < 1:
        raise ValueError("alpha должен быть положительным")
    if max_hops < 1:
        raise ValueError("max_hops должен быть положительным")

    started = time.perf_counter()
    initial_table_size = routing_table.contact_count
    lookup_id = uuid.uuid4().hex
    candidates: dict[bytes, Contact] = {
        contact.node_id: contact
        for contact in routing_table.closest(target_node_id)
        if contact.node_id != identity.node_id
    }

    def trim_candidates() -> None:
        if len(candidates) > LOOKUP_POOL_SIZE:
            nearest = sorted(
                candidates.values(),
                key=lambda contact: xor_distance(contact.node_id, target_node_id),
            )[:LOOKUP_POOL_SIZE]
            candidates.clear()
            candidates.update((contact.node_id, contact) for contact in nearest)

    trim_candidates()
    queried: set[bytes] = set()
    queried_order: list[str] = []
    iteration_log: list[tuple[str, ...]] = []
    errors: list[str] = []
    rpc_count = 0
    found: Contact | None = None

    def remember(response: FindNodeResponse, endpoint: tuple[str, int]) -> Contact:
        nonlocal found
        responder = Contact(response.responder_node_id, endpoint, time.monotonic())
        if responder.node_id != identity.node_id:
            candidates[responder.node_id] = responder
            routing_table.add_contact(responder, now=responder.last_seen)
        for contact in response.contacts:
            if contact.node_id == identity.node_id:
                continue
            candidates[contact.node_id] = contact
            routing_table.add_contact(contact, now=time.monotonic())
        if response.responder_node_id == target_node_id:
            found = responder
        trim_candidates()
        return responder

    # Bootstrap addresses are queried first because their NodeIDs are not yet known.
    unique_bootstrap = tuple(dict.fromkeys(bootstrap_addresses))
    for offset in range(0, len(unique_bootstrap), alpha):
        batch = unique_bootstrap[offset : offset + alpha]
        results = await asyncio.gather(
            *(
                request_find_node(
                    host,
                    port,
                    identity,
                    target_node_id,
                    sender_listen_port=listen_port,
                )
                for host, port in batch
            ),
            return_exceptions=True,
        )
        rpc_count += len(batch)
        round_ids: list[str] = []
        for endpoint, result in zip(batch, results):
            if isinstance(result, asyncio.CancelledError):
                raise result
            if isinstance(result, Exception):
                errors.append(f"{endpoint[0]}:{endpoint[1]}: {result}")
                continue
            responder = remember(result, endpoint)
            queried.add(responder.node_id)
            queried_order.append(responder.node_id.hex())
            round_ids.append(responder.node_id.hex())
        iteration_log.append(tuple(round_ids))
        if found is not None:
            break

    iteration = 0
    while found is None and iteration < max_hops:
        shortlist = sorted(
            candidates.values(),
            key=lambda contact: xor_distance(contact.node_id, target_node_id),
        )[: routing_table.k]
        batch = [contact for contact in shortlist if contact.node_id not in queried][:alpha]
        if not batch:
            break

        iteration += 1
        results = await asyncio.gather(
            *(
                request_find_node(
                    contact.address[0],
                    contact.address[1],
                    identity,
                    target_node_id,
                    sender_listen_port=listen_port,
                    expected_node_id=contact.node_id,
                )
                for contact in batch
            ),
            return_exceptions=True,
        )
        rpc_count += len(batch)
        round_ids = []
        for contact, result in zip(batch, results):
            queried.add(contact.node_id)
            queried_order.append(contact.node_id.hex())
            round_ids.append(contact.node_id.hex())
            if isinstance(result, asyncio.CancelledError):
                raise result
            if isinstance(result, Exception):
                errors.append(f"{contact.address[0]}:{contact.address[1]}: {result}")
                continue
            remember(result, contact.address)
        iteration_log.append(tuple(round_ids))

    return LookupResult(
        lookup_id=lookup_id,
        initiator_node_id=identity.node_id,
        target_node_id=target_node_id,
        found=found,
        iterations=tuple(iteration_log),
        queried_node_ids=tuple(queried_order),
        rpc_count=rpc_count,
        errors=tuple(errors),
        duration_ms=(time.perf_counter() - started) * 1000,
        initial_table_size=initial_table_size,
    )
