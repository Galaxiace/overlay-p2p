"""Reproducible local experiment for iterative FIND_NODE lookups."""

from __future__ import annotations

import asyncio
import csv
import random
import tempfile
from pathlib import Path

from overlay_node.demo import _handle_client
from overlay_node.identity import NodeIdentity
from overlay_node.lookup import iterative_find_node
from overlay_node.routing import RoutingTable
from overlay_node.rpc import request_ping
from overlay_node.secure_session import start_tls_server


async def run_lookup_experiment(
    count: int = 30,
    output_path: str | Path = "results/lookup_experiment.csv",
    seed: int = 20261007,
) -> dict[str, float | int | str]:
    """Run absent-target lookups through a five-peer overlay and save CSV metrics.

    Each query uses a fresh empty routing table, while the same live requester
    identity and the five overlay peers are retained. Bootstrap is a middle
    peer, so candidates returned by it must be queried to continue the lookup.
    Peer keys are temporary and are removed when the experiment ends.
    """
    if count < 1:
        raise ValueError("Число поисков должно быть не меньше 1")

    rng = random.Random(seed)
    rows: list[dict[str, object]] = []
    output_path = Path(output_path)

    with tempfile.TemporaryDirectory(prefix="overlay-find-node-") as temp_root:
        peers: list[dict[str, object]] = []

        async def start_peer(index: int) -> dict[str, object]:
            identity = NodeIdentity.load_or_create(Path(temp_root) / f"peer{index}")
            table = RoutingTable(identity.node_id)

            async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
                local_port = writer.get_extra_info("sockname")[1]
                await _handle_client(
                    reader,
                    writer,
                    identity,
                    table,
                    ("127.0.0.1", local_port),
                    verbose=False,
                )

            server = await start_tls_server(handle, "127.0.0.1", 0, identity)
            address = ("127.0.0.1", server.sockets[0].getsockname()[1])
            peer = {
                "identity": identity,
                "table": table,
                "server": server,
                "address": address,
            }
            peers.append(peer)
            return peer

        try:
            # Build a peer-to-peer chain through ordinary bootstrap lookups.
            for index in range(5):
                peer = await start_peer(index)
                if index == 0:
                    continue
                identity = peer["identity"]
                table = peer["table"]
                port = peer["address"][1]
                bootstrap = peers[index - 1]["address"]
                await request_ping(bootstrap[0], bootstrap[1], identity)
                await iterative_find_node(
                    target_node_id=identity.node_id,
                    identity=identity,
                    routing_table=table,
                    bootstrap_addresses=(bootstrap,),
                    listen_port=port,
                )

            middle_peer = peers[2]
            if middle_peer["table"].contact_count < 2:
                raise RuntimeError(
                    "Промежуточный узел узнал меньше двух контактов; "
                    "эксперимент не подтверждает многошаговый поиск"
                )

            requester = NodeIdentity.load_or_create(Path(temp_root) / "requester")
            existing_ids = {peer["identity"].node_id for peer in peers}
            existing_ids.add(requester.node_id)

            for number in range(1, count + 1):
                target = rng.randbytes(32)
                while target in existing_ids:
                    target = rng.randbytes(32)

                # A new table per search proves that the initiator has no
                # cached directory of peers or previously learned contacts.
                requester_table = RoutingTable(requester.node_id)
                result = await iterative_find_node(
                    target_node_id=target,
                    identity=requester,
                    routing_table=requester_table,
                    bootstrap_addresses=(middle_peer["address"],),
                )
                rows.append(
                    {
                        "search_number": number,
                        "lookup_id": result.lookup_id,
                        "target_node_id": target.hex(),
                        "bootstrap_node_id": middle_peer["identity"].node_id.hex(),
                        "initiator_initial_table_size": result.initial_table_size,
                        "initiator_final_table_size": requester_table.contact_count,
                        "rpc_count": result.rpc_count,
                        "iteration_count": len(result.iterations),
                        "duration_ms": round(result.duration_ms, 3),
                        "target_found": result.found is not None,
                        "queried_node_ids": ";".join(result.queried_node_ids),
                        "errors": ";".join(result.errors),
                    }
                )
        finally:
            for peer in peers:
                server = peer["server"]
                server.close()
                await server.wait_closed()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0].keys())
    with output_path.open("w", encoding="utf-8-sig", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    rpc_total = sum(int(row["rpc_count"]) for row in rows)
    iteration_total = sum(int(row["iteration_count"]) for row in rows)
    duration_total = sum(float(row["duration_ms"]) for row in rows)
    multihop_count = sum(int(row["rpc_count"]) >= 2 for row in rows)
    found_count = sum(bool(row["target_found"]) for row in rows)
    error_count = sum(bool(row["errors"]) for row in rows)
    summary: dict[str, float | int | str] = {
        "search_count": count,
        "multihop_count": multihop_count,
        "found_count": found_count,
        "error_count": error_count,
        "rpc_total": rpc_total,
        "rpc_average": round(rpc_total / count, 2),
        "iteration_average": round(iteration_total / count, 2),
        "duration_average_ms": round(duration_total / count, 3),
        "csv_path": str(output_path),
    }
    return summary


def print_lookup_experiment_summary(summary: dict[str, float | int | str]) -> None:
    print(f"Поисков выполнено: {summary['search_count']}")
    print(f"Многошаговых поисков (не менее 2 RPC): {summary['multihop_count']}")
    print(f"Ошибок запросов: {summary['error_count']}")
    print(f"Целей ошибочно найдено в сети: {summary['found_count']}")
    print(f"Всего RPC: {summary['rpc_total']}; среднее RPC на поиск: {summary['rpc_average']}")
    print(f"Среднее число итераций: {summary['iteration_average']}")
    print(f"Среднее время: {summary['duration_average_ms']} мс")
    print(f"CSV с результатами: {summary['csv_path']}")
