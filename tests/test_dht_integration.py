import asyncio

from overlay_node.demo import _handle_client
from overlay_node.dht import iterative_find_value, replicate_record
from overlay_node.dht_store import DHTStore
from overlay_node.identity import NodeIdentity
from overlay_node.lookup import iterative_find_node
from overlay_node.records import NodeRecord
from overlay_node.routing import RoutingTable
from overlay_node.rpc import request_store
from overlay_node.secure_session import start_tls_server


def test_replicated_record_is_found_after_one_holder_stops(tmp_path):
    async def scenario():
        peers = []

        async def start_peer(name):
            identity = NodeIdentity.load_or_create(tmp_path / name / "identity")
            table = RoutingTable(identity.node_id)
            store = DHTStore(tmp_path / name / "dht_records.json")

            async def handle(reader, writer):
                port = writer.get_extra_info("sockname")[1]
                await _handle_client(
                    reader,
                    writer,
                    identity,
                    table,
                    ("127.0.0.1", port),
                    store,
                )

            server = await start_tls_server(handle, "127.0.0.1", 0, identity)
            port = server.sockets[0].getsockname()[1]
            peer = {
                "identity": identity,
                "table": table,
                "store": store,
                "server": server,
                "address": ("127.0.0.1", port),
            }
            peers.append(peer)
            return peer

        try:
            # Four peers join through normal FIND_NODE exchanges.
            for index in range(4):
                peer = await start_peer(f"peer{index}")
                if index:
                    await iterative_find_node(
                        target_node_id=peer["identity"].node_id,
                        identity=peer["identity"],
                        routing_table=peer["table"],
                        bootstrap_addresses=(peers[index - 1]["address"],),
                        listen_port=peer["address"][1],
                    )

            # Each node learns the other active peers via bootstrap requests.
            for peer in peers:
                other_addresses = tuple(
                    item["address"] for item in peers if item is not peer
                )
                await iterative_find_node(
                    target_node_id=peer["identity"].node_id,
                    identity=peer["identity"],
                    routing_table=peer["table"],
                    bootstrap_addresses=other_addresses,
                    listen_port=peer["address"][1],
                )

            owner = peers[0]
            record = NodeRecord.create(
                owner["identity"],
                (owner["address"],),
                sequence_number=1,
                ttl_seconds=180,
            )
            published = await replicate_record(
                record=record,
                identity=owner["identity"],
                routing_table=owner["table"],
                local_store=None,
                local_address=owner["address"],
            )
            assert published.success
            assert len(published.acknowledged_node_ids) == 3

            rollback = NodeRecord.create(
                owner["identity"],
                (owner["address"],),
                sequence_number=0,
                ttl_seconds=180,
            )
            current_holder_id = bytes.fromhex(published.acknowledged_node_ids[0])
            current_holder = next(
                peer for peer in peers if peer["identity"].node_id == current_holder_id
            )
            rollback_response = await request_store(
                current_holder["address"][0],
                current_holder["address"][1],
                rollback,
                owner["identity"],
                expected_node_id=current_holder_id,
            )
            assert not rollback_response.accepted
            assert rollback_response.highest_sequence == 1

            non_holder = next(
                peer for peer in peers
                if peer["identity"].node_id.hex() not in published.acknowledged_node_ids
            )
            failed_holder_id = current_holder_id
            failed_holder = next(
                peer for peer in peers if peer["identity"].node_id == failed_holder_id
            )
            failed_holder["server"].close()
            await failed_holder["server"].wait_closed()

            requester = await start_peer("requester")
            lookup = await iterative_find_value(
                dht_key=record.dht_key,
                identity=requester["identity"],
                routing_table=requester["table"],
                local_store=requester["store"],
                bootstrap_addresses=(non_holder["address"],),
                listen_port=requester["address"][1],
            )
            assert lookup.record is not None
            assert lookup.record.node_id == owner["identity"].node_id
            assert lookup.record.sequence_number == 1
            assert lookup.rpc_count >= 2
        finally:
            for peer in peers:
                peer["server"].close()
                await peer["server"].wait_closed()

    asyncio.run(scenario())
