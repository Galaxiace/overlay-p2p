import asyncio

from overlay_node.demo import _handle_client
from overlay_node.identity import NodeIdentity
from overlay_node.lookup import iterative_find_node
from overlay_node.routing import RoutingTable
from overlay_node.rpc import request_ping
from overlay_node.secure_session import start_tls_server


def test_iterative_lookup_finds_target_through_intermediate_peer(tmp_path):
    async def scenario():
        async def start_peer(name):
            identity = NodeIdentity.load_or_create(tmp_path / name)
            table = RoutingTable(identity.node_id)

            async def handle(reader, writer):
                port = writer.get_extra_info("sockname")[1]
                await _handle_client(
                    reader,
                    writer,
                    identity,
                    table,
                    ("127.0.0.1", port),
                )

            server = await start_tls_server(handle, "127.0.0.1", 0, identity)
            port = server.sockets[0].getsockname()[1]
            return identity, table, server, port

        seed = await start_peer("seed")
        middle = await start_peer("middle")
        requester = await start_peer("requester")
        peers = (seed, middle, requester)
        try:
            seed_id, _seed_table, _seed_server, seed_port = seed
            middle_id, middle_table, _middle_server, middle_port = middle
            request_id, request_table, _request_server, request_port = requester

            # The middle peer joins the seed and learns the seed's contact.
            join_result = await iterative_find_node(
                target_node_id=middle_id.node_id,
                identity=middle_id,
                routing_table=middle_table,
                bootstrap_addresses=(("127.0.0.1", seed_port),),
                listen_port=middle_port,
            )
            assert middle_table.contact_count >= 1
            assert join_result.rpc_count >= 1

            # The requester starts with an empty table and discovers the seed
            # by asking the middle peer first.
            result = await iterative_find_node(
                target_node_id=seed_id.node_id,
                identity=request_id,
                routing_table=request_table,
                bootstrap_addresses=(("127.0.0.1", middle_port),),
                listen_port=request_port,
            )
            assert result.initial_table_size == 0
            assert result.found is not None
            assert result.found.node_id == seed_id.node_id
            assert result.rpc_count >= 2
            assert middle_id.node_id.hex() in result.queried_node_ids
            assert seed_id.node_id.hex() in result.queried_node_ids
        finally:
            for _identity, _table, server, _port in peers:
                server.close()
                await server.wait_closed()

    asyncio.run(scenario())


def test_five_node_network_keeps_lookup_working_after_seed_stops(tmp_path):
    async def scenario():
        peers = []

        async def start_peer(index):
            identity = NodeIdentity.load_or_create(tmp_path / f"node{index}")
            table = RoutingTable(identity.node_id)

            async def handle(reader, writer):
                port = writer.get_extra_info("sockname")[1]
                await _handle_client(
                    reader,
                    writer,
                    identity,
                    table,
                    ("127.0.0.1", port),
                )

            server = await start_tls_server(handle, "127.0.0.1", 0, identity)
            port = server.sockets[0].getsockname()[1]
            peer = (identity, table, server, port)
            peers.append(peer)
            return peer

        try:
            seed = await start_peer(0)
            seed_identity, _seed_table, _seed_server, seed_port = seed

            # Each joining node checks bootstrap with PING, then performs a
            # self-lookup; replies carry known contacts so the graph grows.
            for index in range(1, 5):
                joining = await start_peer(index)
                identity, table, _server, port = joining
                bootstrap_port = peers[index - 1][3]
                assert await request_ping("127.0.0.1", bootstrap_port, identity) is None
                result = await iterative_find_node(
                    target_node_id=identity.node_id,
                    identity=identity,
                    routing_table=table,
                    bootstrap_addresses=(("127.0.0.1", bootstrap_port),),
                    listen_port=port,
                )
                assert result.rpc_count >= 1

            requester_identity, requester_table, _requester_server, requester_port = peers[4]
            requester_bootstrap = peers[3][3]
            seed_server = peers[0][2]
            assert requester_bootstrap != seed_port
            seed_server.close()
            await seed_server.wait_closed()

            result = await iterative_find_node(
                target_node_id=peers[1][0].node_id,
                identity=requester_identity,
                routing_table=requester_table,
                listen_port=requester_port,
                bootstrap_addresses=(("127.0.0.1", requester_bootstrap),),
            )
            assert result.found is not None
            assert result.found.node_id == peers[1][0].node_id
            # An error may record a stale route to the stopped seed. The
            # acceptance condition is that lookup still completes via live peers.
        finally:
            for _identity, _table, server, _port in peers:
                server.close()
                await server.wait_closed()

    asyncio.run(scenario())
