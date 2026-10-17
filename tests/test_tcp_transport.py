import asyncio
import uuid

from overlay_node.protocol import MessageType
from overlay_node.transport.frame import Frame, PROTOCOL_VERSION, encode_frame
from overlay_node.transport.tcp import read_frame, write_frame


def test_two_tcp_peers_exchange_ping_and_pong():
    async def scenario():
        async def handle_client(reader, writer):
            request = await read_frame(reader)
            response = Frame(
                PROTOCOL_VERSION,
                MessageType.PONG,
                0,
                request.request_id,
                b"PONG: " + request.payload,
            )
            await write_frame(writer, response)
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            request_id = uuid.uuid4().bytes
            request = Frame(
                PROTOCOL_VERSION,
                MessageType.PING,
                0,
                request_id,
                "Тест связи".encode("utf-8"),
            )
            encoded = encode_frame(request)
            # Разбиваем кадр на две записи, как это может случиться в TCP-потоке.
            writer.write(encoded[:5])
            await writer.drain()
            await asyncio.sleep(0)
            writer.write(encoded[5:])
            await writer.drain()

            response = await read_frame(reader)
            writer.close()
            await writer.wait_closed()

            assert response.message_type == MessageType.PONG
            assert response.request_id == request_id
            assert response.payload == "PONG: Тест связи".encode("utf-8")
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())
