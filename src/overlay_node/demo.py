"""Демонстрация обмена PING/PONG между двумя TCP-узлами."""

from __future__ import annotations

import argparse
import asyncio
import time
from pathlib import Path

from overlay_node.config import CONFIG
from overlay_node.dht import iterative_find_value, replicate_record
from overlay_node.dht_store import DHTStore
from overlay_node.identity import NodeIdentity
from overlay_node.lookup import iterative_find_node
from overlay_node.protocol import (
    FindNodeRequest,
    FindNodeResponse,
    FindValueRequest,
    FindValueResponse,
    MessageType,
    StoreResponse,
)
from overlay_node.records import DEFAULT_TTL_SECONDS, NodeRecord, node_record_key
from overlay_node.routing import Contact, RoutingTable, xor_distance
from overlay_node.rpc import request_find_node, request_ping
from overlay_node.secure_session import (
    ReplayGuard,
    peer_node_id,
    read_secure_frame,
    start_tls_server,
    write_secure_frame,
)
from overlay_node.transport.frame import Frame, PROTOCOL_VERSION
from overlay_node.transport.tcp import PeerClosed

_REPLAY_GUARDS: dict[bytes, ReplayGuard] = {}


def _replay_guard_for(node_id: bytes) -> ReplayGuard:
    return _REPLAY_GUARDS.setdefault(node_id, ReplayGuard())


async def _handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    identity: NodeIdentity,
    routing_table: RoutingTable,
    advertised_address: tuple[str, int],
    record_store: DHTStore | None = None,
    verbose: bool = True,
) -> None:
    peer = writer.get_extra_info("peername")
    try:
        authenticated_peer_id = peer_node_id(writer)
        envelope = await read_secure_frame(
            reader,
            peer_id=authenticated_peer_id,
            replay_guard=_replay_guard_for(identity.node_id),
        )
        request = envelope.frame
        if request.message_type == MessageType.PING:
            if verbose:
                print(f"Получен PING от {peer}: {request.payload.decode('utf-8', errors='replace')}")
            response = Frame(
                PROTOCOL_VERSION,
                MessageType.PONG,
                0,
                request.request_id,
                b"PONG: " + request.payload,
            )
        elif request.message_type == MessageType.FIND_NODE_REQUEST:
            find_request = FindNodeRequest.from_payload(request.payload)
            if find_request.sender_node_id != authenticated_peer_id:
                raise ValueError("FIND_NODE sender NodeID does not match TLS client certificate")
            if verbose:
                print(
                    f"FIND_NODE от {find_request.sender_node_id.hex()[:12]}... "
                    f"для {find_request.target_node_id.hex()[:12]}..."
                )
            if find_request.sender_listen_port is not None and find_request.sender_node_id != identity.node_id:
                remote_host = peer[0] if isinstance(peer, tuple) else ""
                if remote_host:
                    sender_contact = Contact(
                        find_request.sender_node_id,
                        (remote_host, find_request.sender_listen_port),
                    )
                    await routing_table.add_contact_with_probe(
                        sender_contact,
                        lambda contact: _ping_contact(contact, identity),
                        now=time.monotonic(),
                    )
            candidate_by_id = {
                contact.node_id: contact
                for contact in routing_table.closest(find_request.target_node_id)
            }
            candidate_by_id[identity.node_id] = Contact(identity.node_id, advertised_address)
            closest_contacts = sorted(
                candidate_by_id.values(),
                key=lambda contact: xor_distance(contact.node_id, find_request.target_node_id),
            )[: routing_table.k]
            find_response = FindNodeResponse(
                responder_node_id=identity.node_id,
                responder_public_key=identity.public_key_bytes,
                contacts=tuple(closest_contacts),
            )
            response = Frame(
                PROTOCOL_VERSION,
                MessageType.FIND_NODE_RESPONSE,
                0,
                request.request_id,
                find_response.to_payload(),
            )
        elif request.message_type == MessageType.STORE_REQUEST:
            record = NodeRecord.from_payload(request.payload)
            if record.node_id != authenticated_peer_id:
                raise ValueError("STORE owner NodeID does not match TLS client certificate")
            store = record_store if record_store is not None else DHTStore()
            decision = store.put(record)
            if verbose:
                print(
                    f"STORE от {record.node_id.hex()[:12]}...: "
                    f"{'принята' if decision.accepted else 'отклонена'}, "
                    f"sequence={record.sequence_number}"
                )
            result = StoreResponse(
                decision.accepted,
                decision.highest_sequence,
                decision.reason,
            )
            response = Frame(
                PROTOCOL_VERSION,
                MessageType.STORE_RESPONSE,
                0,
                request.request_id,
                result.to_payload(),
            )
        elif request.message_type == MessageType.FIND_VALUE_REQUEST:
            find_request = FindValueRequest.from_payload(request.payload)
            if find_request.sender_node_id != authenticated_peer_id:
                raise ValueError("FIND_VALUE sender NodeID does not match TLS client certificate")
            if find_request.sender_listen_port is not None and find_request.sender_node_id != identity.node_id:
                remote_host = peer[0] if isinstance(peer, tuple) else ""
                if remote_host:
                    sender_contact = Contact(
                        find_request.sender_node_id,
                        (remote_host, find_request.sender_listen_port),
                    )
                    await routing_table.add_contact_with_probe(
                        sender_contact,
                        lambda contact: _ping_contact(contact, identity),
                        now=time.monotonic(),
                    )
            store = record_store if record_store is not None else DHTStore()
            record = store.get(find_request.dht_key)
            contacts_by_id = {
                contact.node_id: contact
                for contact in routing_table.closest(find_request.dht_key)
            }
            contacts_by_id[identity.node_id] = Contact(identity.node_id, advertised_address)
            contacts = tuple(sorted(
                contacts_by_id.values(),
                key=lambda contact: xor_distance(contact.node_id, find_request.dht_key),
            )[:routing_table.k])
            result = FindValueResponse(
                identity.node_id,
                identity.public_key_bytes,
                find_request.dht_key,
                record,
                () if record is not None else contacts,
            )
            if verbose:
                print(
                    f"FIND_VALUE от {find_request.sender_node_id.hex()[:12]}...: "
                    f"{'значение найдено' if record else 'возвращены ближайшие контакты'}"
                )
            response = Frame(
                PROTOCOL_VERSION,
                MessageType.FIND_VALUE_RESPONSE,
                0,
                request.request_id,
                result.to_payload(),
            )
        else:
            response = Frame(
                PROTOCOL_VERSION,
                MessageType.ERROR,
                0,
                request.request_id,
                b"Unsupported message type",
            )
        await write_secure_frame(
            writer,
            response,
            session_id=envelope.session_id,
            counter=envelope.counter + 1,
        )
    except (PeerClosed, ConnectionError, TimeoutError, ValueError, OSError) as exc:
        if verbose:
            print(f"Соединение с {peer} завершено: {exc}")
    finally:
        writer.close()
        await writer.wait_closed()


async def _create_peer_server(host: str, port: int, state_dir: str):
    identity = NodeIdentity.load_or_create(state_dir)
    routing_table = RoutingTable(identity.node_id)
    record_store = DHTStore(Path(state_dir) / "dht_records.json")

    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        local_port = writer.get_extra_info("sockname")[1]
        await _handle_client(
            reader,
            writer,
            identity,
            routing_table,
            (host, local_port),
            record_store,
        )

    server = await start_tls_server(handle_client, host, port, identity)
    addresses = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    actual_port = server.sockets[0].getsockname()[1]
    return server, identity, routing_table, addresses, actual_port


async def run_server(host: str, port: int, state_dir: str) -> None:
    server, identity, _routing_table, addresses, _actual_port = await _create_peer_server(
        host, port, state_dir
    )
    print(f"Узел ожидает подключения: {addresses}")
    print(f"NodeID этого узла: {identity.node_id.hex()}")
    async with server:
        await server.serve_forever()


def _parse_address(value: str) -> tuple[str, int]:
    try:
        host, port_text = value.rsplit(":", 1)
        port = int(port_text)
    except (ValueError, AttributeError) as exc:
        raise ValueError("Адрес должен быть в формате host:port") from exc
    if not host or not 1 <= port <= 65535:
        raise ValueError("Адрес bootstrap должен содержать host и порт 1–65535")
    return host, port


def _print_lookup(result, self_lookup: bool = False) -> None:
    print(f"lookup_id: {result.lookup_id}")
    print(f"Инициатор: {result.initiator_node_id.hex()}")
    print(f"Цель: {result.target_node_id.hex()}")
    print(f"Размер таблицы до поиска: {result.initial_table_size}")
    print(f"Итераций: {len(result.iterations)}; RPC: {result.rpc_count}")
    for index, node_ids in enumerate(result.iterations, start=1):
        print(f"  Итерация {index}: {', '.join(node_ids) if node_ids else 'ответов нет'}")
    if result.found is None:
        if self_lookup:
            print("Bootstrap/self-lookup завершён; собственный NodeID не ожидается как удалённый ответивший узел.")
        else:
            print("Результат: целевой узел не найден")
    else:
        print(f"Результат: узел найден по адресу {result.found.address[0]}:{result.found.address[1]}")
    print(f"Время поиска: {result.duration_ms:.2f} мс")
    for error in result.errors:
        print(f"Ошибка узла: {error}")


async def run_node(
    host: str,
    port: int,
    state_dir: str,
    bootstrap_values: list[str],
    lookup_target_hex: str | None,
    routing_export: str | None,
) -> None:
    server, identity, routing_table, addresses, actual_port = await _create_peer_server(
        host, port, state_dir
    )
    print(f"Узел работает: {addresses}")
    print(f"NodeID этого узла: {identity.node_id.hex()}")

    bootstrap_addresses = tuple(_parse_address(value) for value in bootstrap_values)
    if bootstrap_addresses:
        for bootstrap_host, bootstrap_port in bootstrap_addresses:
            try:
                await request_ping(bootstrap_host, bootstrap_port, identity)
                print(f"Bootstrap PING успешен: {bootstrap_host}:{bootstrap_port}")
            except (OSError, ConnectionError, TimeoutError, ValueError) as exc:
                print(
                    f"Bootstrap PING не прошёл: "
                    f"{bootstrap_host}:{bootstrap_port}: {exc}"
                )
        target_node_id = identity.node_id
        if lookup_target_hex is not None:
            try:
                target_node_id = bytes.fromhex(lookup_target_hex)
            except ValueError as exc:
                raise ValueError("--lookup-target должен быть NodeID в hex-формате") from exc
            if len(target_node_id) != 32:
                raise ValueError("--lookup-target должен содержать 64 hex-символа")
        result = await iterative_find_node(
            target_node_id=target_node_id,
            identity=identity,
            routing_table=routing_table,
            bootstrap_addresses=bootstrap_addresses,
            listen_port=actual_port,
        )
        _print_lookup(result, self_lookup=lookup_target_hex is None)
    elif lookup_target_hex is not None:
        raise ValueError("Для --lookup-target укажите хотя бы один --bootstrap")

    def save_routing_table() -> None:
        if routing_export is None:
            return
        destination = routing_table.export_json(routing_export)
        print(
            f"Таблица маршрутизации сохранена: {destination} "
            f"(контактов: {routing_table.contact_count}, "
            f"заполнено bucket: {len(routing_table.snapshot())})"
        )

    save_routing_table()
    try:
        async with server:
            await server.serve_forever()
    finally:
        save_routing_table()


async def run_ping(host: str, port: int, message: str, state_dir: str) -> None:
    identity = NodeIdentity.load_or_create(state_dir)
    await request_ping(host, port, identity, message=message.encode("utf-8"))
    print(f"Ответ узла: PONG: {message}")


async def _ping_contact(contact: Contact, identity: NodeIdentity) -> bool:
    """Check contact reachability before the routing table evicts an old peer."""
    try:
        await request_ping(
            contact.address[0],
            contact.address[1],
            identity,
            timeout=CONFIG["probe_timeout_seconds"],
            expected_node_id=contact.node_id,
        )
        return True
    except (OSError, ConnectionError, TimeoutError, ValueError):
        return False


async def run_find_node(
    host: str, port: int, target_hex: str, state_dir: str
) -> None:
    try:
        target_node_id = bytes.fromhex(target_hex)
    except ValueError as exc:
        raise ValueError("--target должен быть NodeID в hex-формате") from exc
    if len(target_node_id) != 32:
        raise ValueError("--target должен содержать ровно 64 hex-символа")

    identity = NodeIdentity.load_or_create(state_dir)
    response = await request_find_node(host, port, identity, target_node_id)
    print(f"Ответивший узел: {response.responder_node_id.hex()}")
    print("Ближайшие контакты, возвращённые узлом:")
    for contact in response.contacts:
        print(f"  {contact.node_id.hex()} at {contact.address[0]}:{contact.address[1]}")
    if any(contact.node_id == target_node_id for contact in response.contacts):
        print("Целевой NodeID есть в списке ответа.")
    else:
        print("Целевой NodeID пока не найден; получен список ближайших кандидатов.")


async def run_publish_record(
    state_dir: str,
    listen_host: str,
    listen_port: int,
    bootstrap_values: list[str],
    sequence_number: int,
    ttl_seconds: int,
) -> None:
    identity = NodeIdentity.load_or_create(state_dir)
    addresses = ((listen_host, listen_port),)
    record = NodeRecord.create(
        identity, addresses, sequence_number=sequence_number, ttl_seconds=ttl_seconds
    )
    routing_table = RoutingTable(identity.node_id)
    result = await replicate_record(
        record=record,
        identity=identity,
        routing_table=routing_table,
        local_store=None,
        local_address=(listen_host, listen_port),
        bootstrap_addresses=tuple(_parse_address(value) for value in bootstrap_values),
        listen_port=listen_port,
    )
    print(f"NodeID владельца: {record.node_id.hex()}")
    print(f"DHT key: {record.dht_key.hex()}")
    print(f"sequence_number: {record.sequence_number}; TTL: {ttl_seconds} с")
    print(f"Выбраны хранители: {', '.join(result.selected_node_ids) or 'нет'}")
    print(f"Подтверждения STORE: {len(result.acknowledged_node_ids)}")
    for error in result.errors:
        print(f"Ошибка STORE: {error}")
    if not result.success:
        raise RuntimeError(
            f"Недостаточно подтверждений: требуется не менее 2, получено "
            f"{len(result.acknowledged_node_ids)}"
        )
    print("Запись успешно опубликована в DHT.")


async def run_find_value(
    node_id_hex: str,
    state_dir: str,
    bootstrap_values: list[str],
) -> None:
    try:
        node_id = bytes.fromhex(node_id_hex)
    except ValueError as exc:
        raise ValueError("--node-id должен быть NodeID в hex-формате") from exc
    key = node_record_key(node_id)
    identity = NodeIdentity.load_or_create(state_dir)
    routing_table = RoutingTable(identity.node_id)
    local_store = DHTStore(Path(state_dir) / "dht_records.json")
    result = await iterative_find_value(
        dht_key=key,
        identity=identity,
        routing_table=routing_table,
        local_store=local_store,
        bootstrap_addresses=tuple(_parse_address(value) for value in bootstrap_values),
    )
    print(f"lookup_id: {result.lookup_id}")
    print(f"NodeID поиска: {node_id.hex()}")
    print(f"DHT key: {key.hex()}")
    print(f"Итераций: {len(result.iterations)}; RPC: {result.rpc_count}")
    if result.record is None:
        print("Результат: запись не найдена или срок её действия истёк.")
    else:
        record = result.record
        print(f"Результат: запись найдена, sequence_number={record.sequence_number}")
        print(f"Владелец: {record.node_id.hex()}")
        print(f"Действует до (Unix time): {record.expires_at}")
        for host, port in record.addresses:
            print(f"Адрес: {host}:{port}")
    for error in result.errors:
        print(f"Ошибка узла: {error}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Демонстрация TCP-обмена кадрами")
    subparsers = parser.add_subparsers(dest="command", required=True)

    server_parser = subparsers.add_parser("server", help="запустить ожидающий узел")
    server_parser.add_argument("--host", default="127.0.0.1")
    server_parser.add_argument("--port", type=int, default=9000)
    server_parser.add_argument("--state-dir", default=".state/server")

    node_parser = subparsers.add_parser(
        "node", help="запустить узел и присоединить его к bootstrap-соседям"
    )
    node_parser.add_argument("--host", default="127.0.0.1")
    node_parser.add_argument("--port", type=int, default=9000)
    node_parser.add_argument("--state-dir", default=".state/node")
    node_parser.add_argument(
        "--bootstrap", action="append", default=[], metavar="HOST:PORT",
        help="адрес известного узла; параметр можно повторить",
    )
    node_parser.add_argument(
        "--lookup-target", help="выполнить поиск указанного NodeID после запуска"
    )
    node_parser.add_argument(
        "--routing-export",
        metavar="PATH",
        help="сохранять таблицу маршрутизации в JSON после bootstrap и при остановке",
    )

    ping_parser = subparsers.add_parser("ping", help="послать PING узлу")
    ping_parser.add_argument("--host", default="127.0.0.1")
    ping_parser.add_argument("--port", type=int, default=9000)
    ping_parser.add_argument("--message", default="Привет, P2P!")
    ping_parser.add_argument("--state-dir", default=".state/ping-client")

    identity_parser = subparsers.add_parser(
        "identity", help="создать или показать постоянную идентичность узла"
    )
    identity_parser.add_argument("--state-dir", default=".state/demo-node")

    find_parser = subparsers.add_parser("find-node", help="выполнить один FIND_NODE RPC")
    find_parser.add_argument("--host", default="127.0.0.1")
    find_parser.add_argument("--port", type=int, default=9000)
    find_parser.add_argument("--target", required=True, help="целевой 256-битный NodeID в hex")
    find_parser.add_argument("--state-dir", default=".state/client")

    publish_parser = subparsers.add_parser(
        "publish-record", help="подписать NodeRecord и разместить три DHT-копии"
    )
    publish_parser.add_argument("--state-dir", default=".state/node")
    publish_parser.add_argument("--listen-host", default="127.0.0.1")
    publish_parser.add_argument("--listen-port", type=int, required=True)
    publish_parser.add_argument(
        "--bootstrap", action="append", default=[], metavar="HOST:PORT", required=True
    )
    publish_parser.add_argument("--sequence", type=int, required=True)
    publish_parser.add_argument("--ttl", type=int, default=DEFAULT_TTL_SECONDS)

    value_parser = subparsers.add_parser(
        "find-value", help="найти NodeRecord в DHT по NodeID владельца"
    )
    value_parser.add_argument("--node-id", required=True, help="NodeID владельца в hex")
    value_parser.add_argument("--state-dir", default=".state/client")
    value_parser.add_argument(
        "--bootstrap", action="append", default=[], metavar="HOST:PORT", required=True
    )

    args = parser.parse_args()
    try:
        if args.command == "identity":
            identity = NodeIdentity.load_or_create(args.state_dir)
            print(f"NodeID: {identity.node_id.hex()}")
            print(f"Открытый ключ Ed25519: {identity.public_key_bytes.hex()}")
            print(f"Каталог состояния: {args.state_dir}")
        elif args.command == "server":
            asyncio.run(run_server(args.host, args.port, args.state_dir))
        elif args.command == "node":
            asyncio.run(
                run_node(
                    args.host,
                    args.port,
                    args.state_dir,
                    args.bootstrap,
                    args.lookup_target,
                    args.routing_export,
                )
            )
        elif args.command == "find-node":
            asyncio.run(run_find_node(args.host, args.port, args.target, args.state_dir))
        elif args.command == "publish-record":
            asyncio.run(run_publish_record(
                args.state_dir, args.listen_host, args.listen_port, args.bootstrap,
                args.sequence, args.ttl,
            ))
        elif args.command == "find-value":
            asyncio.run(run_find_value(args.node_id, args.state_dir, args.bootstrap))
        else:
            asyncio.run(run_ping(args.host, args.port, args.message, args.state_dir))
    except KeyboardInterrupt:
        print("\nОперация остановлена пользователем.")


if __name__ == "__main__":
    main()
