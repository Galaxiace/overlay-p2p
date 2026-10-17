import asyncio
import json

import pytest

from overlay_node.routing import Contact, RoutingError, RoutingTable, bucket_index, xor_distance


def node_id(number):
    return number.to_bytes(32, "big")


def same_bucket_id(low_bits):
    return ((1 << 255) | low_bits).to_bytes(32, "big")


def test_xor_distance_and_bucket_index():
    local = node_id(0)
    assert xor_distance(local, node_id(1)) == 1
    assert bucket_index(local, node_id(1)) == 0
    assert bucket_index(local, node_id(2)) == 1
    assert bucket_index(local, node_id(3)) == 1
    assert bucket_index(local, node_id(1 << 255)) == 255


def test_bucket_has_capacity_and_updates_existing_peer_lru():
    table = RoutingTable(node_id(0), k=2)
    first = Contact(same_bucket_id(0), ("127.0.0.1", 9002))
    second = Contact(same_bucket_id(1), ("127.0.0.1", 9003))
    third = Contact(same_bucket_id(2), ("127.0.0.1", 9004))

    assert table.add_contact(first, now=1)
    assert table.add_contact(second, now=2)
    assert not table.add_contact(third, now=3)
    assert table.contact_count == 2

    assert not table.add_contact(Contact(first.node_id, ("127.0.0.2", 9101)), now=4)
    bucket = table.get_bucket(255)
    assert [contact.node_id for contact in bucket] == [second.node_id, first.node_id]
    assert bucket[-1].address == ("127.0.0.2", 9101)
    assert bucket[-1].last_seen == 4


def test_full_bucket_keeps_responsive_old_peer():
    async def scenario():
        table = RoutingTable(node_id(0), k=2)
        first = Contact(same_bucket_id(0), ("127.0.0.1", 9002))
        second = Contact(same_bucket_id(1), ("127.0.0.1", 9003))
        newcomer = Contact(same_bucket_id(2), ("127.0.0.1", 9004))
        table.add_contact(first, now=1)
        table.add_contact(second, now=2)
        pinged = []

        async def ping(contact):
            pinged.append(contact.node_id)
            return True

        assert not await table.add_contact_with_probe(newcomer, ping, now=3)
        assert pinged == [first.node_id]
        assert [c.node_id for c in table.get_bucket(255)] == [second.node_id, first.node_id]

    asyncio.run(scenario())


def test_full_bucket_replaces_unresponsive_old_peer():
    async def scenario():
        table = RoutingTable(node_id(0), k=2)
        first = Contact(same_bucket_id(0), ("127.0.0.1", 9002))
        second = Contact(same_bucket_id(1), ("127.0.0.1", 9003))
        newcomer = Contact(same_bucket_id(2), ("127.0.0.1", 9004))
        table.add_contact(first, now=1)
        table.add_contact(second, now=2)

        async def ping(_contact):
            return False

        assert await table.add_contact_with_probe(newcomer, ping, now=3)
        assert [c.node_id for c in table.get_bucket(255)] == [second.node_id, newcomer.node_id]
        assert table.contact_count == 2

    asyncio.run(scenario())


def test_ping_timeout_allows_eviction_of_old_peer():
    async def scenario():
        table = RoutingTable(node_id(0), k=1)
        old = Contact(same_bucket_id(0), ("127.0.0.1", 9002))
        newcomer = Contact(same_bucket_id(1), ("127.0.0.1", 9003))
        table.add_contact(old, now=1)

        async def ping(_contact):
            raise TimeoutError("peer did not answer")

        assert await table.add_contact_with_probe(newcomer, ping, now=2)
        assert [c.node_id for c in table.get_bucket(255)] == [newcomer.node_id]

    asyncio.run(scenario())


def test_closest_peers_are_sorted_by_xor_distance():
    table = RoutingTable(node_id(0), k=4)
    for number in (1, 2, 3, 7):
        table.add_contact(Contact(node_id(number), ("127.0.0.1", 9000 + number)))

    assert [c.node_id for c in table.closest(node_id(2), count=3)] == [
        node_id(2), node_id(3), node_id(1)
    ]


def test_invalid_ids_and_self_contact_are_rejected():
    with pytest.raises(RoutingError):
        RoutingTable(b"short")
    with pytest.raises(RoutingError):
        bucket_index(node_id(0), node_id(0))
    with pytest.raises(RoutingError):
        Contact(node_id(1), ("127.0.0.1", 70000))


def test_export_json_contains_nonempty_bucket_indexes_and_contacts(tmp_path):
    table = RoutingTable(node_id(0), k=2)
    first = Contact(node_id(1), ("127.0.0.1", 9001))
    second = Contact(node_id(1 << 255), ("127.0.0.1", 9002))
    table.add_contact(first, now=12.5)
    table.add_contact(second, now=13.5)

    output = table.export_json(tmp_path / "evidence" / "routing.json")
    document = json.loads(output.read_text(encoding="utf-8"))

    assert document["local_node_id"] == node_id(0).hex()
    assert document["k"] == 2
    assert document["bucket_count_total"] == 256
    assert document["bucket_count_nonempty"] == 2
    assert document["contact_count"] == 2
    assert [bucket["index"] for bucket in document["buckets"]] == [0, 255]
    assert document["buckets"][0]["contacts"] == [
        {
            "node_id": first.node_id.hex(),
            "host": "127.0.0.1",
            "port": 9001,
            "last_seen": 12.5,
        }
    ]
