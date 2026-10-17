from dataclasses import replace

import pytest

from overlay_node.dht_store import DHTStore
from overlay_node.identity import NodeIdentity
from overlay_node.records import MAX_RECORD_BYTES, NodeRecord, RecordError, node_record_key


def make_record(identity, sequence=1, now=1_700_000_000, address=("127.0.0.1", 9000)):
    return NodeRecord.create(
        identity,
        (address,),
        sequence_number=sequence,
        ttl_seconds=180,
        now=now,
    )


def test_node_record_round_trip_and_signature(tmp_path):
    identity = NodeIdentity.load_or_create(tmp_path / "identity")
    record = make_record(identity)
    decoded = NodeRecord.from_payload(record.to_payload(), now=1_700_000_000)

    assert decoded == record
    assert decoded.dht_key == node_record_key(identity.node_id)


def test_node_record_rejects_payload_over_limit():
    with pytest.raises(RecordError, match="Размер NodeRecord"):
        NodeRecord.from_payload(b" " * (MAX_RECORD_BYTES + 1))


def test_node_record_rejects_tampered_address_and_wrong_owner_key(tmp_path):
    identity = NodeIdentity.load_or_create(tmp_path / "identity")
    other = NodeIdentity.load_or_create(tmp_path / "other")
    record = make_record(identity)

    with pytest.raises(RecordError, match="Подпись"):
        replace(record, addresses=(("127.0.0.2", 9000),)).validate(now=1_700_000_000)
    with pytest.raises(RecordError, match="не соответствует"):
        replace(record, identity_public_key=other.public_key_bytes).validate(now=1_700_000_000)
    with pytest.raises(RecordError, match="не соответствует"):
        replace(record, node_id=other.node_id).validate(now=1_700_000_000)


def test_node_record_rejects_expired_bad_address_and_out_of_range_ttl(tmp_path):
    identity = NodeIdentity.load_or_create(tmp_path / "identity")
    record = make_record(identity)

    with pytest.raises(RecordError, match="истёк"):
        record.validate(now=record.expires_at)
    malformed = NodeRecord(
        identity.node_id,
        identity.public_key_bytes,
        (("bad host", 9000),),
        1,
        1_700_000_000,
        1_700_000_180,
        b"\x00" * 64,
    )
    malformed = replace(malformed, signature=identity.sign(malformed.signing_bytes()))
    with pytest.raises(RecordError, match="host или TCP-порт"):
        malformed.validate(now=1_700_000_000)
    with pytest.raises(RecordError, match="TTL"):
        NodeRecord.create(identity, (("127.0.0.1", 9000),), 1, ttl_seconds=30, now=1_700_000_000)


def test_store_rejects_rollback_even_after_expired_value_is_cleaned(tmp_path):
    identity = NodeIdentity.load_or_create(tmp_path / "identity")
    path = tmp_path / "replica.json"
    store = DHTStore(path)
    newest = make_record(identity, sequence=4)
    assert store.put(newest, now=1_700_000_000).accepted
    assert store.get(newest.dht_key, now=1_700_000_180) is None

    reopened = DHTStore(path)
    older = make_record(identity, sequence=3, now=1_700_000_181)
    decision = reopened.put(older, now=1_700_000_181)
    assert not decision.accepted
    assert decision.highest_sequence == 4


def test_store_rejects_conflicting_record_at_same_sequence(tmp_path):
    identity = NodeIdentity.load_or_create(tmp_path / "identity")
    store = DHTStore()
    first = make_record(identity, sequence=2)
    conflicting = NodeRecord.create(
        identity,
        (("127.0.0.2", 9001),),
        sequence_number=2,
        ttl_seconds=180,
        now=1_700_000_000,
    )
    assert store.put(first, now=1_700_000_000).accepted
    assert not store.put(conflicting, now=1_700_000_000).accepted
