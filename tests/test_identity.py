from overlay_node.identity import (
    IdentityError,
    NodeIdentity,
    node_id_from_public_key,
    verify_node_id,
    verify_signature,
)


def test_identity_is_stable_after_reload(tmp_path):
    first = NodeIdentity.load_or_create(tmp_path / "node-a")
    reloaded = NodeIdentity.load_or_create(tmp_path / "node-a")

    assert first.public_key_bytes == reloaded.public_key_bytes
    assert first.node_id == reloaded.node_id
    assert verify_node_id(reloaded.public_key_bytes, first.node_id)


def test_separate_nodes_get_different_identities(tmp_path):
    node_a = NodeIdentity.load_or_create(tmp_path / "node-a")
    node_b = NodeIdentity.load_or_create(tmp_path / "node-b")

    assert node_a.node_id != node_b.node_id


def test_claimed_node_id_must_match_public_key(tmp_path):
    node = NodeIdentity.load_or_create(tmp_path / "node-a")
    other = NodeIdentity.load_or_create(tmp_path / "node-b")

    assert verify_node_id(node.public_key_bytes, node.node_id)
    assert not verify_node_id(node.public_key_bytes, other.node_id)
    assert not verify_node_id(b"short", node.node_id)


def test_ed25519_signature_detects_modified_message(tmp_path):
    node = NodeIdentity.load_or_create(tmp_path / "node-a")
    message = b"node record v1"
    signature = node.sign(message)

    assert verify_signature(node.public_key_bytes, message, signature)
    assert not verify_signature(node.public_key_bytes, b"node record v2", signature)


def test_node_id_rejects_wrong_public_key_length():
    try:
        node_id_from_public_key(b"short")
    except IdentityError:
        pass
    else:
        raise AssertionError("Ожидалась ошибка для некорректной длины открытого ключа")
