import json

import pytest

from overlay_node.identity import NodeIdentity
from overlay_node.protocol import FindNodeRequest, FindNodeResponse
from overlay_node.routing import Contact


def test_find_node_request_round_trip_checks_sender_identity(tmp_path):
    sender = NodeIdentity.load_or_create(tmp_path / "sender")
    target = NodeIdentity.load_or_create(tmp_path / "target")
    message = FindNodeRequest.for_identity(sender, target.node_id)

    decoded = FindNodeRequest.from_payload(message.to_payload())
    assert decoded == message


def test_find_node_request_rejects_node_id_key_mismatch(tmp_path):
    sender = NodeIdentity.load_or_create(tmp_path / "sender")
    other = NodeIdentity.load_or_create(tmp_path / "other")
    payload = {
        "sender_node_id": other.node_id.hex(),
        "sender_public_key": sender.public_key_bytes.hex(),
        "target_node_id": sender.node_id.hex(),
    }

    with pytest.raises(ValueError, match="не соответствует"):
        FindNodeRequest.from_payload(json.dumps(payload).encode("utf-8"))


def test_find_node_response_round_trip_and_identity_validation(tmp_path):
    responder = NodeIdentity.load_or_create(tmp_path / "responder")
    peer = NodeIdentity.load_or_create(tmp_path / "peer")
    response = FindNodeResponse(
        responder_node_id=responder.node_id,
        responder_public_key=responder.public_key_bytes,
        contacts=(Contact(peer.node_id, ("127.0.0.1", 9001)),),
    )

    decoded = FindNodeResponse.from_payload(response.to_payload())
    assert decoded == response

    payload = json.loads(response.to_payload())
    payload["responder_node_id"] = peer.node_id.hex()
    with pytest.raises(ValueError, match="не соответствует"):
        FindNodeResponse.from_payload(json.dumps(payload).encode("utf-8"))
