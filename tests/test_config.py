import json

import pytest

from overlay_node.config import ConfigError, load_config


def test_default_config_has_current_protocol_and_dht_parameters():
    config = load_config()
    assert config["protocol_version"] == 1
    assert config["k_bucket_size"] == 3
    assert config["alpha"] == 3
    assert config["replication_factor"] == 3
    assert config["store_quorum"] == 2


def test_pilot_config_is_loadable_as_an_independent_runtime_profile():
    from pathlib import Path

    pilot_path = Path(__file__).resolve().parents[1] / "config" / "pilot.json"
    config = load_config(pilot_path)

    assert config["protocol_version"] == 1
    assert config["k_bucket_size"] == 3
    assert config["alpha"] == 3
    assert config["replication_factor"] == 3
    assert config["store_quorum"] == 2


def test_config_rejects_inconsistent_quorum(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"replication_factor": 2, "store_quorum": 3}), encoding="utf-8")
    with pytest.raises(ConfigError, match="store_quorum"):
        load_config(path)
