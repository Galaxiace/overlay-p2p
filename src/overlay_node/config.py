"""Чтение внешних параметров узла из config/default.json."""

from __future__ import annotations

import json
import os
from pathlib import Path

DEFAULTS = {
    "node_id_bits": 256,
    "protocol_version": 1,
    "max_frame_payload": 65536,
    "frame_timeout_seconds": 10.0,
    "rpc_timeout_seconds": 5.0,
    "ping_timeout_seconds": 3.0,
    "probe_timeout_seconds": 2.0,
    "k_bucket_size": 3,
    "alpha": 3,
    "replication_factor": 3,
    "store_quorum": 2,
    "dht_ttl_seconds": 180,
    "dht_min_ttl_seconds": 120,
    "dht_max_ttl_seconds": 300,
    "refresh_interval_seconds": 60,
    "republish_interval_seconds": 60,
    "lookup_max_hops": 16,
    "lookup_pool_size": 32,
    "degradation_error_threshold": 3,
    "max_record_bytes": 4096,
    "max_node_addresses": 8,
    "max_file_bytes": 10485760,
}


class ConfigError(ValueError):
    """Ошибка внешней конфигурации узла."""


def load_config(path: str | Path | None = None) -> dict:
    configured_path = path or os.environ.get("OVERLAY_CONFIG")
    if configured_path is None:
        configured_path = Path(__file__).resolve().parents[2] / "config" / "default.json"
    config_path = Path(configured_path)
    try:
        supplied = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"Не удалось прочитать конфигурацию {config_path}: {exc}") from exc
    if not isinstance(supplied, dict):
        raise ConfigError("Конфигурация должна быть JSON-объектом")
    unknown = set(supplied) - set(DEFAULTS)
    if unknown:
        raise ConfigError(f"Неизвестные параметры: {', '.join(sorted(unknown))}")
    result = {**DEFAULTS, **supplied}
    for key, default in DEFAULTS.items():
        value = result[key]
        if isinstance(default, float):
            if not isinstance(value, (int, float)) or isinstance(value, bool) or value <= 0:
                raise ConfigError(f"{key} должен быть положительным числом")
            result[key] = float(value)
        elif not isinstance(value, int) or isinstance(value, bool):
            raise ConfigError(f"{key} должен быть целым числом")
    if result["node_id_bits"] != 256:
        raise ConfigError("node_id_bits фиксирован равным 256 для SHA-256 NodeID")
    if not 1 <= result["protocol_version"] <= 255:
        raise ConfigError("protocol_version должен быть в диапазоне 1–255")
    if not 1 <= result["max_frame_payload"] <= 65536:
        raise ConfigError("max_frame_payload должен быть в диапазоне 1–65536")
    if result["k_bucket_size"] < 1 or result["alpha"] < 1:
        raise ConfigError("k_bucket_size и alpha должны быть положительными")
    if result["lookup_pool_size"] < result["k_bucket_size"]:
        raise ConfigError("lookup_pool_size не должен быть меньше k_bucket_size")
    for key in (
        "refresh_interval_seconds",
        "republish_interval_seconds",
        "lookup_max_hops",
        "lookup_pool_size",
        "degradation_error_threshold",
        "max_file_bytes",
    ):
        if result[key] < 1:
            raise ConfigError(f"{key} должен быть положительным")
    if result["replication_factor"] < 1 or not 1 <= result["store_quorum"] <= result["replication_factor"]:
        raise ConfigError("store_quorum должен быть от 1 до replication_factor")
    if not 1 <= result["dht_min_ttl_seconds"] <= result["dht_ttl_seconds"] <= result["dht_max_ttl_seconds"]:
        raise ConfigError("Требуется min TTL <= TTL по умолчанию <= max TTL")
    if result["republish_interval_seconds"] > result["dht_ttl_seconds"] // 2:
        raise ConfigError("republish_interval_seconds не должен превышать половину TTL")
    if result["max_record_bytes"] < 512 or result["max_record_bytes"] > result["max_frame_payload"]:
        raise ConfigError("max_record_bytes должен быть от 512 до лимита кадра")
    if result["max_node_addresses"] < 1:
        raise ConfigError("max_node_addresses должен быть положительным")
    return result


CONFIG = load_config()
