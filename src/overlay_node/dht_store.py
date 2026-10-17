"""Локальное хранилище NodeRecord с TTL и защитой от отката версии."""

from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from overlay_node.records import NodeRecord


@dataclass(frozen=True)
class StoreDecision:
    accepted: bool
    highest_sequence: int
    reason: str = ""


@dataclass
class _Entry:
    highest_sequence: int
    record: NodeRecord | None


class DHTStore:
    """Хранилище записей одного узла; `path=None` создаёт память-only store."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else None
        self._entries: dict[str, _Entry] = {}
        if self.path is not None and self.path.exists():
            self._load()

    def put(self, record: NodeRecord, now: int | None = None) -> StoreDecision:
        current_time = int(time.time()) if now is None else int(now)
        record.validate(now=current_time)
        key = record.dht_key.hex()
        existing = self._entries.get(key)
        highest = existing.highest_sequence if existing else -1
        if record.sequence_number < highest:
            return StoreDecision(False, highest, "sequence_number ниже сохранённой версии")
        if record.sequence_number == highest:
            if existing and existing.record and existing.record == record:
                return StoreDecision(True, highest, "повторная запись уже сохранена")
            return StoreDecision(False, highest, "конфликт записи с тем же sequence_number")
        self._entries[key] = _Entry(record.sequence_number, record)
        self._save()
        return StoreDecision(True, record.sequence_number)

    def get(self, key: bytes, now: int | None = None) -> NodeRecord | None:
        if len(key) != 32:
            raise ValueError("DHT key должен занимать 32 байта")
        current_time = int(time.time()) if now is None else int(now)
        entry = self._entries.get(key.hex())
        if entry is None or entry.record is None:
            return None
        if entry.record.expires_at <= current_time:
            entry.record = None
            self._save()
            return None
        return entry.record

    def highest_sequence(self, key: bytes) -> int | None:
        entry = self._entries.get(key.hex())
        return entry.highest_sequence if entry else None

    def cleanup(self, now: int | None = None) -> int:
        current_time = int(time.time()) if now is None else int(now)
        removed = 0
        for entry in self._entries.values():
            if entry.record is not None and entry.record.expires_at <= current_time:
                entry.record = None
                removed += 1
        if removed:
            self._save()
        return removed

    def _load(self) -> None:
        assert self.path is not None
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if raw.get("format_version") != 1 or not isinstance(raw.get("entries"), dict):
                raise ValueError("неподдерживаемый формат файла DHT")
            for key, item in raw["entries"].items():
                sequence = item["highest_sequence"]
                if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
                    raise ValueError("некорректный sequence_number в хранилище")
                record_data = item.get("record")
                record = None
                if record_data is not None:
                    encoded = json.dumps(record_data, sort_keys=True, separators=(",", ":")).encode("ascii")
                    record = NodeRecord.from_payload(encoded, now=int(record_data["issued_at"]))
                    if record.dht_key.hex() != key or record.sequence_number != sequence:
                        raise ValueError("несогласованная запись в хранилище")
                    if record.expires_at <= int(time.time()):
                        record = None
                self._entries[key] = _Entry(sequence, record)
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"Не удалось загрузить DHT-хранилище {self.path}: {exc}") from exc

    def _save(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        entries = {}
        for key, entry in self._entries.items():
            record_data = json.loads(entry.record.to_payload().decode("ascii")) if entry.record else None
            entries[key] = {"highest_sequence": entry.highest_sequence, "record": record_data}
        document = {"format_version": 1, "entries": entries}
        fd, temporary_name = tempfile.mkstemp(prefix=".dht-", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                json.dump(document, stream, sort_keys=True, separators=(",", ":"))
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_name, self.path)
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)
