"""Долговременная идентичность узла на основе Ed25519."""

from __future__ import annotations

import hashlib
import secrets
import tempfile
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PUBLIC_KEY_SIZE = 32
PRIVATE_KEY_FILE = "identity_ed25519.key"
NODE_ID_DOMAIN = b"overlay-p2p/identity/ed25519/v1\x00"


class IdentityError(ValueError):
    """Ошибка создания, загрузки или проверки идентичности узла."""


def canonical_encode_public_key(public_key: bytes) -> bytes:
    """Каноническое представление: домен, длина ключа и raw Ed25519 key."""
    if len(public_key) != PUBLIC_KEY_SIZE:
        raise IdentityError(f"Ed25519 public key должен быть длиной {PUBLIC_KEY_SIZE} байт")
    return NODE_ID_DOMAIN + PUBLIC_KEY_SIZE.to_bytes(2, "big") + public_key


def node_id_from_public_key(public_key: bytes) -> bytes:
    """Возвращает NodeID = SHA-256(canonical_encode(identity_public_key))."""
    return hashlib.sha256(canonical_encode_public_key(public_key)).digest()


def verify_node_id(public_key: bytes, claimed_node_id: bytes) -> bool:
    """Проверяет, соответствует ли объявленный NodeID открытому ключу."""
    if len(claimed_node_id) != hashlib.sha256().digest_size:
        return False
    try:
        expected = node_id_from_public_key(public_key)
    except IdentityError:
        return False
    return secrets.compare_digest(expected, claimed_node_id)


def verify_signature(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Проверяет Ed25519-подпись, не раскрывая детали ошибки вызывающему коду."""
    if len(public_key) != PUBLIC_KEY_SIZE:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


@dataclass(frozen=True)
class NodeIdentity:
    """Пара ключей и стабильный NodeID одного логического узла."""

    private_key: Ed25519PrivateKey

    @property
    def public_key_bytes(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def node_id(self) -> bytes:
        return node_id_from_public_key(self.public_key_bytes)

    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(message)

    @classmethod
    def load_or_create(cls, state_dir: str | Path) -> "NodeIdentity":
        """Загружает постоянный ключ узла или создаёт его при первом запуске."""
        state_path = Path(state_dir)
        state_path.mkdir(parents=True, exist_ok=True)
        key_path = state_path / PRIVATE_KEY_FILE

        if key_path.exists():
            raw_private_key = key_path.read_bytes()
            try:
                return cls(Ed25519PrivateKey.from_private_bytes(raw_private_key))
            except ValueError as exc:
                raise IdentityError(f"Файл ключа повреждён или имеет неверный формат: {key_path}") from exc

        private_key = Ed25519PrivateKey.generate()
        raw_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Сначала полностью записываем временный файл в том же каталоге,
        # затем атомарно переименовываем его в постоянный файл ключа.
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=state_path, prefix=".identity-", delete=False
            ) as temporary_file:
                temporary_path = Path(temporary_file.name)
                temporary_file.write(raw_private_key)
                temporary_file.flush()
            temporary_path.replace(key_path)
        finally:
            if temporary_path is not None and temporary_path.exists():
                temporary_path.unlink()

        return cls(private_key)
