"""Envelope encryption: a fresh AES-256-GCM data key per batch, wrapped by a KeyManager.

Why envelope encryption rather than one long-lived key?
  * The master key never leaves the key manager (KMS/HSM in production). Only the small,
    wrapped data key travels with the data.
  * Each batch gets its own data key, so rotating is free: the next run simply asks for a new
    key, and old batches stay readable because their wrapped key is stored alongside them.
  * Revoking access to the master key revokes access to every batch at once.

Ciphertext format for a single value: ``v1.<base64(nonce || ciphertext || tag)>``.
The column name is bound in as AES-GCM associated data, so a ciphertext copied into a different
column fails authentication instead of decrypting silently.

This module is pure Python (no Spark) so the crypto can be unit tested on its own.
"""

from __future__ import annotations

import base64
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CIPHERTEXT_PREFIX = "v1."
NONCE_BYTES = 12  # 96-bit nonce, the size AES-GCM is designed for
KEY_BYTES = 32  # AES-256


@dataclass(frozen=True)
class DataKey:
    """A data key in both forms. `plaintext` must stay in memory only."""

    plaintext: bytes = field(repr=False)
    wrapped: bytes
    key_id: str

    def header(self) -> str:
        """Serialisable reference stored next to the data so it can be unwrapped later."""
        return encode_header(self.key_id, self.wrapped)


def encode_header(key_id: str, wrapped: bytes) -> str:
    kid = base64.urlsafe_b64encode(key_id.encode()).decode()
    return f"{kid}.{base64.urlsafe_b64encode(wrapped).decode()}"


def decode_header(header: str) -> tuple[str, bytes]:
    kid, wrapped = header.split(".", 1)
    return base64.urlsafe_b64decode(kid).decode(), base64.urlsafe_b64decode(wrapped)


class KeyManager(ABC):
    """Generates and unwraps data keys. Implementations hold (or call out to) the master key."""

    @abstractmethod
    def generate_data_key(self) -> DataKey: ...

    @abstractmethod
    def unwrap(self, wrapped: bytes, key_id: str) -> bytes: ...


class LocalKeyManager(KeyManager):
    """In-process master keys. For demos and tests only: the master key is in memory.

    Several master keys can be registered so that data wrapped under an older master key is
    still readable after `active_key_id` moves on.
    """

    def __init__(self, master_keys: dict[str, bytes], active_key_id: str) -> None:
        if active_key_id not in master_keys:
            raise ValueError(f"active key '{active_key_id}' is not registered")
        for kid, key in master_keys.items():
            if len(key) != KEY_BYTES:
                raise ValueError(f"master key '{kid}' must be {KEY_BYTES} bytes")
        self._master_keys = dict(master_keys)
        self.active_key_id = active_key_id

    @classmethod
    def from_env(
        cls, var: str = "PII_LOCAL_MASTER_KEY", key_id: str = "local-1"
    ) -> LocalKeyManager:
        value = os.environ.get(var)
        if not value:
            raise RuntimeError(f"{var} is not set; see .env.example")
        return cls({key_id: base64.b64decode(value)}, key_id)

    @classmethod
    def ephemeral(cls, key_id: str = "ephemeral-1") -> LocalKeyManager:
        """A throwaway master key. Anything encrypted with it is unreadable after exit."""
        return cls({key_id: AESGCM.generate_key(bit_length=256)}, key_id)

    def generate_data_key(self) -> DataKey:
        dek = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(NONCE_BYTES)
        master = AESGCM(self._master_keys[self.active_key_id])
        wrapped = nonce + master.encrypt(nonce, dek, self.active_key_id.encode())
        return DataKey(plaintext=dek, wrapped=wrapped, key_id=self.active_key_id)

    def unwrap(self, wrapped: bytes, key_id: str) -> bytes:
        if key_id not in self._master_keys:
            raise KeyError(f"unknown master key '{key_id}'")
        nonce, body = wrapped[:NONCE_BYTES], wrapped[NONCE_BYTES:]
        return AESGCM(self._master_keys[key_id]).decrypt(nonce, body, key_id.encode())


class AwsKmsKeyManager(KeyManager):
    """AWS KMS adapter. Written against the public boto3 KMS API; not called in tests or CI.

    KMS does the wrapping server-side, so the master key never exists outside KMS. The
    encryption context is bound into the wrapped key and must match on decrypt, which stops a
    data key from another system being replayed here.
    """

    def __init__(
        self, key_id: str, client: Any | None = None, context: dict[str, str] | None = None
    ):
        self.key_id = key_id
        self.context = context or {"purpose": "pii-toolkit"}
        if client is None:
            import boto3  # imported lazily: boto3 is an optional extra

            client = boto3.client("kms")
        self._client = client

    def generate_data_key(self) -> DataKey:
        resp = self._client.generate_data_key(
            KeyId=self.key_id, KeySpec="AES_256", EncryptionContext=self.context
        )
        return DataKey(
            plaintext=resp["Plaintext"], wrapped=resp["CiphertextBlob"], key_id=resp["KeyId"]
        )

    def unwrap(self, wrapped: bytes, key_id: str) -> bytes:
        resp = self._client.decrypt(
            CiphertextBlob=wrapped, KeyId=key_id, EncryptionContext=self.context
        )
        return resp["Plaintext"]


def encrypt_value(key: bytes, value: str | None, aad: bytes) -> str | None:
    """Encrypt one value. A fresh random nonce per value means equal inputs differ on output."""
    if value is None:
        return None
    nonce = os.urandom(NONCE_BYTES)
    blob = nonce + AESGCM(key).encrypt(nonce, value.encode("utf-8"), aad)
    return CIPHERTEXT_PREFIX + base64.b64encode(blob).decode("ascii")


def decrypt_value(key: bytes, token: str | None, aad: bytes) -> str | None:
    if token is None:
        return None
    if not token.startswith(CIPHERTEXT_PREFIX):
        raise ValueError("not a v1 ciphertext")
    blob = base64.b64decode(token[len(CIPHERTEXT_PREFIX) :])
    nonce, body = blob[:NONCE_BYTES], blob[NONCE_BYTES:]
    return AESGCM(key).decrypt(nonce, body, aad).decode("utf-8")
