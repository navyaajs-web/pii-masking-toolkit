"""Envelope encryption: round-trips, per-batch keys, and tamper detection."""

import pytest
from cryptography.exceptions import InvalidTag

from pii_toolkit.engine import apply_policy
from pii_toolkit.envelope import (
    AwsKmsKeyManager,
    LocalKeyManager,
    decode_header,
    decrypt_value,
    encrypt_value,
)
from pii_toolkit.rules import DEK_COLUMN, decrypt_column
from pii_toolkit.vault import TokenVault


def test_value_round_trip_and_random_nonce(key_manager):
    dk = key_manager.generate_data_key()
    a = encrypt_value(dk.plaintext, "1984-02-29", b"dob")
    b = encrypt_value(dk.plaintext, "1984-02-29", b"dob")
    assert a != b  # same plaintext, different ciphertext
    assert decrypt_value(dk.plaintext, a, b"dob") == "1984-02-29"


def test_ciphertext_bound_to_column(key_manager):
    dk = key_manager.generate_data_key()
    token = encrypt_value(dk.plaintext, "secret", b"date_of_birth")
    with pytest.raises(InvalidTag):
        decrypt_value(dk.plaintext, token, b"other_column")


def test_wrapped_key_unwraps_and_rejects_tampering(key_manager):
    dk = key_manager.generate_data_key()
    key_id, wrapped = decode_header(dk.header())
    assert key_manager.unwrap(wrapped, key_id) == dk.plaintext
    tampered = wrapped[:-1] + bytes([wrapped[-1] ^ 1])
    with pytest.raises(InvalidTag):
        key_manager.unwrap(tampered, key_id)


def test_old_master_key_still_readable_after_rotation():
    old = LocalKeyManager.ephemeral("m1")
    dk = old.generate_data_key()
    rotated = LocalKeyManager({**old._master_keys, "m2": b"\x01" * 32}, active_key_id="m2")
    assert rotated.generate_data_key().key_id == "m2"
    assert rotated.unwrap(dk.wrapped, "m1") == dk.plaintext


def test_dataframe_decrypt_round_trip(spark, customers, secrets, key_manager, policy, tmp_path):
    vault = TokenVault(spark, str(tmp_path / "vault"), key_manager)
    protected = apply_policy(customers, policy, secrets, key_manager=key_manager, vault=vault).df
    assert protected.select(DEK_COLUMN).distinct().count() == 1  # one data key per batch
    restored = decrypt_column(protected, "date_of_birth", key_manager)
    expected = {r.customer_id: r.date_of_birth for r in customers.collect()}
    actual = {r.customer_id: r.date_of_birth for r in restored.collect()}
    assert actual == expected


def test_each_batch_gets_a_new_data_key_and_union_still_decrypts(
    spark, customers, secrets, key_manager, policy, tmp_path
):
    vault = TokenVault(spark, str(tmp_path / "vault"), key_manager)
    b1 = apply_policy(customers, policy, secrets, key_manager=key_manager, vault=vault).df
    b2 = apply_policy(customers, policy, secrets, key_manager=key_manager, vault=vault).df
    both = b1.unionByName(b2)
    assert both.select(DEK_COLUMN).distinct().count() == 2
    restored = decrypt_column(both, "date_of_birth", key_manager)
    assert restored.where("date_of_birth is null").count() == 0


def test_aws_adapter_calls_kms_api_shape():
    """The KMS adapter is not called against AWS; a stub checks it uses the API correctly."""

    class StubKms:
        def generate_data_key(self, **kw):
            assert kw["KeySpec"] == "AES_256" and kw["EncryptionContext"]
            return {"Plaintext": b"k" * 32, "CiphertextBlob": b"wrapped", "KeyId": "arn:stub"}

        def decrypt(self, **kw):
            assert kw["CiphertextBlob"] == b"wrapped" and kw["EncryptionContext"]
            return {"Plaintext": b"k" * 32}

    km = AwsKmsKeyManager("alias/stub", client=StubKms())
    dk = km.generate_data_key()
    key_id, wrapped = decode_header(dk.header())
    assert km.unwrap(wrapped, key_id) == dk.plaintext
