"""Determinism, irreversibility and masking behaviour of the column rules."""

from pyspark.sql import functions as F

from pii_toolkit.engine import apply_policy
from pii_toolkit.rules import hash_column, mask_column, tokenise_column
from pii_toolkit.vault import TokenVault

PII_COLUMNS = ["ssn", "email", "card_number", "date_of_birth"]


def _values(df, col=None):
    """Values of `col`, or of the first column when `col` is omitted."""
    return [r[0] for r in (df if col is None else df.select(col)).collect()]


def test_hash_is_deterministic_and_salted(customers, secrets):
    first = _values(customers.select(hash_column(F.col("ssn"), secrets.hash_salt)))
    second = _values(customers.select(hash_column(F.col("ssn"), secrets.hash_salt)))
    other_salt = _values(customers.select(hash_column(F.col("ssn"), "a-different-salt")))
    assert first == second
    assert all(len(h) == 64 for h in first)
    assert set(first).isdisjoint(other_salt)


def test_tokenise_is_deterministic_across_runs_and_joinable(customers, secrets):
    run1 = customers.select(
        "customer_id", tokenise_column(F.col("email"), secrets.token_key).alias("t")
    )
    run2 = customers.select(
        "customer_id", tokenise_column(F.col("email"), secrets.token_key).alias("t")
    )
    joined = run1.join(run2, ["customer_id", "t"])
    assert joined.count() == customers.count()
    assert all(t.startswith("tok_") for t in _values(run1, "t"))


def test_no_plaintext_survives_protection(spark, customers, secrets, key_manager, policy, tmp_path):
    vault = TokenVault(spark, str(tmp_path / "vault"), key_manager)
    result = apply_policy(customers, policy, secrets, key_manager=key_manager, vault=vault)
    original = {c: set(_values(customers, c)) for c in PII_COLUMNS}
    protected = result.df.collect()
    for row in protected:
        for col in ["ssn", "email", "date_of_birth"]:
            assert row[col] not in original[col]
            # not even as a substring (e.g. a "salt|value" concatenation leaking through)
            assert not any(v in row[col] for v in original[col])
        assert row["notes"] is None
        assert row["card_number"] not in original["card_number"]


def test_hash_cannot_be_recovered_by_brute_force_without_salt(customers, secrets):
    """An attacker who guesses the value but not the salt cannot reproduce the hash."""
    hashed = set(_values(customers.select(hash_column(F.col("ssn"), secrets.hash_salt))))
    unsalted = set(_values(customers.select(F.sha2(F.col("ssn"), 256))))
    assert hashed.isdisjoint(unsalted)


def test_mask_keeps_last_four(spark):
    df = spark.createDataFrame([("4000001234567899",), ("1234",), ("12",), (None,)], "v string")
    out = _values(df.select(mask_column(F.col("v"), 4)))
    assert out == ["************7899", "****", "**", None]


def test_mask_keep_zero_masks_everything(spark):
    df = spark.createDataFrame([("abcdef",)], "v string")
    assert _values(df.select(mask_column(F.col("v"), 0, "#"))) == ["######"]


def test_nullify_preserves_type(customers, secrets, key_manager, policy, spark, tmp_path):
    vault = TokenVault(spark, str(tmp_path / "vault"), key_manager)
    result = apply_policy(customers, policy, secrets, key_manager=key_manager, vault=vault)
    assert result.df.schema["notes"].dataType == customers.schema["notes"].dataType
