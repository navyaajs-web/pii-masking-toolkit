"""Spark column expressions for each rule.

Native Spark functions are used where they exist (sha2, lpad, substring) because they run in the
JVM and avoid Python serialisation. HMAC and AES-GCM have no Spark built-in, so those two use
Python UDFs; the key material reaches executors inside the UDF closure, which is the normal
trade-off for envelope encryption on Spark and is why data keys are per batch and short-lived.

Every rule maps null to null: a null carries no PII, and keeping it null preserves the
"value was missing" signal for downstream quality checks.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable

from pyspark.sql import Column, DataFrame
from pyspark.sql import functions as F
from pyspark.sql.types import DataType, StringType

from pii_toolkit.envelope import DataKey, KeyManager, decode_header, decrypt_value, encrypt_value

DEK_COLUMN = "_pii_dek"
TOKEN_PREFIX = "tok_"
TOKEN_HEX_CHARS = 32  # 128 bits of HMAC output: collision-safe for any realistic table


def string_udf(fn: Callable[..., str | None]) -> Callable[..., Column]:
    """Wrap a plain Python function as a string-returning, row-at-a-time Spark UDF.

    Spark 4 inspects a UDF's type hints to decide whether it is a pandas UDF and warns when it
    cannot tell. Hiding the hints behind a lambda keeps it a plain Python UDF, so no pandas or
    pyarrow dependency is needed.
    """
    return F.udf(lambda *args: fn(*args), StringType())


def hash_column(col: Column, salt: str) -> Column:
    """Salted SHA-256. One-way: use when nobody ever needs the original back.

    The salt defeats rainbow tables for low-entropy values (phone numbers, national IDs). It
    is the same across tables so that hashed keys still join.
    """
    value = col.cast("string")
    return F.when(value.isNull(), F.lit(None)).otherwise(
        F.sha2(F.concat(F.lit(salt), F.lit("|"), value), 256)
    )


def token_for(key: bytes, value: str) -> str:
    """Deterministic token: same key + same value -> same token, so joins keep working."""
    digest = hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()
    return TOKEN_PREFIX + digest[:TOKEN_HEX_CHARS]


def tokenise_column(col: Column, key: bytes) -> Column:
    """HMAC-SHA256 token. Unlike a plain hash, guessing requires the key, not just the salt."""

    @string_udf
    def _tokenise(value: str | None) -> str | None:
        return None if value is None else token_for(key, value)

    return _tokenise(col.cast("string"))


def mask_column(col: Column, keep_last: int = 4, mask_char: str = "*") -> Column:
    """Replace all but the last `keep_last` characters.

    Values no longer than `keep_last` are masked completely: showing "the last 4" of a
    4-character value would show all of it.
    """
    value = col.cast("string")
    length = F.length(value)
    fully_masked = F.lpad(F.lit(""), length, mask_char)
    if keep_last == 0:
        partially_masked = fully_masked
    else:
        partially_masked = F.lpad(F.substring(value, -keep_last, keep_last), length, mask_char)
    return (
        F.when(value.isNull(), F.lit(None))
        .when(length <= keep_last, fully_masked)
        .otherwise(partially_masked)
    )


def nullify_column(data_type: DataType) -> Column:
    """Drop the value but keep the column and its type, so downstream schemas do not break."""
    return F.lit(None).cast(data_type)


def encrypt_column(col: Column, data_key: DataKey, column_name: str) -> Column:
    """AES-GCM with the batch data key; the column name is bound in as associated data."""
    key, aad = data_key.plaintext, column_name.encode("utf-8")

    @string_udf
    def _encrypt(value: str | None) -> str | None:
        return encrypt_value(key, value, aad)

    return _encrypt(col.cast("string"))


def decrypt_column(df: DataFrame, column_name: str, key_manager: KeyManager) -> DataFrame:
    """Reverse `encrypt_column`. Returns the column as string.

    A DataFrame may union several batches, each with its own data key, so every distinct key
    header is unwrapped once on the driver and the right key is picked per row.
    """
    headers = [r[0] for r in df.select(DEK_COLUMN).distinct().collect() if r[0] is not None]
    keys: dict[str, bytes] = {}
    for header in headers:
        key_id, wrapped = decode_header(header)
        keys[header] = key_manager.unwrap(wrapped, key_id)
    aad = column_name.encode("utf-8")

    @string_udf
    def _decrypt(token: str | None, header: str | None) -> str | None:
        if token is None:
            return None
        return decrypt_value(keys[header], token, aad)

    return df.withColumn(column_name, _decrypt(F.col(column_name), F.col(DEK_COLUMN)))
