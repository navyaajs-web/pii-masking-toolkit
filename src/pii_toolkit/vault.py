"""Token vault: the only place a tokenised value can be turned back into the original.

Design choices:
  * Values in the vault are themselves envelope-encrypted (one data key per write). A copy of
    the vault files on its own does not leak PII; you also need the key manager.
  * Writes are insert-only: a token that already exists is never rewritten, so a token keeps
    meaning the same thing forever.
  * Re-identification checks the caller's role. This is an application-level guard that makes
    intent explicit in code and audit; real enforcement belongs in storage ACLs / IAM, with the
    vault path readable only by the re-identification role.
  * Storage format is configurable (`parquet` by default). Delta works the same way when
    delta-spark is on the classpath, but only Parquet is exercised in the tests.
"""

from __future__ import annotations

from pyspark.errors import AnalysisException
from pyspark.sql import DataFrame, SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import StringType, StructField, StructType, TimestampType

from pii_toolkit.envelope import KeyManager, decode_header, decrypt_value, encrypt_value
from pii_toolkit.rules import DEK_COLUMN, string_udf

REIDENTIFY_ROLE = "pii_reidentifier"

VAULT_SCHEMA = StructType(
    [
        StructField("column_name", StringType(), False),
        StructField("token", StringType(), False),
        StructField("value_ct", StringType(), False),
        StructField(DEK_COLUMN, StringType(), False),
        StructField("created_at", TimestampType(), False),
    ]
)


def _aad(column_name: str) -> bytes:
    return f"vault:{column_name}".encode()


class TokenVault:
    def __init__(
        self,
        spark: SparkSession,
        path: str,
        key_manager: KeyManager,
        fmt: str = "parquet",
        reidentify_roles: frozenset[str] = frozenset({REIDENTIFY_ROLE}),
    ) -> None:
        self.spark = spark
        self.path = path
        self.key_manager = key_manager
        self.fmt = fmt
        self.reidentify_roles = reidentify_roles

    def read(self) -> DataFrame:
        try:
            return self.spark.read.format(self.fmt).load(self.path)
        except AnalysisException:  # vault not created yet
            return self.spark.createDataFrame([], VAULT_SCHEMA)

    def record(self, pairs: DataFrame) -> int:
        """Insert new (column_name, token, value) rows; existing tokens are left untouched.

        Returns the number of tokens added.
        """
        data_key = self.key_manager.generate_data_key()
        key = data_key.plaintext

        @string_udf
        def _encrypt(column_name: str, value: str) -> str | None:
            return encrypt_value(key, value, _aad(column_name))

        existing = self.read().select("column_name", "token")
        new_rows = (
            pairs.select("column_name", "token", "value")
            .where(F.col("value").isNotNull())
            .dropDuplicates(["column_name", "token"])
            .join(existing, ["column_name", "token"], "left_anti")
            .select(
                "column_name",
                "token",
                _encrypt("column_name", "value").alias("value_ct"),
                F.lit(data_key.header()).alias(DEK_COLUMN),
                F.current_timestamp().alias("created_at"),
            )
            # Materialise before writing: we read from the same path we append to.
            .localCheckpoint()
        )
        added = new_rows.count()
        if added:
            new_rows.write.format(self.fmt).mode("append").save(self.path)
        return added

    def reidentify(self, df: DataFrame, column: str, role: str) -> DataFrame:
        """Swap tokens in `column` back to original values. Requires an authorised role."""
        if role not in self.reidentify_roles:
            raise PermissionError(f"role '{role}' may not re-identify tokens")

        vault = self.read().where(F.col("column_name") == column)
        keys: dict[str, bytes] = {}
        for (header,) in vault.select(DEK_COLUMN).distinct().collect():
            key_id, wrapped = decode_header(header)
            keys[header] = self.key_manager.unwrap(wrapped, key_id)
        aad = _aad(column)

        @string_udf
        def _decrypt(value_ct: str | None, header: str | None) -> str | None:
            return None if value_ct is None else decrypt_value(keys[header], value_ct, aad)

        lookup = vault.select(
            F.col("token").alias("__token"),
            _decrypt("value_ct", DEK_COLUMN).alias("__value"),
        )
        joined = df.join(lookup, df[column] == lookup["__token"], "left")
        return joined.withColumn(column, F.col("__value")).drop("__token", "__value")
