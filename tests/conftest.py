from __future__ import annotations

import pytest
from pyspark.sql import SparkSession

from pii_toolkit.engine import Secrets
from pii_toolkit.envelope import LocalKeyManager
from pii_toolkit.policy import parse_policy
from pii_toolkit.spark import get_spark
from pii_toolkit.synthetic import generate_customers


@pytest.fixture(scope="session")
def spark() -> SparkSession:
    session = get_spark("pii-toolkit-tests")
    yield session
    session.stop()


@pytest.fixture(scope="session")
def customers(spark):
    return spark.createDataFrame(generate_customers(60, seed=11)).cache()


@pytest.fixture
def secrets() -> Secrets:
    # Test-only constants, not real secrets.
    return Secrets(hash_salt="test-salt-not-a-secret", token_key=b"test-token-key-not-a-secret")


@pytest.fixture
def key_manager() -> LocalKeyManager:
    return LocalKeyManager.ephemeral()


@pytest.fixture
def policy():
    return parse_policy(
        {
            "version": 1,
            "name": "test_policy",
            "columns": {
                "ssn": "hash",
                "email": {"rule": "tokenise"},
                "card_number": {"rule": "mask", "keep_last": 4},
                "notes": "nullify",
                "date_of_birth": {"rule": "encrypt"},
            },
        }
    )
