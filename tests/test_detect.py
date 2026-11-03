import logging

from pii_toolkit.detect import detect, unmapped_findings
from pii_toolkit.policy import parse_policy


def _by_column(findings):
    out = {}
    for f in findings:
        out.setdefault(f.column, set()).add((f.pii_type, f.reason))
    return out


def test_detects_by_name_and_by_value(customers):
    found = _by_column(detect(customers))
    assert ("national_id", "name") in found["ssn"]
    assert ("national_id", "values") in found["ssn"]
    assert ("card_number", "values") in found["card_number"]
    assert ("email", "values") in found["contact_alt"]  # innocuous name, PII values
    assert ("person_name", "name") in found["first_name"]
    assert "segment" not in found and "city" not in found


def test_value_rule_needs_a_majority(spark):
    df = spark.createDataFrame(
        [("call me at someone@example.com",), ("no",), ("n/a",), ("ok",)], "remarks string"
    )
    assert detect(df) == []


def test_card_detection_requires_luhn(spark):
    df = spark.createDataFrame([("4000001234567890",), ("4000001234567891",)], "ref string")
    assert all(f.pii_type != "card_number" for f in detect(df))


def test_unmapped_columns_warn(customers, policy, caplog):
    with caplog.at_level(logging.WARNING, logger="pii_toolkit.detect"):
        findings = unmapped_findings(customers, policy)
    columns = {f.column for f in findings}
    assert "contact_alt" in columns and "phone" in columns
    assert "ssn" not in columns and "email" not in columns  # mapped in the policy
    assert any("contact_alt" in m for m in caplog.messages)


def test_fully_mapped_policy_has_no_unmapped_findings(customers):
    pii = [
        "ssn",
        "email",
        "card_number",
        "phone",
        "first_name",
        "last_name",
        "date_of_birth",
        "contact_alt",
    ]
    policy = parse_policy({"version": 1, "name": "full", "columns": {c: "hash" for c in pii}})
    assert unmapped_findings(customers, policy) == []
