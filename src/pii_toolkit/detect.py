"""Heuristic PII detection: flag columns that look like PII but are not covered by the policy.

The detector is a safety net, not a classifier. Its job is to catch the common failure mode in
which an upstream team adds a column (say `contact_alt`) full of email addresses and nobody
updates the policy. It uses two cheap signals:

  1. Column-name rules (e.g. `ssn`, `dob`, `*_email`).
  2. Value patterns on a sample of rows, with a minimum match ratio so a single stray
     email in a free-text column does not trigger a finding.

False positives are acceptable (a warning costs a minute); false negatives are the real risk,
so the patterns lean permissive.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from pyspark.sql import DataFrame
from pyspark.sql.types import StringType

from pii_toolkit.policy import Policy

log = logging.getLogger(__name__)

NAME_RULES: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"e_?mail"),
    "phone": re.compile(r"phone|mobile|msisdn|tel(ephone)?$"),
    "national_id": re.compile(r"(^|_)(ssn|nino|national_id|tax_id|passport)(_|$)"),
    "date_of_birth": re.compile(r"(^|_)(dob|birth_?date|date_of_birth)(_|$)"),
    "card_number": re.compile(r"(^|_)(card_?(number|no|num)|pan)(_|$)"),
    "bank_account": re.compile(r"(^|_)(iban|account_?(number|no|num)|sort_code)(_|$)"),
    "person_name": re.compile(r"(^|_)(first|last|full|given|family|sur)_?name(_|$)"),
    "address": re.compile(r"(^|_)(address|street|postcode|post_code|zip(_?code)?)(_|\d|$)"),
    "ip_address": re.compile(r"(^|_)ip(_?addr(ess)?)?(_|$)"),
}


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


_EMAIL = re.compile(r"^[\w.+-]+@[\w-]+(\.[\w-]+)+$")
_SSN = re.compile(r"^\d{3}-\d{2}-\d{4}$")
_PHONE = re.compile(r"^\+?[\d ()-]{10,17}$")
_IBAN = re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$")
_IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def _is_card(value: str) -> bool:
    digits = re.sub(r"[ -]", "", value)
    return digits.isdigit() and 13 <= len(digits) <= 19 and _luhn_ok(digits)


VALUE_RULES: dict[str, Callable[[str], bool]] = {
    "email": lambda v: bool(_EMAIL.match(v)),
    "national_id": lambda v: bool(_SSN.match(v)),
    "card_number": _is_card,
    "phone": lambda v: bool(_PHONE.match(v)) and sum(c.isdigit() for c in v) >= 10,
    "bank_account": lambda v: bool(_IBAN.match(v.replace(" ", ""))),
    "ip_address": lambda v: bool(_IPV4.match(v)),
}


@dataclass(frozen=True)
class Finding:
    column: str
    pii_type: str
    reason: str  # "name" or "values"
    match_ratio: float | None = None


def detect(df: DataFrame, sample_rows: int = 500, min_ratio: float = 0.6) -> list[Finding]:
    """Return likely-PII findings for every column in `df`."""
    findings: list[Finding] = []
    for column in df.columns:
        lowered = column.lower()
        for pii_type, pattern in NAME_RULES.items():
            if pattern.search(lowered):
                findings.append(Finding(column, pii_type, "name"))
                break

    string_cols = [f.name for f in df.schema.fields if isinstance(f.dataType, StringType)]
    if string_cols:
        sample = df.select(string_cols).limit(sample_rows).collect()
        for column in string_cols:
            values = [str(r[column]).strip() for r in sample if r[column] not in (None, "")]
            findings.extend(_value_findings(column, values, min_ratio))
    return findings


def _value_findings(column: str, values: Iterable[str], min_ratio: float) -> list[Finding]:
    values = list(values)
    if not values:
        return []
    results = []
    for pii_type, check in VALUE_RULES.items():
        ratio = sum(1 for v in values if check(v)) / len(values)
        if ratio >= min_ratio:
            results.append(Finding(column, pii_type, "values", round(ratio, 3)))
    return results


def unmapped_findings(
    df: DataFrame, policy: Policy, sample_rows: int = 500, min_ratio: float = 0.6
) -> list[Finding]:
    """Findings for columns the policy does not mention, logged as warnings."""
    mapped = set(policy.column_names)
    found = detect(df, sample_rows=sample_rows, min_ratio=min_ratio)
    unmapped = [f for f in found if f.column not in mapped]
    for f in unmapped:
        detail = f" ({f.match_ratio:.0%} of sampled values)" if f.match_ratio is not None else ""
        log.warning(
            "Column '%s' looks like %s by %s%s but is not in policy '%s'",
            f.column,
            f.pii_type,
            f.reason,
            detail,
            policy.name,
        )
    return unmapped
