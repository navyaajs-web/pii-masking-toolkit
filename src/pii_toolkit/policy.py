"""Policy loading and validation.

A policy is the contract between the privacy team and the pipeline: it says, per column,
which control applies. We validate it eagerly and report *every* problem at once, because a
policy is usually edited by someone who is not running Spark locally, and a one-error-at-a-time
loop through CI is painful.

The policy hash is computed over a canonical JSON form so that reordering keys or changing
YAML formatting does not change the hash, but changing any rule does. The hash is what the
audit log records, which lets an auditor tie an output dataset to the exact policy applied.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

SUPPORTED_VERSIONS = {1}
RULES = {"hash", "tokenise", "mask", "nullify", "encrypt"}

# Options each rule accepts, with their defaults. Unknown options are rejected so that a typo
# such as `keep_lst: 4` fails loudly instead of silently falling back to the default.
RULE_OPTIONS: dict[str, dict[str, Any]] = {
    "hash": {},
    "tokenise": {"vault": True},
    "mask": {"keep_last": 4, "mask_char": "*"},
    "nullify": {},
    "encrypt": {},
}


class PolicyError(ValueError):
    """Raised when a policy is invalid. `errors` holds every problem found."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__("Invalid policy:\n  - " + "\n  - ".join(errors))


@dataclass(frozen=True)
class ColumnRule:
    column: str
    rule: str
    options: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Policy:
    name: str
    version: int
    hash_salt_env: str
    token_key_env: str
    columns: tuple[ColumnRule, ...]
    raw: dict[str, Any] = field(repr=False, compare=False, default_factory=dict)

    @property
    def policy_hash(self) -> str:
        return policy_hash(self.raw)

    def rule_for(self, column: str) -> ColumnRule | None:
        return next((c for c in self.columns if c.column == column), None)

    @property
    def column_names(self) -> list[str]:
        return [c.column for c in self.columns]


def policy_hash(raw: dict[str, Any]) -> str:
    """SHA-256 of the policy in canonical JSON (sorted keys, no whitespace)."""
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_policy(path: str | Path) -> Policy:
    with open(path, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    return parse_policy(raw)


def parse_policy(raw: Any) -> Policy:
    """Validate a decoded YAML document and build a Policy, collecting all errors."""
    errors: list[str] = []
    if not isinstance(raw, dict):
        raise PolicyError(["policy must be a mapping at the top level"])

    for key in sorted(set(raw) - {"version", "name", "secrets", "columns"}):
        errors.append(f"unknown top-level key '{key}'")

    version = raw.get("version")
    if version not in SUPPORTED_VERSIONS:
        errors.append(f"version must be one of {sorted(SUPPORTED_VERSIONS)}, got {version!r}")

    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        errors.append("name is required and must be a non-empty string")

    secrets = raw.get("secrets") or {}
    if not isinstance(secrets, dict):
        errors.append("secrets must be a mapping of *_env keys to environment variable names")
        secrets = {}
    hash_salt_env = secrets.get("hash_salt_env", "PII_HASH_SALT")
    token_key_env = secrets.get("token_key_env", "PII_TOKEN_KEY")
    for label, value in (("hash_salt_env", hash_salt_env), ("token_key_env", token_key_env)):
        if not isinstance(value, str) or not value.isidentifier():
            errors.append(f"secrets.{label} must name an environment variable, got {value!r}")
    # Secrets live in the environment, never in the policy file. Catch the obvious mistake.
    for key in sorted(set(secrets) - {"hash_salt_env", "token_key_env"}):
        errors.append(f"secrets.{key} is not allowed; reference env vars via *_env keys only")

    columns_raw = raw.get("columns")
    columns: list[ColumnRule] = []
    if not isinstance(columns_raw, dict) or not columns_raw:
        errors.append("columns is required and must map column names to rules")
    else:
        for column, spec in columns_raw.items():
            rule, col_errors = _parse_column(str(column), spec)
            errors.extend(col_errors)
            if rule:
                columns.append(rule)

    if errors:
        raise PolicyError(errors)
    return Policy(
        name=name,
        version=version,
        hash_salt_env=hash_salt_env,
        token_key_env=token_key_env,
        columns=tuple(columns),
        raw=raw,
    )


def _parse_column(column: str, spec: Any) -> tuple[ColumnRule | None, list[str]]:
    if isinstance(spec, str):  # shorthand: `email: hash`
        spec = {"rule": spec}
    if not isinstance(spec, dict):
        return None, [f"columns.{column}: expected a rule name or mapping, got {spec!r}"]

    rule = spec.get("rule")
    if rule not in RULES:
        return None, [f"columns.{column}: unknown rule {rule!r}; expected one of {sorted(RULES)}"]

    allowed = RULE_OPTIONS[rule]
    options = {k: v for k, v in spec.items() if k != "rule"}
    errors = [
        f"columns.{column}: option '{k}' is not valid for rule '{rule}'"
        for k in sorted(set(options) - set(allowed))
    ]
    merged = {**allowed, **{k: v for k, v in options.items() if k in allowed}}

    if rule == "mask":
        keep = merged["keep_last"]
        if not isinstance(keep, int) or isinstance(keep, bool) or not 0 <= keep <= 8:
            errors.append(f"columns.{column}: keep_last must be an integer 0-8, got {keep!r}")
        mask_char = merged["mask_char"]
        if not isinstance(mask_char, str) or len(mask_char) != 1:
            errors.append(f"columns.{column}: mask_char must be a single character")
    if rule == "tokenise" and not isinstance(merged["vault"], bool):
        errors.append(f"columns.{column}: vault must be true or false")

    return ColumnRule(column=column, rule=rule, options=merged), errors
