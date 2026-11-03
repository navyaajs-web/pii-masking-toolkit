"""Append-only, hash-chained audit log (JSON Lines).

Each record states who ran which policy (by hash), when, over which columns and how many rows.
Records are chained: each one stores the SHA-256 of the previous line, so editing or deleting
any earlier record breaks `verify()`. That does not make tampering impossible (someone with write
access can rebuild the chain), but it makes silent edits detectable, and in production the file
would sit on object storage with object lock / WORM retention.

The log deliberately never contains data values, salts or keys.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

GENESIS = "0" * 64


@dataclass(frozen=True)
class AuditRecord:
    actor: str
    policy_name: str
    policy_hash: str
    columns: dict[str, str]  # column -> rule
    row_count: int
    source: str = ""
    destination: str = ""
    unmapped_pii_columns: list[str] = field(default_factory=list)
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


def current_actor() -> str:
    return os.environ.get("PII_ACTOR") or getpass.getuser()


def _line_hash(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = ""
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = line.rstrip("\n")
        return _line_hash(last) if last else GENESIS

    def append(self, record: AuditRecord) -> dict:
        """Append one record. The file is only ever opened in append mode."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        entry = {**asdict(record), "prev_hash": self._last_hash()}
        line = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        return entry

    def records(self) -> list[dict]:
        if not self.path.exists():
            return []
        with self.path.open(encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def verify(self) -> bool:
        """True if every record's prev_hash matches the line before it."""
        expected = GENESIS
        if not self.path.exists():
            return True
        with self.path.open(encoding="utf-8") as fh:
            for raw in fh:
                line = raw.rstrip("\n")
                if not line:
                    continue
                if json.loads(line).get("prev_hash") != expected:
                    return False
                expected = _line_hash(line)
        return True
