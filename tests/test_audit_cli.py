import json

from pii_toolkit.audit import AuditLog, AuditRecord
from pii_toolkit.cli import main
from pii_toolkit.engine import apply_policy
from pii_toolkit.vault import TokenVault


def _record(**kw):
    base = dict(
        actor="tester", policy_name="p", policy_hash="h" * 64, columns={"ssn": "hash"}, row_count=3
    )
    return AuditRecord(**{**base, **kw})


def test_audit_is_append_only_and_chained(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append(_record(row_count=1))
    log.append(_record(row_count=2))
    assert [r["row_count"] for r in log.records()] == [1, 2]
    assert log.verify()

    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    edited = json.loads(lines[0])
    edited["row_count"] = 999
    lines[0] = json.dumps(edited, sort_keys=True, separators=(",", ":"))
    (tmp_path / "audit.jsonl").write_text("\n".join(lines) + "\n")
    assert not log.verify()


def test_engine_audit_record_contents(spark, customers, secrets, key_manager, policy, tmp_path):
    vault = TokenVault(spark, str(tmp_path / "vault"), key_manager)
    result = apply_policy(
        customers, policy, secrets, key_manager=key_manager, vault=vault, actor="unit-test"
    )
    rec = result.audit_record
    assert rec.actor == "unit-test"
    assert rec.row_count == customers.count()
    assert rec.policy_hash == policy.policy_hash
    assert rec.columns["date_of_birth"] == "encrypt"
    assert "contact_alt" in rec.unmapped_pii_columns
    serialised = json.dumps(rec.__dict__)
    assert secrets.hash_salt not in serialised  # no secrets in the audit trail


def test_cli_validate(capsys, tmp_path):
    assert main(["validate", "examples/policy.yaml"]) == 0
    assert "customer_profile_v1" in capsys.readouterr().out
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 1\nname: x\ncolumns:\n  a: {rule: shred}\n")
    assert main(["validate", str(bad)]) == 2


def test_cli_apply_end_to_end(spark, tmp_path, monkeypatch):
    import base64
    import os

    monkeypatch.setenv("PII_HASH_SALT", "cli-test-salt-not-secret")
    monkeypatch.setenv("PII_TOKEN_KEY", "cli-test-key-not-secret")
    monkeypatch.setenv("PII_LOCAL_MASTER_KEY", base64.b64encode(os.urandom(32)).decode())
    monkeypatch.setenv("PII_ACTOR", "ci")
    src, out = str(tmp_path / "in"), str(tmp_path / "out")
    assert main(["generate", "--output", src, "--rows", "25"]) == 0
    rc = main(
        [
            "apply",
            "--policy",
            "examples/policy.yaml",
            "--input",
            src,
            "--output",
            out,
            "--audit",
            str(tmp_path / "audit.jsonl"),
            "--vault",
            str(tmp_path / "vault"),
        ]
    )
    assert rc == 0
    assert spark.read.parquet(out).count() == 25
    (entry,) = AuditLog(tmp_path / "audit.jsonl").records()
    assert entry["actor"] == "ci" and entry["row_count"] == 25


def test_cli_apply_fails_without_secrets(tmp_path, monkeypatch):
    monkeypatch.delenv("PII_HASH_SALT", raising=False)
    monkeypatch.delenv("PII_TOKEN_KEY", raising=False)
    monkeypatch.setenv("PII_LOCAL_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    rc = main(
        [
            "apply",
            "--policy",
            "examples/policy.yaml",
            "--input",
            "missing.parquet",
            "--output",
            str(tmp_path / "o"),
            "--audit",
            str(tmp_path / "a.jsonl"),
        ]
    )
    assert rc == 1
