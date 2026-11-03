"""Command-line entry point: `pii-toolkit {validate,detect,generate,apply,demo}`.

Secrets and the key manager are taken from the environment (see .env.example). The only command
that invents secrets is `demo`, which uses throwaway in-memory values so it runs with zero setup.
"""

from __future__ import annotations

import argparse
import logging
import os
import secrets as pysecrets
import shutil
import sys
from pathlib import Path

from pyspark.sql import DataFrame, SparkSession

from pii_toolkit.audit import AuditLog
from pii_toolkit.detect import detect
from pii_toolkit.engine import Secrets, apply_policy
from pii_toolkit.envelope import AwsKmsKeyManager, KeyManager, LocalKeyManager
from pii_toolkit.policy import PolicyError, load_policy
from pii_toolkit.rules import decrypt_column
from pii_toolkit.vault import REIDENTIFY_ROLE, TokenVault

log = logging.getLogger("pii_toolkit")


def _read(spark: SparkSession, path: str) -> DataFrame:
    if path.endswith(".csv"):
        return spark.read.option("header", True).csv(path)
    return spark.read.parquet(path)


def _key_manager_from_env() -> KeyManager:
    kind = os.environ.get("PII_KEY_MANAGER", "local")
    if kind == "aws":
        return AwsKmsKeyManager(os.environ["PII_KMS_KEY_ID"])
    return LocalKeyManager.from_env()


def cmd_validate(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    print(f"OK  {policy.name}  hash={policy.policy_hash}")
    for c in policy.columns:
        print(f"    {c.column:<20} {c.rule:<9} {c.options or ''}")
    return 0


def cmd_detect(args: argparse.Namespace) -> int:
    from pii_toolkit.spark import get_spark

    df = _read(get_spark(), args.input)
    findings = detect(df)
    for f in findings:
        ratio = f"  {f.match_ratio:.0%}" if f.match_ratio is not None else ""
        print(f"{f.column:<20} {f.pii_type:<14} by {f.reason}{ratio}")
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    from pii_toolkit.spark import get_spark
    from pii_toolkit.synthetic import generate_customers

    df = get_spark().createDataFrame(generate_customers(args.rows, args.seed))
    df.write.mode("overwrite").parquet(args.output)
    print(f"wrote {args.rows} synthetic customers to {args.output}")
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    from pii_toolkit.spark import get_spark

    spark = get_spark()
    policy = load_policy(args.policy)
    secrets = Secrets.from_env(policy)  # fail fast, before touching any data
    key_manager = (
        _key_manager_from_env() if any(c.rule == "encrypt" for c in policy.columns) else None
    )
    vault = (
        TokenVault(spark, args.vault, key_manager or _key_manager_from_env())
        if args.vault
        else None
    )
    result = apply_policy(
        _read(spark, args.input),
        policy,
        secrets,
        key_manager=key_manager,
        vault=vault,
        source=args.input,
        destination=args.output,
        strict=not args.non_strict,
    )
    result.df.write.mode("overwrite").parquet(args.output)
    AuditLog(args.audit).append(result.audit_record)  # only after the write succeeded
    print(f"protected {result.audit_record.row_count} rows -> {args.output}")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    from pii_toolkit.spark import get_spark
    from pii_toolkit.synthetic import generate_customers

    spark = get_spark()
    workdir = Path(args.workdir)
    # Keys are ephemeral, so anything left from a previous demo run is unreadable: start clean.
    shutil.rmtree(workdir, ignore_errors=True)
    policy = load_policy(args.policy)
    # Throwaway secrets: nothing produced by the demo can be reversed after it exits.
    secrets = Secrets(hash_salt=pysecrets.token_hex(16), token_key=pysecrets.token_bytes(32))
    key_manager = LocalKeyManager.ephemeral()
    vault = TokenVault(spark, str(workdir / "vault"), key_manager)

    raw = spark.createDataFrame(generate_customers(args.rows))
    print("\n=== BEFORE (synthetic) ===")
    raw.show(3, truncate=28, vertical=True)

    result = apply_policy(
        raw,
        policy,
        secrets,
        key_manager=key_manager,
        vault=vault,
        source="synthetic",
        destination=str(workdir / "protected"),
    )
    result.df.write.mode("overwrite").parquet(str(workdir / "protected"))
    entry = AuditLog(workdir / "audit.jsonl").append(result.audit_record)

    protected = spark.read.parquet(str(workdir / "protected")).orderBy("customer_id")
    print("=== AFTER ===")
    protected.show(3, truncate=28, vertical=True)

    if result.unmapped:
        print("=== DETECTOR: likely PII not covered by the policy ===")
        for f in result.unmapped:
            print(f"  {f.column}: {f.pii_type} (by {f.reason})")

    enc_cols = [c.column for c in policy.columns if c.rule == "encrypt"]
    if enc_cols:
        back = decrypt_column(protected.limit(1), enc_cols[0], key_manager)
        print(f"\n=== DECRYPT ROUND-TRIP ({enc_cols[0]}) ===")
        print(f"  ciphertext: {protected.first()[enc_cols[0]][:40]}...")
        print(f"  decrypted : {back.first()[enc_cols[0]]}")

    tok_cols = [c.column for c in policy.columns if c.rule == "tokenise"]
    if tok_cols:
        sample = protected.select(tok_cols[0]).limit(1)
        reid = vault.reidentify(sample, tok_cols[0], role=REIDENTIFY_ROLE)
        print(f"\n=== RE-IDENTIFY ({tok_cols[0]}, role={REIDENTIFY_ROLE}) ===")
        print(f"  {sample.first()[0]} -> {reid.first()[0]}")

    print("\n=== AUDIT RECORD ===")
    for key in ("actor", "timestamp", "policy_name", "policy_hash", "columns", "row_count"):
        print(f"  {key:<12} {entry[key]}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pii-toolkit", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("validate", help="validate a policy file")
    p.add_argument("policy")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("detect", help="list likely PII columns in a dataset")
    p.add_argument("--input", required=True)
    p.set_defaults(func=cmd_detect)

    p = sub.add_parser("generate", help="write synthetic customers to Parquet")
    p.add_argument("--output", required=True)
    p.add_argument("--rows", type=int, default=200)
    p.add_argument("--seed", type=int, default=7)
    p.set_defaults(func=cmd_generate)

    p = sub.add_parser("apply", help="apply a policy and write protected Parquet")
    p.add_argument("--policy", required=True)
    p.add_argument("--input", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--audit", required=True, help="path of the JSONL audit log")
    p.add_argument("--vault", help="token vault path (required if the policy tokenises)")
    p.add_argument(
        "--non-strict",
        action="store_true",
        help="skip policy columns missing from the input instead of failing",
    )
    p.set_defaults(func=cmd_apply)

    p = sub.add_parser("demo", help="end-to-end demo on synthetic data with throwaway keys")
    p.add_argument("--policy", default="examples/policy.yaml")
    p.add_argument("--workdir", default="out/demo")
    p.add_argument("--rows", type=int, default=200)
    p.set_defaults(func=cmd_demo)
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except PolicyError as exc:
        print(exc, file=sys.stderr)
        return 2
    except RuntimeError as exc:  # e.g. missing secrets in the environment
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
