# pii-masking-toolkit

[![CI](https://github.com/navyaajs-web/pii-masking-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/navyaajs-web/pii-masking-toolkit/actions/workflows/ci.yml)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)

A small PySpark library and CLI for applying column-level privacy controls from a YAML policy:
- Hashing
- Deterministic tokenisation, with a token vault
- Partial masking
- Nulling
- Envelope encryption

Every run writes an append-only audit record.

## Problem
Regulated datasets, such as banking customers and card transactions, need the same controls applied the same way in every pipeline. Ad-hoc `regexp_replace` calls scattered across jobs are hard to audit.

## Architecture
```mermaid
flowchart LR
  P[policy.yaml<br/>column → rule] --> E[Policy engine]
  IN[(Input DataFrame)] --> D[PII detector<br/>regex + column-name rules]
  D -->|unmapped PII warning| E
  E --> H[hash: SHA-256 + salt]
  E --> T[tokenise: HMAC → vault]
  E --> M[mask: keep last 4]
  E --> X[encrypt: envelope<br/>data key per batch]
  X --> KM[KeyManager interface<br/>LocalKeyManager / AwsKmsKeyManager]
  H & T & M & X --> OUT[(Protected output)]
  E --> A[(Audit log: who, when,<br/>policy hash, columns, row count)]
```

## Run it in three commands
```bash
make setup     # venv + pyspark, cryptography, pyyaml
make demo      # generates synthetic customers, applies examples/policy.yaml, prints before/after
make test
```

## What is inside
| Path | What it does |
|---|---|
| `src/pii_toolkit/policy.py` | YAML schema and validation; a policy hash is stored in the audit |
| `src/pii_toolkit/rules.py` | Spark column expressions for each rule |
| `src/pii_toolkit/envelope.py` | AES-GCM data keys wrapped by a `KeyManager`; the AWS KMS adapter is documented, not called in CI |
| `src/pii_toolkit/vault.py` | Token vault (Parquet by default; the format is configurable, e.g. Delta, but only Parquet is tested) with values encrypted at rest and re-identification restricted to a separate role |
| `src/pii_toolkit/detect.py` | Flags likely PII columns not covered by the policy |
| `src/pii_toolkit/audit.py` | Append-only audit records, hash-chained so edits are detectable |
| `src/pii_toolkit/cli.py` | `pii-toolkit validate / detect / generate / apply / demo` |
| `docs/design.md` | Rule choice, key handling, vault and audit design, known trade-offs |
| `tests/` | Determinism, irreversibility of hash, decrypt round-trip, policy validation, detector |

## What this proves
- I can turn privacy requirements into a tested, reusable library.
- I can implement envelope encryption correctly.
- I can make the controls auditable.

## Limitations
- This is a pattern demonstration, not a certified compliance product.
- Key rotation is shown for data keys only.
- The local key manager is for demos.

## About the author
Built by Navya Sindhu, Senior Data Engineer. [LinkedIn](https://www.linkedin.com/in/navyaajs/). This is a personal project with synthetic data. It contains no employer or client security designs or code.
