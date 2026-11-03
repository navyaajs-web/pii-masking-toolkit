# Design notes

## Choosing a rule

| Rule | Reversible? | Joinable? | Use when |
|---|---|---|---|
| `hash` | No | Yes (same salt) | The value is a key nobody needs back, such as a national ID used only to de-duplicate. |
| `tokenise` | Yes, through the vault and only for the re-identification role | Yes (same HMAC key) | Analysts join on it, and operations sometimes need the original, for example an email for a support case. |
| `mask` | No | No | People need to recognise the value, such as the last 4 digits of a card on a statement screen. |
| `nullify` | No | No | Nobody downstream needs the column, but the schema must stay stable. |
| `encrypt` | Yes, for key holders | No (random nonce) | A small set of services needs the real value, such as date of birth for an eligibility check. |

## Why hashing is salted and tokenising uses HMAC
A plain SHA-256 of a 9-digit identifier can be brute-forced in seconds. The salt stops
precomputed tables. HMAC goes further: without the key, an attacker cannot even test a guess.
That is why tokens, which are long-lived and widely shared, use HMAC.

## Envelope encryption
```
KeyManager (KMS / local)            per batch
  master key  --wraps-->  data key (AES-256)  --encrypts-->  values (AES-GCM, nonce per value)
                               |
                               +--> wrapped copy stored in `_pii_dek` next to the rows
```
- **One data key per batch.** Each call to `apply_policy` asks the key manager for a new data
  key. Data-key rotation is therefore automatic. Master-key rotation is supported by
  `LocalKeyManager`, which can hold several master keys and use one as the active key, and by
  KMS natively.
- **Associated data.** The column name is the AES-GCM associated data. A ciphertext copied into
  another column fails to decrypt.
- **Mixed batches.** `decrypt_column` unwraps every distinct `_pii_dek` once on the driver, so a
  union of several batches still decrypts.

## Token vault
- The vault stores `(column_name, token, value_ct, _pii_dek, created_at)`.
- Values are encrypted with their own per-write data key. A leaked copy of the vault files is
  therefore not a leak of PII.
- Writes are insert-only: an existing token is never rewritten.
- The `reidentify(..., role=...)` check makes intent explicit in code. Real enforcement is the
  storage ACL on the vault path.

## Detector
There are two signals: column-name rules and value patterns (email, SSN-style IDs, Luhn-valid
card numbers, phone numbers, IBAN and IPv4) on a sample of rows. A value rule needs at least 60%
of the sampled non-empty values to match before it reports a finding. Findings on columns that
the policy does not map are logged as warnings and recorded in the audit record as
`unmapped_pii_columns`.

## Audit log
- The log is JSON Lines and the file is only ever opened in append mode.
- Each record holds the SHA-256 of the previous line, and `AuditLog.verify()` detects edits and
  deletions.
- The engine returns the record and the caller appends it after the output is written. The log
  never records a run that did not land.
- Records never contain values, salts or keys.

## Known trade-offs
- The salt is a Spark literal, so it appears in the query plan (`df.explain()`). Do not log
  plans of protected jobs at DEBUG level in shared log stores.
- The HMAC key and the data key reach executors inside Python UDF closures. This is the standard
  trade-off on Spark. Keep data keys per batch and short-lived.
- Python UDFs (HMAC, AES-GCM) are slower than JVM built-ins. On large tables, apply
  `tokenise`/`encrypt` only to the columns that need them.
