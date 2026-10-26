# Synthetic Ledger Lab

An independent software-engineering portfolio project exploring double-entry transaction processing and reconciliation using *synthetic* accounts. Not affiliated with Wealthsimple. Not financial or investment advice; no real money, customer data or banking integration.

## First slice

`Ledger.post(tx_id, entries)` accepts an atomic, zero-sum batch of signed 64-bit integer minor-unit postings. An exact transaction-ID replay has no effect; the same ID with a different payload is rejected. Unbalanced, duplicate-account, zero or non-integer postings are rejected before storage. SQLite write transactions serialize competing writers; account balances are derived from persisted entries and summed in Python so an account total can safely exceed SQLite's signed-integer range.

```python
from synthetic_ledger_lab.ledger import Ledger

ledger = Ledger("demo.sqlite3")
ledger.post("synthetic-funding-001", [("external-clearing", -1000), ("demo-wallet", 1000)])
ledger.post("synthetic-transfer-001", [("demo-wallet", -250), ("merchant", 250)])
assert ledger.balance("demo-wallet") == 750
```

## Reconciliation export

`Ledger.export_reconciliation_csv(path)` writes an atomic, deterministic CSV
snapshot ordered by transaction and account. It returns the posting row count
and SHA-256 digest so a downstream synthetic reconciliation job can verify the
artifact after transfer:

```python
snapshot = ledger.export_reconciliation_csv("reconciliation.csv")
print(snapshot.row_count, snapshot.sha256)

# At the receiving side, verify transfer integrity and compare without mutation.
report = ledger.reconcile_csv(
    "reconciliation.csv", expected_sha256=snapshot.sha256
)
assert report.matched
```

For authenticity as well as transfer integrity, the exporter can produce a
detached HMAC-SHA256 tag over the exact CSV bytes. The receiver verifies the tag
before parsing or comparing any rows:

```python
shared_key = b"replace-with-at-least-32-secret-bytes"
snapshot = ledger.export_reconciliation_csv(
    "signed-reconciliation.csv", signing_key=shared_key
)
report = ledger.reconcile_csv(
    "signed-reconciliation.csv",
    expected_hmac_sha256=snapshot.hmac_sha256,
    signing_key=shared_key,
)
assert report.matched
```

CSV fields use standard quoting, amounts remain integer minor units, and the
export refuses to overwrite the SQLite ledger itself. Unsigned exports are
portable posting-level artifacts, not proofs of authenticity. Signed exports
use a shared secret (minimum 32 bytes) and therefore provide integrity and
authenticity, but not public-key signatures or non-repudiation; callers are
responsible for secret storage, rotation and out-of-band tag transfer.
Imports are strictly validated (UTF-8, exact header, canonical signed 64-bit
minor-unit amounts, unique transaction/account pairs) and limited to 10 MiB.
Mismatch reports deterministically identify changed, missing and unexpected
postings. Reconciliation reads never post transactions or mutate balances.

Run: `python3 -m unittest discover -s tests -v` (Python standard library only).

Tests run locally and in GitHub Actions on Python 3.11 and 3.14.

This is an educational ledger core, not a payment system. Negative balances are currently allowed (e.g. external clearing); account-level overdraft policies are future work. Each transaction uses distinct accounts and an ordered payload; reordering otherwise equivalent postings counts as a conflict.
