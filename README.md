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

## Account balance floors

Synthetic wallet-style accounts can opt into an atomic minimum-balance policy.
The policy is checked inside the same serialized SQLite write transaction as the
posting, preventing competing writers from both spending the same available
balance. Accounts remain unrestricted by default so synthetic clearing accounts
can model negative balances:

```python
ledger.set_minimum_balance("demo-wallet", 0)
ledger.post("synthetic-purchase-001", [("demo-wallet", -750), ("merchant", 750)])

# This raises ValueError without recording any part of the transaction.
ledger.post("synthetic-overdraft-001", [("demo-wallet", -1), ("merchant", 1)])

# Explicitly remove a policy when unrestricted behavior is intended.
ledger.set_minimum_balance("demo-wallet", None)
```

A floor must be a signed 64-bit integer no greater than the account's current
available balance when configured. Policies persist in the ledger database.
They are a narrow posting-time invariant, not authorization, credit
underwriting, or a substitute for a production risk engine.

## Account holds

Accounts with a minimum-balance policy can reserve funds under a durable,
idempotent hold ID. Active holds reduce `available_balance` without changing the
posted ledger balance, and posting checks run under the same SQLite write lock:

```python
ledger.place_hold("synthetic-order-hold-001", "demo-wallet", 250)
assert ledger.balance("demo-wallet") == 750
assert ledger.available_balance("demo-wallet") == 500

ledger.release_hold("synthetic-order-hold-001")
assert ledger.available_balance("demo-wallet") == 750
```

Exact hold-ID replays have no effect; conflicting reuse is rejected. Released
holds remain queryable with `ledger.hold(id)` for audit and cannot be reactivated.
A minimum-balance policy cannot be removed while its account has active holds.

The full reserved amount can instead be atomically captured into an immutable
two-posting transaction. Capture deactivates the hold and debits the held account
in the same SQLite write transaction, so the reserved balance is never briefly
available to a competing writer:

```python
ledger.place_hold("synthetic-order-hold-002", "demo-wallet", 250)
ledger.capture_hold(
    "synthetic-order-hold-002", "synthetic-purchase-002", "merchant"
)
```

Exact capture replays have no effect; conflicting transaction IDs, destinations,
or attempts to capture released holds are rejected. Capture always transfers the
entire hold to one destination account. Partial capture, expiration,
authorization, external payment-rail semantics, and distributed locking remain
explicitly out of scope.

## Transaction audit queries

Operational consumers can retrieve one immutable transaction or traverse the
ledger with bounded keyset pagination. Pages are ordered by transaction ID;
postings are ordered by account for deterministic output. An account filter
selects transactions containing that account while still returning every
posting in each matched transaction:

```python
page = ledger.transactions(limit=50, account="demo-wallet")
for transaction in page.transactions:
    print(transaction.transaction_id, transaction.postings)

if page.next_cursor is not None:
    next_page = ledger.transactions(
        limit=50, account="demo-wallet", after=page.next_cursor
    )

single = ledger.transaction("synthetic-transfer-001")
```

Limits are restricted to 1–100 transactions. Cursors are transaction IDs, not
offsets, so concurrent inserts before a cursor do not shift later pages. A
multi-page traversal is not a frozen snapshot: transactions committed between
requests can appear on a later page when their ID sorts after the cursor.

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

This is an educational ledger core, not a payment system. Negative balances are
allowed for unrestricted accounts (for example, external clearing). Each
transaction uses distinct accounts and an ordered payload; reordering otherwise
equivalent postings counts as a conflict.
