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

Run: `python3 -m unittest discover -s tests -v` (Python standard library only).

Tests run locally and in GitHub Actions on Python 3.11 and 3.14.

This is an educational ledger core, not a payment system. Negative balances are currently allowed (e.g. external clearing); account-level overdraft policies, cross-system reconciliation, signatures and audit exports are future work. Each transaction uses distinct accounts and an ordered payload; reordering otherwise equivalent postings counts as a conflict.
