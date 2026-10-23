# Synthetic Ledger Lab

An independent software-engineering portfolio project exploring double-entry transaction processing and reconciliation using *synthetic* accounts. Not affiliated with Wealthsimple. Not financial or investment advice; no real money, customer data or banking integration.

## First slice

`Ledger.post(tx_id, entries)` accepts an atomic, zero-sum batch of integer minor-unit postings. An exact transaction-ID replay has no effect; the same ID with a different payload is rejected. Unbalanced, duplicate-account, zero or non-integer postings are rejected before storage. SQLite write transactions serialize competing writers; account balances are derived from persisted entries.

```python
from synthetic_ledger_lab.ledger import Ledger

ledger = Ledger("demo.sqlite3")
ledger.post("synthetic-funding-001", [("external-clearing", -1000), ("demo-wallet", 1000)])
ledger.post("synthetic-transfer-001", [("demo-wallet", -250), ("merchant", 250)])
assert ledger.balance("demo-wallet") == 750
```

Run: `python3 -m unittest discover -s tests -v` (Python standard library only).

This is an educational ledger core, not a payment system. Negative balances are currently allowed (e.g. external clearing); account-level overdraft policies, cross-system reconciliation, signatures, audit exports, CI and SQLite aggregate overflow protections are future work. Each transaction uses distinct accounts and an ordered payload; reordering otherwise equivalent postings counts as a conflict.
