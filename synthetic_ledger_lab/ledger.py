"""Synthetic double-entry ledger with atomic, idempotent postings."""

import json
import sqlite3
from pathlib import Path


class Ledger:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        with sqlite3.connect(self.path) as db:
            db.execute("""CREATE TABLE IF NOT EXISTS transactions (
                tx_id TEXT PRIMARY KEY, payload TEXT NOT NULL
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS postings (
                tx_id TEXT NOT NULL REFERENCES transactions(tx_id),
                account TEXT NOT NULL,
                amount INTEGER NOT NULL CHECK(amount != 0),
                PRIMARY KEY (tx_id, account)
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS postings_account ON postings(account)")

    def post(self, tx_id: str, entries: list[tuple[str, int]]) -> bool:
        """Post a zero-sum batch in integer minor units; False on exact replay."""
        if not isinstance(tx_id, str) or not tx_id.strip():
            raise ValueError("tx_id must be a non-empty string")
        if not isinstance(entries, (list, tuple)) or len(entries) < 2:
            raise ValueError("at least two postings required")
        normalized = []
        for entry in entries:
            if not isinstance(entry, (list, tuple)) or len(entry) != 2:
                raise ValueError("each posting requires account and amount")
            account, amount = entry
            if not isinstance(account, str) or not account.strip():
                raise ValueError("account must be a non-empty string")
            if type(amount) is not int or not -(2**63) <= amount < 2**63:
                raise ValueError("amount must be a non-zero signed 64-bit integer")
            if amount == 0:
                raise ValueError("zero postings are not allowed")
            normalized.append((account, amount))
        if len({account for account, _ in normalized}) != len(normalized):
            raise ValueError("duplicate accounts in transaction")
        if sum(amount for _, amount in normalized) != 0:
            raise ValueError("postings must balance to zero")
        payload = json.dumps(normalized, separators=(",", ":"))

        with sqlite3.connect(self.path, timeout=10) as db:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute(
                "SELECT payload FROM transactions WHERE tx_id = ?", (tx_id,)
            ).fetchone()
            if prior is not None:
                if prior[0] != payload:
                    raise ValueError("transaction ID conflict")
                return False
            db.execute(
                "INSERT INTO transactions (tx_id, payload) VALUES (?, ?)",
                (tx_id, payload),
            )
            db.executemany(
                "INSERT INTO postings (tx_id, account, amount) VALUES (?, ?, ?)",
                [(tx_id, account, amount) for account, amount in normalized],
            )
            return True

    def balance(self, account: str) -> int:
        """Return an account balance without SQLite aggregate overflow.

        Individual postings fit SQLite's signed 64-bit INTEGER type, but an
        account's running total may not. Sum in Python so valid histories stay
        readable after crossing that boundary.
        """
        with sqlite3.connect(self.path) as db:
            amounts = db.execute(
                "SELECT amount FROM postings WHERE account = ?",
                (account,),
            )
            return sum(amount for (amount,) in amounts)
