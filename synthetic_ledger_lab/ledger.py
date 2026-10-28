"""Synthetic double-entry ledger with atomic, idempotent postings."""

import csv
import hashlib
import hmac
import io
import json
import os
import re
import sqlite3
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ReconciliationExport:
    """Metadata for a deterministic reconciliation artifact."""

    path: Path
    row_count: int
    sha256: str
    hmac_sha256: str | None = None


@dataclass(frozen=True)
class ReconciliationDifference:
    """One posting that differs between the ledger and an imported snapshot."""

    transaction_id: str
    account: str
    ledger_amount: int | None
    imported_amount: int | None


@dataclass(frozen=True)
class ReconciliationReport:
    """Result of comparing an imported artifact with the current ledger."""

    path: Path
    row_count: int
    sha256: str
    matched: bool
    differences: tuple[ReconciliationDifference, ...]


@dataclass(frozen=True)
class Posting:
    """One immutable posting returned by the audit query API."""

    account: str
    amount: int


@dataclass(frozen=True)
class LedgerTransaction:
    """One persisted transaction and its deterministically ordered postings."""

    transaction_id: str
    postings: tuple[Posting, ...]


@dataclass(frozen=True)
class TransactionPage:
    """A keyset-paginated page of immutable ledger transactions."""

    transactions: tuple[LedgerTransaction, ...]
    next_cursor: str | None


_RECONCILIATION_HEADER = ("transaction_id", "account", "amount_minor")
_CANONICAL_INTEGER = re.compile(r"-?[1-9][0-9]*\Z")
_MAX_RECONCILIATION_BYTES = 10 * 1024 * 1024


def _validate_signing_key(signing_key: bytes) -> None:
    if not isinstance(signing_key, bytes) or len(signing_key) < 32:
        raise ValueError("signing_key must contain at least 32 bytes")


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
            db.execute("""CREATE TABLE IF NOT EXISTS account_policies (
                account TEXT PRIMARY KEY,
                minimum_balance INTEGER NOT NULL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS postings_account ON postings(account)")

    @staticmethod
    def _validate_account(account: str) -> None:
        if not isinstance(account, str) or not account.strip():
            raise ValueError("account must be a non-empty string")

    @staticmethod
    def _balance_in_connection(db: sqlite3.Connection, account: str) -> int:
        amounts = db.execute(
            "SELECT amount FROM postings WHERE account = ?",
            (account,),
        )
        return sum(amount for (amount,) in amounts)

    def set_minimum_balance(self, account: str, minimum_balance: int | None) -> None:
        """Atomically set or remove an account's posting-time balance floor.

        A new floor cannot exceed the account's current balance. Passing ``None``
        removes the policy. Policy checks and postings share SQLite's write lock,
        so competing writers cannot both spend the same available balance.
        """
        self._validate_account(account)
        if minimum_balance is not None and (
            type(minimum_balance) is not int
            or not -(2**63) <= minimum_balance < 2**63
        ):
            raise ValueError("minimum_balance must be a signed 64-bit integer or None")

        with sqlite3.connect(self.path, timeout=10) as db:
            db.execute("BEGIN IMMEDIATE")
            if minimum_balance is None:
                db.execute("DELETE FROM account_policies WHERE account = ?", (account,))
                return
            if self._balance_in_connection(db, account) < minimum_balance:
                raise ValueError("minimum balance cannot exceed current balance")
            db.execute(
                """INSERT INTO account_policies (account, minimum_balance)
                   VALUES (?, ?)
                   ON CONFLICT(account) DO UPDATE
                   SET minimum_balance = excluded.minimum_balance""",
                (account, minimum_balance),
            )

    def minimum_balance(self, account: str) -> int | None:
        """Return an account's configured balance floor, or ``None`` if unrestricted."""
        self._validate_account(account)
        with sqlite3.connect(self.path) as db:
            row = db.execute(
                "SELECT minimum_balance FROM account_policies WHERE account = ?",
                (account,),
            ).fetchone()
        return None if row is None else row[0]

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
            self._validate_account(account)
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
            for account, amount in normalized:
                policy = db.execute(
                    "SELECT minimum_balance FROM account_policies WHERE account = ?",
                    (account,),
                ).fetchone()
                if policy is not None:
                    resulting_balance = self._balance_in_connection(db, account) + amount
                    if resulting_balance < policy[0]:
                        raise ValueError(
                            f"minimum balance policy violated for account {account!r}"
                        )
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
            return self._balance_in_connection(db, account)

    def transaction(self, transaction_id: str) -> LedgerTransaction | None:
        """Return one transaction for audit, or ``None`` when it does not exist."""
        if not isinstance(transaction_id, str) or not transaction_id.strip():
            raise ValueError("transaction_id must be a non-empty string")
        with sqlite3.connect(self.path) as db:
            exists = db.execute(
                "SELECT 1 FROM transactions WHERE tx_id = ?", (transaction_id,)
            ).fetchone()
            if exists is None:
                return None
            rows = db.execute(
                """SELECT account, amount FROM postings
                   WHERE tx_id = ? ORDER BY account""",
                (transaction_id,),
            ).fetchall()
        return LedgerTransaction(
            transaction_id=transaction_id,
            postings=tuple(Posting(account, amount) for account, amount in rows),
        )

    def transactions(
        self,
        *,
        limit: int = 50,
        after: str | None = None,
        account: str | None = None,
    ) -> TransactionPage:
        """Return a deterministic keyset page for operational audit workflows.

        Transactions are ordered by their ID and postings by account. ``after``
        is the last transaction ID from a prior page. Supplying ``account``
        returns complete transactions that contain a posting for that account,
        rather than returning partial posting sets.
        """
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("limit must be an integer from 1 to 100")
        if after is not None and (not isinstance(after, str) or not after.strip()):
            raise ValueError("after must be a non-empty string or None")
        if account is not None:
            self._validate_account(account)

        clauses: list[str] = []
        parameters: list[str | int] = []
        if after is not None:
            clauses.append("t.tx_id > ?")
            parameters.append(after)
        if account is not None:
            clauses.append(
                "EXISTS (SELECT 1 FROM postings f "
                "WHERE f.tx_id = t.tx_id AND f.account = ?)"
            )
            parameters.append(account)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        with sqlite3.connect(self.path) as db:
            transaction_ids = [
                row[0]
                for row in db.execute(
                    f"""SELECT t.tx_id FROM transactions t {where}
                        ORDER BY t.tx_id LIMIT ?""",
                    (*parameters, limit + 1),
                )
            ]
            page_ids = transaction_ids[:limit]
            postings_by_transaction: dict[str, list[Posting]] = {
                transaction_id: [] for transaction_id in page_ids
            }
            if page_ids:
                placeholders = ",".join("?" for _ in page_ids)
                for transaction_id, posting_account, amount in db.execute(
                    f"""SELECT tx_id, account, amount FROM postings
                        WHERE tx_id IN ({placeholders}) ORDER BY tx_id, account""",
                    page_ids,
                ):
                    postings_by_transaction[transaction_id].append(
                        Posting(posting_account, amount)
                    )

        transactions = tuple(
            LedgerTransaction(transaction_id, tuple(postings_by_transaction[transaction_id]))
            for transaction_id in page_ids
        )
        return TransactionPage(
            transactions=transactions,
            next_cursor=page_ids[-1] if len(transaction_ids) > limit else None,
        )

    def export_reconciliation_csv(
        self,
        destination: str | Path,
        *,
        signing_key: bytes | None = None,
    ) -> ReconciliationExport:
        """Atomically write a deterministic posting-level CSV snapshot.

        Rows are sorted independently of insertion order. The returned SHA-256
        digest lets a downstream reconciliation process verify that the file it
        received is byte-for-byte identical to the exported artifact. Supplying
        a secret signing key also returns an HMAC-SHA256 authenticity tag.
        """
        destination = Path(destination)
        if destination.resolve() == self.path.resolve():
            raise ValueError("export destination must not overwrite the ledger")
        if signing_key is not None:
            _validate_signing_key(signing_key)

        with sqlite3.connect(self.path) as db:
            rows = db.execute(
                """SELECT tx_id, account, amount
                   FROM postings
                   ORDER BY tx_id, account"""
            ).fetchall()

        text = io.StringIO(newline="")
        writer = csv.writer(text, lineterminator="\n")
        writer.writerow(_RECONCILIATION_HEADER)
        writer.writerows(rows)
        payload = text.getvalue().encode("utf-8")

        temporary_path: Path | None = None
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                dir=destination.parent,
                prefix=f".{destination.name}.",
                suffix=".tmp",
            )
            temporary_path = Path(temporary_name)
            with os.fdopen(descriptor, "wb") as export_file:
                export_file.write(payload)
                export_file.flush()
                os.fsync(export_file.fileno())
            os.replace(temporary_path, destination)
            temporary_path = None
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

        return ReconciliationExport(
            path=destination,
            row_count=len(rows),
            sha256=hashlib.sha256(payload).hexdigest(),
            hmac_sha256=(
                hmac.new(signing_key, payload, hashlib.sha256).hexdigest()
                if signing_key is not None
                else None
            ),
        )

    def reconcile_csv(
        self,
        source: str | Path,
        *,
        expected_sha256: str | None = None,
        expected_hmac_sha256: str | None = None,
        signing_key: bytes | None = None,
    ) -> ReconciliationReport:
        """Validate and compare a reconciliation CSV without mutating the ledger.

        When supplied, ``expected_sha256`` is checked before parsing so transfer
        corruption is distinguishable from a legitimate ledger discrepancy.
        HMAC verification requires both ``expected_hmac_sha256`` and the shared
        ``signing_key`` and also occurs before parsing. Differences are ordered
        by transaction ID and account for stable reports.
        """
        source = Path(source)
        with source.open("rb") as reconciliation_file:
            payload = reconciliation_file.read(_MAX_RECONCILIATION_BYTES + 1)
        if len(payload) > _MAX_RECONCILIATION_BYTES:
            raise ValueError("reconciliation CSV exceeds 10 MiB limit")
        digest = hashlib.sha256(payload).hexdigest()
        if expected_sha256 is not None:
            if not isinstance(expected_sha256, str) or not re.fullmatch(
                r"[0-9a-fA-F]{64}", expected_sha256
            ):
                raise ValueError("expected_sha256 must be a 64-character hex digest")
            if not hmac.compare_digest(digest, expected_sha256.lower()):
                raise ValueError("reconciliation CSV checksum mismatch")
        if (expected_hmac_sha256 is None) != (signing_key is None):
            raise ValueError("expected_hmac_sha256 and signing_key must be supplied together")
        if signing_key is not None:
            _validate_signing_key(signing_key)
            if not isinstance(expected_hmac_sha256, str) or not re.fullmatch(
                r"[0-9a-fA-F]{64}", expected_hmac_sha256
            ):
                raise ValueError("expected_hmac_sha256 must be a 64-character hex tag")
            actual_hmac = hmac.new(signing_key, payload, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(actual_hmac, expected_hmac_sha256.lower()):
                raise ValueError("reconciliation CSV authentication failed")

        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("reconciliation CSV must be UTF-8") from error

        try:
            reader = csv.reader(io.StringIO(text, newline=""), strict=True)
            header = next(reader, None)
            if header != list(_RECONCILIATION_HEADER):
                raise ValueError("invalid reconciliation CSV header")

            imported: dict[tuple[str, str], int] = {}
            for line_number, row in enumerate(reader, start=2):
                if len(row) != 3:
                    raise ValueError(f"line {line_number} must contain exactly 3 fields")
                transaction_id, account, raw_amount = row
                if not transaction_id.strip() or not account.strip():
                    raise ValueError(
                        f"line {line_number} transaction and account must be non-empty"
                    )
                if _CANONICAL_INTEGER.fullmatch(raw_amount) is None:
                    raise ValueError(f"line {line_number} has an invalid amount")
                amount = int(raw_amount)
                if not -(2**63) <= amount < 2**63 or amount == 0:
                    raise ValueError(
                        f"line {line_number} amount must be a non-zero signed 64-bit integer"
                    )
                key = (transaction_id, account)
                if key in imported:
                    raise ValueError(f"line {line_number} duplicates a posting")
                imported[key] = amount
        except csv.Error as error:
            raise ValueError("malformed reconciliation CSV") from error

        with sqlite3.connect(self.path) as db:
            ledger = {
                (transaction_id, account): amount
                for transaction_id, account, amount in db.execute(
                    "SELECT tx_id, account, amount FROM postings"
                )
            }

        differences = tuple(
            ReconciliationDifference(
                transaction_id=key[0],
                account=key[1],
                ledger_amount=ledger.get(key),
                imported_amount=imported.get(key),
            )
            for key in sorted(ledger.keys() | imported.keys())
            if ledger.get(key) != imported.get(key)
        )
        return ReconciliationReport(
            path=source,
            row_count=len(imported),
            sha256=digest,
            matched=not differences,
            differences=differences,
        )
