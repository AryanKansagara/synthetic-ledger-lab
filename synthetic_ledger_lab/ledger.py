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
import time
from collections.abc import Callable
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


@dataclass(frozen=True)
class AccountHold:
    """One durable synthetic balance reservation."""

    hold_id: str
    account: str
    amount: int
    active: bool
    captured_transaction_id: str | None = None
    expires_at: int | None = None
    expired_at: int | None = None


_RECONCILIATION_HEADER = ("transaction_id", "account", "amount_minor")
_CANONICAL_INTEGER = re.compile(r"-?[1-9][0-9]*\Z")
_MAX_RECONCILIATION_BYTES = 10 * 1024 * 1024


def _validate_signing_key(signing_key: bytes) -> None:
    if not isinstance(signing_key, bytes) or len(signing_key) < 32:
        raise ValueError("signing_key must contain at least 32 bytes")


class Ledger:
    def __init__(
        self, path: str | Path, *, clock: Callable[[], int] | None = None
    ):
        self.path = Path(path)
        self._clock = clock or (lambda: int(time.time()))
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
            db.execute("""CREATE TABLE IF NOT EXISTS account_holds (
                hold_id TEXT PRIMARY KEY,
                account TEXT NOT NULL,
                amount INTEGER NOT NULL CHECK(amount > 0),
                active INTEGER NOT NULL CHECK(active IN (0, 1)),
                captured_tx_id TEXT REFERENCES transactions(tx_id),
                expires_at INTEGER,
                expired_at INTEGER
            )""")
            hold_columns = {
                row[1] for row in db.execute("PRAGMA table_info(account_holds)")
            }
            if "captured_tx_id" not in hold_columns:
                db.execute(
                    "ALTER TABLE account_holds ADD COLUMN captured_tx_id TEXT "
                    "REFERENCES transactions(tx_id)"
                )
            if "expires_at" not in hold_columns:
                db.execute("ALTER TABLE account_holds ADD COLUMN expires_at INTEGER")
            if "expired_at" not in hold_columns:
                db.execute("ALTER TABLE account_holds ADD COLUMN expired_at INTEGER")
            db.execute("CREATE INDEX IF NOT EXISTS postings_account ON postings(account)")
            db.execute(
                "CREATE INDEX IF NOT EXISTS active_holds_account "
                "ON account_holds(account, active)"
            )

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

    @staticmethod
    def _active_holds_in_connection(db: sqlite3.Connection, account: str) -> int:
        amounts = db.execute(
            "SELECT amount FROM account_holds WHERE account = ? AND active = 1",
            (account,),
        )
        return sum(amount for (amount,) in amounts)

    def _now(self) -> int:
        now = self._clock()
        if type(now) is not int or not 0 <= now < 2**63:
            raise ValueError("clock must return a non-negative signed 64-bit integer")
        return now

    @staticmethod
    def _expire_holds_in_connection(
        db: sqlite3.Connection, now: int, account: str | None = None
    ) -> int:
        account_clause = " AND account = ?" if account is not None else ""
        parameters = (now, account) if account is not None else (now,)
        cursor = db.execute(
            """UPDATE account_holds
               SET active = 0, expired_at = expires_at
               WHERE active = 1 AND expires_at IS NOT NULL AND expires_at <= ?"""
            + account_clause,
            parameters,
        )
        return cursor.rowcount

    def expire_holds(self) -> int:
        """Durably expire all holds whose deadline has passed.

        Returns the number transitioned by this call. Expiration uses the
        injected integer Unix-time clock and is idempotent across retries.
        """
        now = self._now()
        with sqlite3.connect(self.path, timeout=10) as db:
            db.execute("BEGIN IMMEDIATE")
            return self._expire_holds_in_connection(db, now)

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
            self._expire_holds_in_connection(db, self._now(), account)
            if minimum_balance is None:
                if self._active_holds_in_connection(db, account):
                    raise ValueError("cannot remove policy while account has active holds")
                db.execute("DELETE FROM account_policies WHERE account = ?", (account,))
                return
            available = self._balance_in_connection(
                db, account
            ) - self._active_holds_in_connection(db, account)
            if available < minimum_balance:
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

    def place_hold(
        self,
        hold_id: str,
        account: str,
        amount: int,
        *,
        expires_at: int | None = None,
    ) -> bool:
        """Reserve available balance under an account's configured floor.

        Returns ``False`` for an exact hold-ID replay. A hold is durable until
        released, captured, or expired and prevents unrelated postings from
        spending its reserved amount. Holds require an existing minimum-balance
        policy so their lower bound is explicit rather than silently assuming
        zero.
        """
        if not isinstance(hold_id, str) or not hold_id.strip():
            raise ValueError("hold_id must be a non-empty string")
        self._validate_account(account)
        if type(amount) is not int or not 0 < amount < 2**63:
            raise ValueError("amount must be a positive signed 64-bit integer")
        if expires_at is not None and (
            type(expires_at) is not int or not 0 <= expires_at < 2**63
        ):
            raise ValueError(
                "expires_at must be a non-negative signed 64-bit integer or None"
            )

        with sqlite3.connect(self.path, timeout=10) as db:
            db.execute("BEGIN IMMEDIATE")
            now = self._now()
            self._expire_holds_in_connection(db, now, account)
            prior = db.execute(
                "SELECT account, amount, expires_at FROM account_holds WHERE hold_id = ?",
                (hold_id,),
            ).fetchone()
            if prior is not None:
                if prior != (account, amount, expires_at):
                    raise ValueError("hold ID conflict")
                return False
            if expires_at is not None and expires_at <= now:
                raise ValueError("expires_at must be in the future")
            policy = db.execute(
                "SELECT minimum_balance FROM account_policies WHERE account = ?",
                (account,),
            ).fetchone()
            if policy is None:
                raise ValueError("account hold requires a minimum balance policy")
            available = self._balance_in_connection(
                db, account
            ) - self._active_holds_in_connection(db, account)
            if available - amount < policy[0]:
                raise ValueError("insufficient available balance for hold")
            db.execute(
                """INSERT INTO account_holds
                   (hold_id, account, amount, active, expires_at)
                   VALUES (?, ?, ?, 1, ?)""",
                (hold_id, account, amount, expires_at),
            )
            return True

    def release_hold(self, hold_id: str) -> bool:
        """Release a hold once; return ``False`` when it was already released."""
        if not isinstance(hold_id, str) or not hold_id.strip():
            raise ValueError("hold_id must be a non-empty string")
        with sqlite3.connect(self.path, timeout=10) as db:
            db.execute("BEGIN IMMEDIATE")
            self._expire_holds_in_connection(db, self._now())
            row = db.execute(
                """SELECT active, captured_tx_id, expired_at
                   FROM account_holds WHERE hold_id = ?""",
                (hold_id,),
            ).fetchone()
            if row is None:
                raise ValueError("unknown hold ID")
            if row[1] is not None:
                raise ValueError("captured hold cannot be released")
            if row[2] is not None:
                raise ValueError("expired hold cannot be released")
            if not row[0]:
                return False
            db.execute(
                "UPDATE account_holds SET active = 0 WHERE hold_id = ?", (hold_id,)
            )
            return True

    def capture_hold(
        self, hold_id: str, transaction_id: str, destination_account: str
    ) -> bool:
        """Atomically convert an active hold into a two-posting transaction.

        The full reserved amount is debited from the held account and credited to
        ``destination_account``. Returns ``False`` for an exact capture replay.
        Capture, policy checks, hold state, and postings share one SQLite write
        transaction, so funds cannot become available between those operations.
        """
        if not isinstance(hold_id, str) or not hold_id.strip():
            raise ValueError("hold_id must be a non-empty string")
        if not isinstance(transaction_id, str) or not transaction_id.strip():
            raise ValueError("transaction_id must be a non-empty string")
        self._validate_account(destination_account)

        with sqlite3.connect(self.path, timeout=10) as db:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("BEGIN IMMEDIATE")
            self._expire_holds_in_connection(db, self._now())
            hold = db.execute(
                """SELECT account, amount, active, captured_tx_id, expired_at
                   FROM account_holds WHERE hold_id = ?""",
                (hold_id,),
            ).fetchone()
            if hold is None:
                raise ValueError("unknown hold ID")
            account, amount, active, captured_transaction_id, expired_at = hold
            if destination_account == account:
                raise ValueError("capture destination must differ from held account")
            entries = [(account, -amount), (destination_account, amount)]
            payload = json.dumps(entries, separators=(",", ":"))

            if captured_transaction_id is not None:
                prior = db.execute(
                    "SELECT payload FROM transactions WHERE tx_id = ?",
                    (captured_transaction_id,),
                ).fetchone()
                if captured_transaction_id == transaction_id and prior == (payload,):
                    return False
                raise ValueError("hold capture conflict")
            if expired_at is not None:
                raise ValueError("expired hold cannot be captured")
            if not active:
                raise ValueError("released hold cannot be captured")
            if db.execute(
                "SELECT 1 FROM transactions WHERE tx_id = ?", (transaction_id,)
            ).fetchone() is not None:
                raise ValueError("transaction ID conflict")

            db.execute(
                "INSERT INTO transactions (tx_id, payload) VALUES (?, ?)",
                (transaction_id, payload),
            )
            db.execute(
                """UPDATE account_holds
                   SET active = 0, captured_tx_id = ? WHERE hold_id = ?""",
                (transaction_id, hold_id),
            )
            for posting_account, posting_amount in entries:
                policy = db.execute(
                    "SELECT minimum_balance FROM account_policies WHERE account = ?",
                    (posting_account,),
                ).fetchone()
                if policy is not None:
                    resulting_available = (
                        self._balance_in_connection(db, posting_account)
                        + posting_amount
                        - self._active_holds_in_connection(db, posting_account)
                    )
                    if resulting_available < policy[0]:
                        raise ValueError(
                            "minimum balance policy violated for account "
                            f"{posting_account!r}"
                        )
            db.executemany(
                "INSERT INTO postings (tx_id, account, amount) VALUES (?, ?, ?)",
                [
                    (transaction_id, posting_account, posting_amount)
                    for posting_account, posting_amount in entries
                ],
            )
            return True

    def hold(self, hold_id: str) -> AccountHold | None:
        """Return a hold for operational audit, including inactive holds."""
        if not isinstance(hold_id, str) or not hold_id.strip():
            raise ValueError("hold_id must be a non-empty string")
        with sqlite3.connect(self.path, timeout=10) as db:
            db.execute("BEGIN IMMEDIATE")
            self._expire_holds_in_connection(db, self._now())
            row = db.execute(
                """SELECT hold_id, account, amount, active, captured_tx_id,
                          expires_at, expired_at
                   FROM account_holds WHERE hold_id = ?""",
                (hold_id,),
            ).fetchone()
        return (
            None
            if row is None
            else AccountHold(
                row[0], row[1], row[2], bool(row[3]), row[4], row[5], row[6]
            )
        )

    def available_balance(self, account: str) -> int:
        """Return current balance less all active holds for an account."""
        self._validate_account(account)
        with sqlite3.connect(self.path, timeout=10) as db:
            db.execute("BEGIN IMMEDIATE")
            self._expire_holds_in_connection(db, self._now(), account)
            return self._balance_in_connection(
                db, account
            ) - self._active_holds_in_connection(db, account)

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
            now = self._now()
            for account, _ in normalized:
                self._expire_holds_in_connection(db, now, account)
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
                    resulting_available = (
                        self._balance_in_connection(db, account)
                        + amount
                        - self._active_holds_in_connection(db, account)
                    )
                    if resulting_available < policy[0]:
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
