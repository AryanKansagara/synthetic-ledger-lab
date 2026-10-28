import csv
import concurrent.futures
import hashlib
import hmac
import tempfile
import unittest
from pathlib import Path
from typing import Any

from synthetic_ledger_lab.ledger import AccountHold, Ledger


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "ledger.sqlite3"
        self.ledger = Ledger(self.path)

    def test_balanced_postings_persist_and_replay_once(self):
        entries = [("synthetic-cash", -1250), ("user-cash", 1250)]
        self.assertTrue(self.ledger.post("tx-1", entries))
        self.assertFalse(Ledger(self.path).post("tx-1", entries))
        self.assertEqual(self.ledger.balance("user-cash"), 1250)
        self.assertEqual(self.ledger.balance("synthetic-cash"), -1250)

    def test_unbalanced_postings_are_rejected_without_mutation(self):
        with self.assertRaisesRegex(ValueError, "balance to zero"):
            self.ledger.post("tx-1", [("a", -100), ("b", 99)])
        self.assertEqual(self.ledger.balance("a"), 0)

    def test_conflicting_transaction_id_is_rejected(self):
        self.ledger.post("tx-1", [("a", -100), ("b", 100)])
        with self.assertRaisesRegex(ValueError, "transaction ID conflict"):
            self.ledger.post("tx-1", [("a", -99), ("b", 99)])
        self.assertEqual(self.ledger.balance("b"), 100)

    def test_malformed_amounts_and_accounts_are_rejected(self):
        cases = [
            [("a", -1), ("b", True)],
            [("a", -1), ("b", 1.0)],
            [("a", -1), ("b", 0), ("c", 1)],
            [("", -1), ("b", 1)],
            [("a", -1), ("a", 1)],
        ]
        for postings in cases:
            with self.subTest(postings=postings):
                with self.assertRaises(ValueError):
                    self.ledger.post("bad", postings)
        with self.assertRaises(ValueError):
            self.ledger.post("", [("a", -1), ("b", 1)])
        self.assertEqual(self.ledger.balance("a"), 0)

    def test_balance_can_exceed_sqlite_signed_integer_range(self):
        maximum = 2**63 - 1
        self.ledger.post("tx-1", [("clearing-1", -maximum), ("wallet", maximum)])
        self.ledger.post("tx-2", [("clearing-2", -maximum), ("wallet", maximum)])

        self.assertEqual(self.ledger.balance("wallet"), 2 * maximum)
        self.assertEqual(self.ledger.balance("missing"), 0)

    def test_minimum_balance_blocks_overdraft_without_mutation(self):
        self.ledger.post("fund", [("clearing", -1000), ("wallet", 1000)])
        self.ledger.set_minimum_balance("wallet", 0)

        with self.assertRaisesRegex(ValueError, "minimum balance policy violated"):
            self.ledger.post("overspend", [("wallet", -1001), ("merchant", 1001)])

        self.assertEqual(self.ledger.balance("wallet"), 1000)
        self.assertEqual(self.ledger.balance("merchant"), 0)
        self.assertEqual(self.ledger.minimum_balance("wallet"), 0)

        self.assertTrue(
            self.ledger.post("spend", [("wallet", -1000), ("merchant", 1000)])
        )
        self.assertEqual(self.ledger.balance("wallet"), 0)

    def test_minimum_balance_policy_persists_and_can_be_removed(self):
        self.ledger.set_minimum_balance("wallet", 0)
        reopened = Ledger(self.path)

        self.assertEqual(reopened.minimum_balance("wallet"), 0)
        self.assertIsNone(reopened.minimum_balance("clearing"))
        reopened.set_minimum_balance("wallet", None)
        self.assertIsNone(self.ledger.minimum_balance("wallet"))
        self.assertTrue(
            self.ledger.post("unrestricted", [("wallet", -1), ("clearing", 1)])
        )

    def test_minimum_balance_serializes_competing_spends(self):
        self.ledger.post("fund", [("clearing", -1000), ("wallet", 1000)])
        self.ledger.set_minimum_balance("wallet", 0)

        def spend(sequence: int) -> str:
            try:
                Ledger(self.path).post(
                    f"spend-{sequence}",
                    [("wallet", -750), (f"merchant-{sequence}", 750)],
                )
                return "posted"
            except ValueError as error:
                return str(error)

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(spend, (1, 2)))

        self.assertEqual(outcomes.count("posted"), 1)
        self.assertEqual(
            sum("minimum balance policy violated" in outcome for outcome in outcomes),
            1,
        )
        self.assertEqual(self.ledger.balance("wallet"), 250)
        self.assertEqual(
            self.ledger.balance("merchant-1") + self.ledger.balance("merchant-2"),
            750,
        )

    def test_minimum_balance_cannot_be_raised_above_current_balance(self):
        self.ledger.set_minimum_balance("wallet", -10)

        with self.assertRaisesRegex(ValueError, "cannot exceed current balance"):
            self.ledger.set_minimum_balance("wallet", 1)

        self.assertEqual(self.ledger.minimum_balance("wallet"), -10)

    def test_minimum_balance_validates_inputs_and_exact_replay_stays_idempotent(self):
        self.ledger.post("fund", [("clearing", -5), ("wallet", 5)])
        self.ledger.set_minimum_balance("wallet", 5)
        self.assertFalse(
            self.ledger.post("fund", [("clearing", -5), ("wallet", 5)])
        )

        invalid_values: tuple[Any, ...] = (True, 1.5, 2**63)
        for invalid in invalid_values:
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    self.ledger.set_minimum_balance("wallet", invalid)
        with self.assertRaises(ValueError):
            self.ledger.set_minimum_balance("", 0)

    def test_hold_reserves_available_balance_until_idempotent_release(self):
        self.ledger.post("fund", [("clearing", -1000), ("wallet", 1000)])
        self.ledger.set_minimum_balance("wallet", 0)

        self.assertTrue(self.ledger.place_hold("hold-1", "wallet", 700))
        self.assertFalse(self.ledger.place_hold("hold-1", "wallet", 700))
        self.assertEqual(self.ledger.balance("wallet"), 1000)
        self.assertEqual(self.ledger.available_balance("wallet"), 300)
        self.assertEqual(
            self.ledger.hold("hold-1"),
            AccountHold("hold-1", "wallet", 700, True),
        )

        with self.assertRaisesRegex(ValueError, "minimum balance policy violated"):
            self.ledger.post("spend", [("wallet", -301), ("merchant", 301)])
        with self.assertRaisesRegex(ValueError, "active holds"):
            self.ledger.set_minimum_balance("wallet", None)
        self.assertTrue(self.ledger.release_hold("hold-1"))
        self.assertFalse(self.ledger.release_hold("hold-1"))
        self.assertEqual(self.ledger.available_balance("wallet"), 1000)
        released = self.ledger.hold("hold-1")
        self.assertIsNotNone(released)
        assert released is not None
        self.assertFalse(released.active)
        self.assertTrue(
            self.ledger.post("spend", [("wallet", -301), ("merchant", 301)])
        )

    def test_hold_validates_policy_funds_and_id_conflicts_without_mutation(self):
        self.ledger.post("fund", [("clearing", -500), ("wallet", 500)])
        with self.assertRaisesRegex(ValueError, "requires a minimum balance policy"):
            self.ledger.place_hold("hold-1", "wallet", 100)
        self.ledger.set_minimum_balance("wallet", 100)
        self.ledger.place_hold("hold-1", "wallet", 400)

        with self.assertRaisesRegex(ValueError, "insufficient available balance"):
            self.ledger.place_hold("hold-2", "wallet", 1)
        with self.assertRaisesRegex(ValueError, "hold ID conflict"):
            self.ledger.place_hold("hold-1", "wallet", 399)
        with self.assertRaisesRegex(ValueError, "cannot exceed current balance"):
            self.ledger.set_minimum_balance("wallet", 101)
        with self.assertRaisesRegex(ValueError, "unknown hold ID"):
            self.ledger.release_hold("missing")

        invalid_amounts: tuple[Any, ...] = (True, 0, -1, 1.5, 2**63)
        for invalid in invalid_amounts:
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    self.ledger.place_hold("invalid", "wallet", invalid)
        self.assertEqual(self.ledger.available_balance("wallet"), 100)

    def test_competing_holds_cannot_reserve_the_same_available_balance(self):
        self.ledger.post("fund", [("clearing", -1000), ("wallet", 1000)])
        self.ledger.set_minimum_balance("wallet", 0)

        def reserve(sequence: int) -> str:
            try:
                Ledger(self.path).place_hold(f"hold-{sequence}", "wallet", 750)
                return "held"
            except ValueError as error:
                return str(error)

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(reserve, (1, 2)))

        self.assertEqual(outcomes.count("held"), 1)
        self.assertEqual(
            sum("insufficient available balance" in outcome for outcome in outcomes), 1
        )
        self.assertEqual(self.ledger.available_balance("wallet"), 250)

    def test_transaction_audit_lookup_returns_complete_deterministic_record(self):
        self.ledger.post("tx-1", [("wallet", -125), ("merchant", 100), ("fee", 25)])

        transaction = self.ledger.transaction("tx-1")

        self.assertIsNotNone(transaction)
        assert transaction is not None
        self.assertEqual(transaction.transaction_id, "tx-1")
        self.assertEqual(
            [(posting.account, posting.amount) for posting in transaction.postings],
            [("fee", 25), ("merchant", 100), ("wallet", -125)],
        )
        self.assertIsNone(self.ledger.transaction("missing"))

    def test_transaction_pages_use_stable_keyset_and_return_complete_transactions(self):
        for transaction_id, account in (
            ("tx-c", "shop-2"),
            ("tx-a", "shop-1"),
            ("tx-b", "shop-1"),
        ):
            self.ledger.post(transaction_id, [("wallet", -10), (account, 10)])

        first = self.ledger.transactions(limit=2)
        second = self.ledger.transactions(limit=2, after=first.next_cursor)

        self.assertEqual(
            [transaction.transaction_id for transaction in first.transactions],
            ["tx-a", "tx-b"],
        )
        self.assertEqual(first.next_cursor, "tx-b")
        self.assertEqual(
            [transaction.transaction_id for transaction in second.transactions], ["tx-c"]
        )
        self.assertIsNone(second.next_cursor)
        self.assertEqual(len(second.transactions[0].postings), 2)

        filtered = self.ledger.transactions(account="shop-1")
        self.assertEqual(
            [transaction.transaction_id for transaction in filtered.transactions],
            ["tx-a", "tx-b"],
        )
        self.assertTrue(
            all(len(transaction.postings) == 2 for transaction in filtered.transactions)
        )

    def test_transaction_queries_validate_bounds_and_do_not_mutate(self):
        self.ledger.post("tx-1", [("wallet", -10), ("merchant", 10)])

        invalid_limits: tuple[Any, ...] = (True, 0, 101, 1.5)
        for invalid in invalid_limits:
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    self.ledger.transactions(limit=invalid)
        with self.assertRaises(ValueError):
            self.ledger.transactions(after="")
        with self.assertRaises(ValueError):
            self.ledger.transactions(after=1)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            self.ledger.transactions(account="")
        with self.assertRaises(ValueError):
            self.ledger.transaction("")

        self.assertEqual(self.ledger.balance("wallet"), -10)
        self.assertFalse(
            self.ledger.post("tx-1", [("wallet", -10), ("merchant", 10)])
        )

    def test_reconciliation_export_is_deterministic_and_checksummed(self):
        self.ledger.post("tx-z", [("wallet", -250), ("merchant", 250)])
        self.ledger.post("tx-a", [("clearing", -1000), ("wallet", 1000)])
        destination = Path(self.tmp.name) / "snapshot.csv"

        result = self.ledger.export_reconciliation_csv(destination)
        payload = destination.read_bytes()

        self.assertEqual(result.path, destination)
        self.assertEqual(result.row_count, 4)
        self.assertEqual(result.sha256, hashlib.sha256(payload).hexdigest())
        with destination.open(newline="") as export_file:
            self.assertEqual(
                list(csv.reader(export_file)),
                [
                    ["transaction_id", "account", "amount_minor"],
                    ["tx-a", "clearing", "-1000"],
                    ["tx-a", "wallet", "1000"],
                    ["tx-z", "merchant", "250"],
                    ["tx-z", "wallet", "-250"],
                ],
            )

        second = self.ledger.export_reconciliation_csv(destination)
        self.assertEqual(second.sha256, result.sha256)

    def test_reconciliation_export_quotes_accounts_and_protects_database(self):
        self.ledger.post("tx-1", [("account,with-comma", -5), ("wallet\nline", 5)])
        destination = Path(self.tmp.name) / "snapshot.csv"
        result = self.ledger.export_reconciliation_csv(destination)

        with destination.open(newline="") as export_file:
            rows = list(csv.reader(export_file))
        self.assertEqual(
            rows[1:],
            [["tx-1", "account,with-comma", "-5"], ["tx-1", "wallet\nline", "5"]],
        )
        self.assertEqual(result.row_count, 2)

        with self.assertRaisesRegex(ValueError, "must not overwrite"):
            self.ledger.export_reconciliation_csv(self.path)
        self.assertEqual(self.ledger.balance("wallet\nline"), 5)

    def test_reconciliation_import_matches_export_and_verifies_checksum(self):
        self.ledger.post("tx-1", [("clearing", -500), ("wallet", 500)])
        source = Path(self.tmp.name) / "snapshot.csv"
        exported = self.ledger.export_reconciliation_csv(source)

        report = self.ledger.reconcile_csv(source, expected_sha256=exported.sha256.upper())

        self.assertTrue(report.matched)
        self.assertEqual(report.row_count, 2)
        self.assertEqual(report.sha256, exported.sha256)
        self.assertEqual(report.differences, ())

        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            self.ledger.reconcile_csv(source, expected_sha256="0" * 64)

    def test_reconciliation_import_reports_changed_missing_and_extra_postings(self):
        self.ledger.post("tx-1", [("clearing", -500), ("wallet", 500)])
        source = Path(self.tmp.name) / "external.csv"
        source.write_text(
            "transaction_id,account,amount_minor\n"
            "tx-1,clearing,-499\n"
            "tx-2,merchant,25\n",
            encoding="utf-8",
        )

        report = self.ledger.reconcile_csv(source)

        self.assertFalse(report.matched)
        self.assertEqual(
            [
                (item.transaction_id, item.account, item.ledger_amount, item.imported_amount)
                for item in report.differences
            ],
            [
                ("tx-1", "clearing", -500, -499),
                ("tx-1", "wallet", 500, None),
                ("tx-2", "merchant", None, 25),
            ],
        )
        self.assertEqual(self.ledger.balance("wallet"), 500)

    def test_reconciliation_import_rejects_malformed_or_ambiguous_rows(self):
        source = Path(self.tmp.name) / "invalid.csv"
        cases = [
            "wrong,header,names\n",
            "transaction_id,account,amount_minor\ntx-1,a\n",
            "transaction_id,account,amount_minor\ntx-1,a,0\n",
            "transaction_id,account,amount_minor\ntx-1,a,+1\n",
            "transaction_id,account,amount_minor\ntx-1,a,01\n",
            "transaction_id,account,amount_minor\ntx-1,a,1\ntx-1,a,1\n",
            f"transaction_id,account,amount_minor\ntx-1,a,{2**63}\n",
        ]
        for payload in cases:
            with self.subTest(payload=payload):
                source.write_text(payload, encoding="utf-8")
                with self.assertRaises(ValueError):
                    self.ledger.reconcile_csv(source)

        with self.assertRaisesRegex(ValueError, "64-character hex"):
            self.ledger.reconcile_csv(source, expected_sha256="not-a-digest")

    def test_signed_reconciliation_snapshot_authenticates_before_import(self):
        self.ledger.post("tx-1", [("clearing", -500), ("wallet", 500)])
        source = Path(self.tmp.name) / "signed.csv"
        key = b"synthetic-reconciliation-key-32b"

        exported = self.ledger.export_reconciliation_csv(source, signing_key=key)
        payload = source.read_bytes()

        self.assertEqual(
            exported.hmac_sha256,
            hmac.new(key, payload, hashlib.sha256).hexdigest(),
        )
        report = self.ledger.reconcile_csv(
            source,
            expected_sha256=exported.sha256,
            expected_hmac_sha256=exported.hmac_sha256,
            signing_key=key,
        )
        self.assertTrue(report.matched)

        source.write_bytes(payload + b"tampered")
        with self.assertRaisesRegex(ValueError, "authentication failed"):
            self.ledger.reconcile_csv(
                source,
                expected_hmac_sha256=exported.hmac_sha256,
                signing_key=key,
            )

    def test_signed_reconciliation_requires_complete_strong_credentials(self):
        source = Path(self.tmp.name) / "snapshot.csv"
        source.write_text("transaction_id,account,amount_minor\n", encoding="utf-8")
        key = b"synthetic-reconciliation-key-32b"

        with self.assertRaisesRegex(ValueError, "at least 32 bytes"):
            self.ledger.export_reconciliation_csv(source, signing_key=b"too-short")
        with self.assertRaisesRegex(ValueError, "supplied together"):
            self.ledger.reconcile_csv(source, signing_key=key)
        with self.assertRaisesRegex(ValueError, "64-character hex tag"):
            self.ledger.reconcile_csv(
                source, expected_hmac_sha256="invalid", signing_key=key
            )


if __name__ == "__main__":
    unittest.main()
