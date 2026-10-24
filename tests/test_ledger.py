import tempfile
import unittest
from pathlib import Path

from synthetic_ledger_lab.ledger import Ledger


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


if __name__ == "__main__":
    unittest.main()
