import json
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from typing import Any
from unittest.mock import patch
from wsgiref.util import setup_testing_defaults

from synthetic_ledger_lab.http import _ShutdownState, _shutdown_handler, create_app
from synthetic_ledger_lab.ledger import Ledger


class AuditHttpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ledger = Ledger(Path(self.tmp.name) / "ledger.sqlite3", clock=lambda: 100)
        self.ledger.post("fund", [("clearing", -1000), ("wallet", 1000)])
        self.ledger.set_minimum_balance("wallet", 0)
        self.ledger.place_hold("hold-active", "wallet", 100, expires_at=200)
        self.app = create_app(self.ledger)

    def request(
        self,
        path: str,
        *,
        query: str = "",
        method: str = "GET",
        authorization: str | None = None,
    ) -> tuple[str, dict[str, str], dict[str, Any]]:
        environ: dict[str, Any] = {}
        setup_testing_defaults(environ)
        environ.update(
            REQUEST_METHOD=method,
            PATH_INFO=path,
            QUERY_STRING=query,
        )
        if authorization is not None:
            environ["HTTP_AUTHORIZATION"] = authorization
        response_status = ""
        response_headers: list[tuple[str, str]] = []

        def start_response(status, headers):
            nonlocal response_status, response_headers
            response_status = status
            response_headers = headers

        body = b"".join(self.app(environ, start_response))
        return response_status, dict(response_headers), json.loads(body)

    def raw_request(
        self, path: str, *, query: str = "", method: str = "GET"
    ) -> tuple[str, dict[str, str], bytes]:
        environ: dict[str, Any] = {}
        setup_testing_defaults(environ)
        environ.update(REQUEST_METHOD=method, PATH_INFO=path, QUERY_STRING=query)
        response_status = ""
        response_headers: list[tuple[str, str]] = []

        def start_response(status, headers):
            nonlocal response_status, response_headers
            response_status = status
            response_headers = headers

        body = b"".join(self.app(environ, start_response))
        return response_status, dict(response_headers), body

    def test_health_and_read_only_method_boundary(self):
        status, headers, payload = self.request("/health")
        self.assertEqual(status, "200 OK")
        self.assertEqual(payload, {"status": "ok"})
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(int(headers["Content-Length"]), len(b'{"status":"ok"}'))
        self.assertEqual(len(headers["X-Request-ID"]), 32)

        status, _, payload = self.request("/transactions", method="POST")
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertEqual(payload, {"error": "method not allowed"})

    def test_readiness_is_public_unlimited_and_withdrawn_during_shutdown(self):
        state = _ShutdownState()
        self.app = create_app(
            self.ledger,
            api_token="synthetic-demo-token",
            audit_rate_limit=1,
            rate_clock=lambda: 100.0,
            readiness=state.ready,
        )

        for _ in range(3):
            status, _, payload = self.request("/ready")
            self.assertEqual((status, payload), ("200 OK", {"status": "ready"}))

        state.begin(lambda: None)
        status, _, payload = self.request("/ready")
        self.assertEqual(
            (status, payload),
            ("503 Service Unavailable", {"status": "unavailable"}),
        )
        self.assertEqual(self.request("/health")[0], "200 OK")

    def test_readiness_checks_existing_database_and_required_schema_without_creating(self):
        database_path = self.ledger.path
        database_path.unlink()

        status, _, payload = self.request("/ready")

        self.assertEqual(
            (status, payload),
            ("503 Service Unavailable", {"status": "unavailable"}),
        )
        self.assertFalse(database_path.exists())
        self.assertEqual(self.request("/health")[0], "200 OK")

    def test_readiness_sanitizes_corrupt_and_incomplete_databases(self):
        database_path = self.ledger.path
        database_path.write_bytes(b"not a sqlite database /private/ledger.sqlite3")
        self.assertEqual(self.request("/ready")[0], "503 Service Unavailable")

        database_path.unlink()
        with closing(sqlite3.connect(database_path)) as database, database:
            database.execute("CREATE TABLE transactions (tx_id TEXT PRIMARY KEY)")
        status, _, payload = self.request("/ready")
        self.assertEqual(status, "503 Service Unavailable")
        self.assertEqual(payload, {"status": "unavailable"})

    def test_shutdown_handler_is_idempotent_and_runs_shutdown_off_signal_thread(self):
        state = _ShutdownState()
        shutdown_called = threading.Event()
        call_threads: list[int] = []

        def shutdown():
            call_threads.append(threading.get_ident())
            shutdown_called.set()

        handler = _shutdown_handler(state, shutdown)
        signal_thread = threading.get_ident()
        handler(15, None)
        handler(15, None)

        self.assertTrue(shutdown_called.wait(timeout=1))
        self.assertFalse(state.ready())
        self.assertEqual(len(call_threads), 1)
        self.assertNotEqual(call_threads[0], signal_thread)

    def test_correlation_and_access_records_are_bounded_and_privacy_conscious(self):
        records: list[dict[str, Any]] = []
        self.app = create_app(
            self.ledger,
            api_token="synthetic-demo-token",
            access_logger=records.append,
            request_id_factory=lambda: "request-123",
        )

        status, headers, _ = self.request(
            "/transactions/fund",
            query="secret-query=value",
            authorization="Bearer synthetic-demo-token",
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(headers["X-Request-ID"], "request-123")
        self.assertEqual(
            records,
            [
                {
                    "event": "audit_http_access",
                    "method": "GET",
                    "request_id": "request-123",
                    "route": "/transactions/{id}",
                    "status": 400,
                }
            ],
        )
        serialized = json.dumps(records)
        self.assertNotIn("secret-query", serialized)
        self.assertNotIn("synthetic-demo-token", serialized)
        self.assertNotIn("fund", serialized)

        self.request("/user-controlled/value/nested", method="DELETE")
        self.assertEqual(records[-1]["method"], "OTHER")
        self.assertEqual(records[-1]["route"], "unmatched")
        self.assertEqual(records[-1]["status"], 401)

    def test_metrics_are_public_prometheus_compatible_and_have_bounded_labels(self):
        monotonic_values = iter((1.0, 1.125, 2.0, 2.25, 3.0, 3.375, 4.0, 4.5))
        self.app = create_app(
            self.ledger,
            api_token="synthetic-demo-token",
            audit_rate_limit=1,
            rate_clock=lambda: 100.0,
            metrics_clock=lambda: next(monotonic_values),
        )

        self.request("/health")
        self.request("/transactions/secret-id")
        self.request("/customer/secret-id", method="ATTACKER-CONTROLLED")
        status, headers, body = self.raw_request("/metrics")

        self.assertEqual(status, "200 OK")
        self.assertEqual(
            headers["Content-Type"], "text/plain; version=0.0.4; charset=utf-8"
        )
        self.assertEqual(headers["Cache-Control"], "no-store")
        text = body.decode()
        self.assertIn("# TYPE ledger_audit_http_requests_total counter", text)
        self.assertIn(
            'ledger_audit_http_requests_total{method="GET",route="/health",status="200"} 1',
            text,
        )
        self.assertIn(
            'ledger_audit_http_requests_total{method="GET",route="/transactions/{id}",status="401"} 1',
            text,
        )
        self.assertIn(
            'ledger_audit_http_requests_total{method="OTHER",route="unmatched",status="429"} 1',
            text,
        )
        self.assertIn(
            'ledger_audit_http_request_duration_seconds_sum{method="GET",route="/health",status="200"} 0.125000',
            text,
        )
        self.assertNotIn("ATTACKER-CONTROLLED", text)
        self.assertNotIn("customer", text)
        self.assertNotIn("secret-id", text)

    def test_metrics_endpoint_contract_and_scrapes_are_observed(self):
        self.assertEqual(
            self.raw_request("/metrics", method="POST")[0],
            "405 Method Not Allowed",
        )
        status, _, payload = self.request("/metrics", query="secret=value")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(
            payload, {"error": "metrics endpoint does not accept query parameters"}
        )

        status, _, body = self.raw_request("/metrics")
        self.assertEqual(status, "200 OK")
        self.assertIn(
            b'ledger_audit_http_requests_total{method="POST",route="/metrics",status="405"} 1',
            body,
        )
        self.assertIn(
            b'ledger_audit_http_requests_total{method="GET",route="/metrics",status="400"} 1',
            body,
        )

    def test_request_id_factory_rejects_unsafe_values(self):
        for request_id in ["", "space value", "line\nbreak", "nōn-ascii", "x" * 129]:
            with self.subTest(request_id=request_id):
                self.app = create_app(
                    self.ledger, request_id_factory=lambda value=request_id: value
                )
                with self.assertRaisesRegex(ValueError, "request_id_factory"):
                    self.request("/health")

    def test_optional_bearer_auth_protects_audit_routes_but_not_health(self):
        self.app = create_app(self.ledger, api_token="synthetic-demo-token")

        status, _, payload = self.request("/health")
        self.assertEqual(status, "200 OK")
        self.assertEqual(payload, {"status": "ok"})

        for authorization in [
            None,
            "",
            "Bearer wrong",
            "bearer synthetic-demo-token",
            "Bearer nōn-ascii",
        ]:
            with self.subTest(authorization=authorization):
                status, headers, payload = self.request(
                    "/transactions", authorization=authorization
                )
                self.assertEqual(status, "401 Unauthorized")
                self.assertEqual(payload, {"error": "unauthorized"})
                self.assertEqual(headers["WWW-Authenticate"], 'Bearer realm="ledger-audit"')
                self.assertNotIn("synthetic-demo-token", json.dumps(payload))

        status, _, payload = self.request(
            "/transactions", authorization="Bearer synthetic-demo-token"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(payload["transactions"][0]["transaction_id"], "fund")

    def test_bearer_token_configuration_rejects_unsafe_values(self):
        for token in ["", "contains whitespace", "line\nbreak", "nōn-ascii"]:
            with self.subTest(token=token):
                with self.assertRaisesRegex(ValueError, "api_token"):
                    create_app(self.ledger, api_token=token)

    def test_audit_rate_limit_counts_auth_failures_and_recovers_after_window(self):
        now = 100.0
        self.app = create_app(
            self.ledger,
            api_token="synthetic-demo-token",
            audit_rate_limit=2,
            rate_window_seconds=30,
            rate_clock=lambda: now,
        )

        self.assertEqual(self.request("/transactions")[0], "401 Unauthorized")
        self.assertEqual(
            self.request("/holds", authorization="Bearer synthetic-demo-token")[0],
            "200 OK",
        )
        status, headers, payload = self.request(
            "/transactions", authorization="Bearer synthetic-demo-token"
        )
        self.assertEqual(status, "429 Too Many Requests")
        self.assertEqual(headers["Retry-After"], "30")
        self.assertEqual(payload, {"error": "audit request rate limit exceeded"})

        now += 29.2
        status, headers, _ = self.request(
            "/transactions", authorization="Bearer synthetic-demo-token"
        )
        self.assertEqual(status, "429 Too Many Requests")
        self.assertEqual(headers["Retry-After"], "1")

        now += 0.8
        self.assertEqual(
            self.request(
                "/transactions", authorization="Bearer synthetic-demo-token"
            )[0],
            "200 OK",
        )

    def test_health_is_not_rate_limited(self):
        self.app = create_app(
            self.ledger,
            audit_rate_limit=1,
            rate_window_seconds=60,
            rate_clock=lambda: 100.0,
        )

        self.assertEqual(self.request("/transactions")[0], "200 OK")
        self.assertEqual(self.request("/transactions")[0], "429 Too Many Requests")
        for _ in range(3):
            self.assertEqual(self.request("/health")[0], "200 OK")

    def test_rate_limit_is_atomic_for_competing_requests(self):
        self.app = create_app(
            self.ledger,
            audit_rate_limit=5,
            rate_window_seconds=60,
            rate_clock=lambda: 100.0,
        )

        with ThreadPoolExecutor(max_workers=20) as executor:
            statuses = list(
                executor.map(lambda _: self.request("/transactions")[0], range(20))
            )

        self.assertEqual(statuses.count("200 OK"), 5)
        self.assertEqual(statuses.count("429 Too Many Requests"), 15)

    def test_rate_limit_configuration_must_be_positive_integers(self):
        for options in [
            {"audit_rate_limit": 0},
            {"audit_rate_limit": True},
            {"rate_window_seconds": 0},
            {"rate_window_seconds": 1.5},
        ]:
            with self.subTest(options=options):
                with self.assertRaisesRegex(ValueError, "positive integer"):
                    create_app(self.ledger, **options)

    def test_transactions_support_exact_lookup_and_keyset_pagination(self):
        self.ledger.post("purchase", [("merchant", 250), ("wallet", -250)])

        status, _, payload = self.request(
            "/transactions", query="account=wallet&limit=1"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual([item["transaction_id"] for item in payload["transactions"]], ["fund"])
        self.assertEqual(payload["next_cursor"], "fund")
        self.assertEqual(
            payload["transactions"][0]["postings"],
            [
                {"account": "clearing", "amount": -1000},
                {"account": "wallet", "amount": 1000},
            ],
        )

        status, _, payload = self.request("/transactions", query="after=fund&limit=1")
        self.assertEqual(status, "200 OK")
        self.assertEqual(payload["transactions"][0]["transaction_id"], "purchase")
        self.assertIsNone(payload["next_cursor"])

        status, _, payload = self.request("/transactions/purchase")
        self.assertEqual(status, "200 OK")
        self.assertEqual(payload["transaction_id"], "purchase")
        status, _, payload = self.request("/transactions/missing")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(payload, {"error": "transaction not found"})

    def test_holds_expose_explicit_lifecycle_state_and_filters(self):
        self.ledger.place_hold("hold-release", "wallet", 50)
        self.ledger.release_hold("hold-release")

        status, _, payload = self.request("/holds", query="state=active&account=wallet")
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(payload["holds"]), 1)
        self.assertEqual(payload["holds"][0]["hold_id"], "hold-active")
        self.assertEqual(payload["holds"][0]["state"], "active")

        status, _, payload = self.request("/holds/hold-release")
        self.assertEqual(status, "200 OK")
        self.assertEqual(payload["state"], "released")
        status, _, payload = self.request("/holds/missing")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(payload, {"error": "hold not found"})

    def test_account_statement_exposes_bounded_running_balance_pages(self):
        self.ledger.post("purchase", [("merchant", 250), ("wallet", -250)])

        status, _, payload = self.request(
            "/account-statement", query="account=wallet&limit=1"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(payload["account"], "wallet")
        self.assertEqual(
            payload["entries"],
            [{"amount": 1000, "balance_after": 1000, "transaction_id": "fund"}],
        )
        self.assertEqual(payload["next_cursor"], "fund")

        status, _, payload = self.request(
            "/account-statement", query="account=wallet&after=fund&limit=1"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(payload["entries"][0]["transaction_id"], "purchase")
        self.assertEqual(payload["entries"][0]["balance_after"], 750)
        self.assertIsNone(payload["next_cursor"])

    def test_query_validation_is_strict_and_bounded(self):
        cases = [
            ("/transactions", "limit=0", "limit must be"),
            ("/transactions", "limit=1.0", "limit must be"),
            ("/transactions", "limit=1&limit=2", "must appear once"),
            ("/transactions", "unknown=value", "unsupported query parameter"),
            ("/transactions", "account=", "account must be"),
            ("/account-statement", "limit=1", "account is required"),
            ("/account-statement", "account=", "account must be"),
            ("/holds", "state=pending", "state must be"),
            ("/holds", "badfield", "malformed query string"),
            ("/health", "check=true", "does not accept"),
            ("/ready", "check=true", "does not accept"),
        ]
        for path, query, message in cases:
            with self.subTest(path=path, query=query):
                status, _, payload = self.request(path, query=query)
                self.assertEqual(status, "400 Bad Request")
                self.assertIn(message, payload["error"])

    def test_unknown_and_nested_resource_paths_are_not_found(self):
        for path in ["/", "/unknown", "/transactions/one/two", "/holds/one/two"]:
            with self.subTest(path=path):
                status, _, payload = self.request(path)
                self.assertEqual(status, "404 Not Found")
                self.assertEqual(payload, {"error": "not found"})

    def test_database_failures_are_sanitized_and_correlated(self):
        records: list[dict[str, Any]] = []
        self.app = create_app(
            self.ledger,
            access_logger=records.append,
            request_id_factory=lambda: "request-db-failure",
        )
        detail = "unable to open database file: /private/ledger.sqlite3"

        cases = [
            ("/transactions", "transactions"),
            ("/transactions/fund", "transaction"),
            ("/account-statement", "account_statement"),
            ("/holds", "holds"),
            ("/holds/hold-active", "hold"),
        ]
        for path, method in cases:
            with self.subTest(path=path), patch.object(
                self.ledger, method, side_effect=sqlite3.OperationalError(detail)
            ):
                query = "account=wallet" if path == "/account-statement" else ""
                status, headers, payload = self.request(path, query=query)
                self.assertEqual(status, "503 Service Unavailable")
                self.assertEqual(payload, {"error": "ledger temporarily unavailable"})
                self.assertEqual(headers["X-Request-ID"], "request-db-failure")
                self.assertNotIn(detail, json.dumps(payload))
                self.assertEqual(records[-1]["status"], 503)


if __name__ == "__main__":
    unittest.main()
