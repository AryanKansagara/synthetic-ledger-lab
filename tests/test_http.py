import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from wsgiref.util import setup_testing_defaults

from synthetic_ledger_lab.http import create_app
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

    def test_query_validation_is_strict_and_bounded(self):
        cases = [
            ("/transactions", "limit=0", "limit must be"),
            ("/transactions", "limit=1.0", "limit must be"),
            ("/transactions", "limit=1&limit=2", "must appear once"),
            ("/transactions", "unknown=value", "unsupported query parameter"),
            ("/transactions", "account=", "account must be"),
            ("/holds", "state=pending", "state must be"),
            ("/holds", "badfield", "malformed query string"),
            ("/health", "check=true", "does not accept"),
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


if __name__ == "__main__":
    unittest.main()
