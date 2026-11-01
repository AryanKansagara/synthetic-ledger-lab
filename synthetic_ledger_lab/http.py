"""Dependency-free read-only HTTP adapter for synthetic ledger audit data."""

import argparse
import hmac
import json
import os
import secrets
import sys
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import asdict
from typing import Any
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server

from synthetic_ledger_lab.ledger import Ledger

StartResponse = Callable[[str, list[tuple[str, str]]], Any]
AccessLogger = Callable[[dict[str, Any]], None]


class _FixedWindowRateLimiter:
    """Thread-safe, process-local request limiter for the demo audit routes."""

    def __init__(
        self,
        limit: int,
        window_seconds: int,
        clock: Callable[[], float],
    ) -> None:
        if type(limit) is not int or limit <= 0:
            raise ValueError("audit_rate_limit must be a positive integer")
        if type(window_seconds) is not int or window_seconds <= 0:
            raise ValueError("rate_window_seconds must be a positive integer")
        self.limit = limit
        self.window_seconds = window_seconds
        self._clock = clock
        self._window_started: float | None = None
        self._requests = 0
        self._lock = threading.Lock()

    def allow(self) -> tuple[bool, int]:
        with self._lock:
            now = self._clock()
            if (
                self._window_started is None
                or now - self._window_started >= self.window_seconds
            ):
                self._window_started = now
                self._requests = 0
            elapsed = max(0.0, now - self._window_started)
            retry_after = max(1, int(self.window_seconds - elapsed + 0.999))
            if self._requests >= self.limit:
                return False, retry_after
            self._requests += 1
            return True, retry_after


def _route(path: str) -> str:
    if path in {"/health", "/transactions", "/holds"}:
        return path
    if path.startswith("/transactions/") and "/" not in path.removeprefix(
        "/transactions/"
    ):
        return "/transactions/{id}"
    if path.startswith("/holds/") and "/" not in path.removeprefix("/holds/"):
        return "/holds/{id}"
    return "unmatched"


def _request_id(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 128
        or not value.isascii()
        or any(not 33 <= ord(char) <= 126 for char in value)
    ):
        raise ValueError("request_id_factory must return 1-128 visible ASCII characters")
    return value


def _stderr_access_logger(record: dict[str, Any]) -> None:
    print(json.dumps(record, separators=(",", ":"), sort_keys=True), file=sys.stderr)


def _json_response(
    start_response: StartResponse,
    status: str,
    payload: dict[str, Any],
    extra_headers: list[tuple[str, str]] | None = None,
) -> list[bytes]:
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    start_response(
        status,
        [
            ("Content-Type", "application/json; charset=utf-8"),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
        ]
        + (extra_headers or []),
    )
    return [body]


def _query(environ: dict[str, Any], allowed: set[str]) -> dict[str, str]:
    try:
        values = parse_qs(
            environ.get("QUERY_STRING", ""),
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=10,
        )
    except ValueError as error:
        raise ValueError("malformed query string") from error
    unknown = set(values) - allowed
    if unknown:
        raise ValueError(f"unsupported query parameter: {sorted(unknown)[0]}")
    duplicate = next((key for key, items in values.items() if len(items) != 1), None)
    if duplicate is not None:
        raise ValueError(f"query parameter must appear once: {duplicate}")
    return {key: items[0] for key, items in values.items()}


def _limit(value: str | None) -> int:
    if value is None:
        return 50
    if not value.isascii() or not value.isdecimal():
        raise ValueError("limit must be an integer from 1 to 100")
    limit = int(value)
    if not 1 <= limit <= 100:
        raise ValueError("limit must be an integer from 1 to 100")
    return limit


def _hold_payload(hold: Any) -> dict[str, Any]:
    payload = asdict(hold)
    if hold.expired_at is not None:
        payload["state"] = "expired"
    elif hold.captured_transaction_id is not None:
        payload["state"] = "captured"
    elif hold.active:
        payload["state"] = "active"
    else:
        payload["state"] = "released"
    return payload


def create_app(
    ledger: Ledger,
    *,
    api_token: str | None = None,
    audit_rate_limit: int = 120,
    rate_window_seconds: int = 60,
    rate_clock: Callable[[], float] | None = None,
    access_logger: AccessLogger | None = None,
    request_id_factory: Callable[[], str] | None = None,
) -> Callable[[dict[str, Any], StartResponse], Iterable[bytes]]:
    """Create a read-only WSGI app with auth, rate limits, and access records."""

    if api_token is not None and (
        not api_token
        or not api_token.isascii()
        or any(not 33 <= ord(char) <= 126 for char in api_token)
    ):
        raise ValueError(
            "api_token must be non-empty ASCII with no whitespace or control characters"
        )

    make_request_id = request_id_factory or (lambda: secrets.token_hex(16))
    rate_limiter = _FixedWindowRateLimiter(
        audit_rate_limit,
        rate_window_seconds,
        rate_clock or time.monotonic,
    )

    def dispatch(
        environ: dict[str, Any], start_response: StartResponse
    ) -> Iterable[bytes]:
        path = environ.get("PATH_INFO", "")
        if path != "/health":
            allowed, retry_after = rate_limiter.allow()
            if not allowed:
                return _json_response(
                    start_response,
                    "429 Too Many Requests",
                    {"error": "audit request rate limit exceeded"},
                    [("Retry-After", str(retry_after))],
                )

        if path != "/health" and api_token is not None:
            expected = f"Bearer {api_token}"
            supplied = environ.get("HTTP_AUTHORIZATION", "")
            if (
                not isinstance(supplied, str)
                or not supplied.isascii()
                or not hmac.compare_digest(supplied, expected)
            ):
                return _json_response(
                    start_response,
                    "401 Unauthorized",
                    {"error": "unauthorized"},
                    [("WWW-Authenticate", 'Bearer realm="ledger-audit"')],
                )

        if environ.get("REQUEST_METHOD") != "GET":
            response = _json_response(
                start_response, "405 Method Not Allowed", {"error": "method not allowed"}
            )
            return response

        try:
            if path == "/health":
                if environ.get("QUERY_STRING"):
                    raise ValueError("health endpoint does not accept query parameters")
                return _json_response(start_response, "200 OK", {"status": "ok"})

            if path == "/transactions":
                query = _query(environ, {"limit", "after", "account"})
                page = ledger.transactions(
                    limit=_limit(query.get("limit")),
                    after=query.get("after"),
                    account=query.get("account"),
                )
                return _json_response(
                    start_response,
                    "200 OK",
                    {
                        "transactions": [asdict(item) for item in page.transactions],
                        "next_cursor": page.next_cursor,
                    },
                )

            if path.startswith("/transactions/"):
                if environ.get("QUERY_STRING"):
                    raise ValueError("transaction endpoint does not accept query parameters")
                transaction_id = path.removeprefix("/transactions/")
                if not transaction_id or "/" in transaction_id:
                    return _json_response(
                        start_response, "404 Not Found", {"error": "not found"}
                    )
                transaction = ledger.transaction(transaction_id)
                if transaction is None:
                    return _json_response(
                        start_response, "404 Not Found", {"error": "transaction not found"}
                    )
                return _json_response(start_response, "200 OK", asdict(transaction))

            if path == "/holds":
                query = _query(environ, {"limit", "after", "account", "state"})
                page = ledger.holds(
                    limit=_limit(query.get("limit")),
                    after=query.get("after"),
                    account=query.get("account"),
                    state=query.get("state"),
                )
                return _json_response(
                    start_response,
                    "200 OK",
                    {
                        "holds": [_hold_payload(item) for item in page.holds],
                        "next_cursor": page.next_cursor,
                    },
                )

            if path.startswith("/holds/"):
                if environ.get("QUERY_STRING"):
                    raise ValueError("hold endpoint does not accept query parameters")
                hold_id = path.removeprefix("/holds/")
                if not hold_id or "/" in hold_id:
                    return _json_response(
                        start_response, "404 Not Found", {"error": "not found"}
                    )
                hold = ledger.hold(hold_id)
                if hold is None:
                    return _json_response(
                        start_response, "404 Not Found", {"error": "hold not found"}
                    )
                return _json_response(start_response, "200 OK", _hold_payload(hold))

            return _json_response(start_response, "404 Not Found", {"error": "not found"})
        except ValueError as error:
            return _json_response(
                start_response, "400 Bad Request", {"error": str(error)}
            )

    def app(environ: dict[str, Any], start_response: StartResponse) -> Iterable[bytes]:
        request_id = _request_id(make_request_id())
        status_code = 500

        def correlated_start_response(
            status: str, headers: list[tuple[str, str]]
        ) -> Any:
            nonlocal status_code
            try:
                status_code = int(status.split(" ", 1)[0])
            except (ValueError, IndexError):
                status_code = 500
            return start_response(status, headers + [("X-Request-ID", request_id)])

        try:
            return dispatch(environ, correlated_start_response)
        finally:
            if access_logger is not None:
                method = environ.get("REQUEST_METHOD")
                access_logger(
                    {
                        "event": "audit_http_access",
                        "method": method if method in {"GET", "POST"} else "OTHER",
                        "request_id": request_id,
                        "route": _route(environ.get("PATH_INFO", "")),
                        "status": status_code,
                    }
                )

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local read-only ledger audit API")
    parser.add_argument("database", help="path to the synthetic SQLite ledger")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument(
        "--api-token-env",
        metavar="NAME",
        help="protect audit routes with a bearer token read from environment variable NAME",
    )
    parser.add_argument(
        "--audit-rate-limit",
        type=int,
        default=120,
        help="maximum non-health requests per process-local window (default: 120)",
    )
    parser.add_argument(
        "--rate-window-seconds",
        type=int,
        default=60,
        help="process-local rate-limit window in seconds (default: 60)",
    )
    arguments = parser.parse_args()
    if not 1 <= arguments.port <= 65535:
        parser.error("--port must be from 1 to 65535")

    api_token = None
    if arguments.api_token_env is not None:
        api_token = os.environ.get(arguments.api_token_env)
        if not api_token:
            parser.error(f"environment variable {arguments.api_token_env!r} is missing or empty")

    try:
        app = create_app(
            Ledger(arguments.database),
            api_token=api_token,
            audit_rate_limit=arguments.audit_rate_limit,
            rate_window_seconds=arguments.rate_window_seconds,
            access_logger=_stderr_access_logger,
        )
    except ValueError as error:
        parser.error(str(error))
    with make_server(arguments.host, arguments.port, app) as server:
        print(f"Serving read-only synthetic audit API on {arguments.host}:{arguments.port}")
        server.serve_forever()


if __name__ == "__main__":
    main()
