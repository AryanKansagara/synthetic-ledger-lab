"""Dependency-free read-only HTTP adapter for synthetic ledger audit data."""

import argparse
import json
from collections.abc import Callable, Iterable
from dataclasses import asdict
from typing import Any
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server

from synthetic_ledger_lab.ledger import Ledger

StartResponse = Callable[[str, list[tuple[str, str]]], Any]


def _json_response(
    start_response: StartResponse, status: str, payload: dict[str, Any]
) -> list[bytes]:
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    start_response(
        status,
        [
            ("Content-Type", "application/json; charset=utf-8"),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
        ],
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


def create_app(ledger: Ledger) -> Callable[[dict[str, Any], StartResponse], Iterable[bytes]]:
    """Create a read-only WSGI app over one ledger instance."""

    def app(environ: dict[str, Any], start_response: StartResponse) -> Iterable[bytes]:
        if environ.get("REQUEST_METHOD") != "GET":
            response = _json_response(
                start_response, "405 Method Not Allowed", {"error": "method not allowed"}
            )
            return response

        path = environ.get("PATH_INFO", "")
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

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local read-only ledger audit API")
    parser.add_argument("database", help="path to the synthetic SQLite ledger")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    arguments = parser.parse_args()
    if not 1 <= arguments.port <= 65535:
        parser.error("--port must be from 1 to 65535")

    app = create_app(Ledger(arguments.database))
    with make_server(arguments.host, arguments.port, app) as server:
        print(f"Serving read-only synthetic audit API on {arguments.host}:{arguments.port}")
        server.serve_forever()


if __name__ == "__main__":
    main()
