"""Shared HTTP plumbing for the single-server example suite.

The pieces every family's handlers need but that are NOT the SDK example itself:
the tiny :class:`Response` value, the JSON/text/redirect response builders, the
request-body / query helpers, a static-file MIME map, and the network-timeout
``requests.Session`` the short-cycled polls inject into the SDK so one blackholed
request cannot pin the single worker. Kept deliberately small — the teaching
material is the per-family handler files, not this scaffolding.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

import requests


class Response:
    __slots__ = ("status", "headers", "body")

    def __init__(self, status: int, headers: Dict[str, str], body: bytes) -> None:
        self.status = status
        self.headers = headers
        self.body = body


class TimeoutSession(requests.Session):
    """A ``requests.Session`` that applies a default network timeout to every call —
    injected into the SDK clients used by the short-cycled polls / webhook feed
    fallback so one blackholed request cannot pin the single-worker server."""

    def __init__(self, timeout: float) -> None:
        super().__init__()
        self._timeout = timeout

    def request(self, *args: Any, **kwargs: Any):  # type: ignore[override]
        kwargs.setdefault("timeout", self._timeout)
        return super().request(*args, **kwargs)


def json_response(data: Any, status: int = 200) -> Response:
    body = json.dumps(data).encode("utf-8")
    return Response(status, {"Content-Type": "application/json"}, body)


def failure_response(
    reason: Any, token: str = "server_error", status: int = 500
) -> Response:
    """The contract's FAILURE envelope: ``{"error": "<token> — <reason>", "message": <reason>}``.

    The suite's shared frontend client raises the ``error`` value VERBATIM and ignores every
    other key, so a bare token in ``error`` reaches the developer as one uninformative word and
    the REASON — which the backend has right there — is dropped: a failure converted into
    something indistinguishable from any other failure. The token is
    kept and the reason appended in the shape this contract already uses for exactly this
    (``no_origin — …``); ``message`` keeps the bare reason for a programmatic reader.

    ``reason`` may be an exception or a sentence. An exception with an EMPTY ``str()``
    (``KeyError()``, a bare ``RuntimeError()``) would otherwise report nothing at all, so its
    class name stands in.

    NOT used for the token-only refusals the suite handles by STATUS rather than body —
    ``409 not_configured`` (``startScenario`` maps the 409 before reading the body) and
    ``404 not_found``.
    """
    text = str(reason).strip()
    if not text and isinstance(reason, BaseException):
        text = type(reason).__name__
    return json_response(
        {"error": token + " — " + (text or "no reason was reported"), "message": text}, status
    )


def text_response(body: str, status: int = 200) -> Response:
    return Response(status, {"Content-Type": "text/plain; charset=utf-8"}, body.encode("utf-8"))


def redirect(location: str) -> Response:
    return Response(302, {"Location": location}, b"")


def parse_body(raw: bytes) -> Dict[str, Any]:
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def query_one(query: Dict[str, List[str]], key: str) -> str:
    values = query.get(key)
    return values[0] if values else ""


def header(headers: Dict[str, str], name: str) -> "str | None":
    target = name.lower()
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == target:
            return value
    return None


def jsonable(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, dict)):
        return value
    return str(value)  # dates / BinaryHandle / etc.


def mime(path: str) -> str:
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    return {
        "html": "text/html; charset=utf-8",
        "js": "text/javascript; charset=utf-8",
        "mjs": "text/javascript; charset=utf-8",
        "css": "text/css; charset=utf-8",
        "json": "application/json; charset=utf-8",
        "map": "application/json; charset=utf-8",
        "svg": "image/svg+xml",
        "png": "image/png",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "gif": "image/gif",
        "ico": "image/x-icon",
        "woff": "font/woff",
        "woff2": "font/woff2",
        "ttf": "font/ttf",
        "webp": "image/webp",
    }.get(ext, "application/octet-stream")
