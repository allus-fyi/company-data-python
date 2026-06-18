"""OAuth token + HTTP layer.

The :class:`HttpClient` is the thin transport every higher layer goes through.
It owns:

* **Auth** — ``client_credentials`` only. On the first call (or when the cached
  token is near expiry) it POSTs ``client_id``/``client_secret`` to
  ``{api_url}/oauth2/token`` and caches the bearer token + its expiry. Refresh is
  automatic and transparent; a 401 mid-flight triggers exactly one
  refresh-and-retry, then surfaces as :class:`AuthError`.
* **Format** — sets ``Accept`` per ``config.format`` (``application/json`` or
  ``application/xml``) and parses the body accordingly. The XML parser mirrors
  the platform serializer: a ``<response>`` root, int-keyed lists rendered as
  repeated ``<item>`` tags, and scalars as text (booleans as
  ``"true"``/``"false"``).
* **Errors** — maps non-2xx to the error taxonomy: a 401 → refresh+retry then
  :class:`AuthError`; a 429 → read ``Retry-After`` and back off + retry a bounded
  number of times, then :class:`RateLimitError`; any other non-2xx →
  :class:`ApiError` carrying the body's ``error_key`` when present.

Config-only key handling: the client id/secret come from the
:class:`~allus_company_data.config.Config` — never a method argument.
"""

from __future__ import annotations

import time
import xml.etree.ElementTree as ET
from typing import Any, Optional

import requests

from .config import Config
from .errors import ApiError, AuthError, RateLimitError

# Refresh the token a little before it actually expires so an in-flight call
# never races the expiry boundary.
_TOKEN_EXPIRY_SKEW_S = 30.0

# 429 backoff policy: bounded retries with a Retry-After-driven (or default)
# sleep between attempts. Connections endpoints are heavily limited, so after
# the bounded retries we surface RateLimitError rather than hammering.
_DEFAULT_MAX_RETRIES_429 = 3
_DEFAULT_BACKOFF_S = 1.0
_MAX_BACKOFF_S = 60.0


class HttpClient:
    """Authenticated JSON/XML transport for the company-data API."""

    def __init__(
        self,
        config: Config,
        session: Optional[requests.Session] = None,
        *,
        sleep=time.sleep,
        clock=time.monotonic,
        max_retries_429: int = _DEFAULT_MAX_RETRIES_429,
    ) -> None:
        self._config = config
        # An injectable session keeps the client unit-testable without the live
        # API (the tests pass a fake session); otherwise a real requests.Session.
        self._session = session if session is not None else requests.Session()
        self._sleep = sleep
        self._clock = clock
        self._max_retries_429 = max_retries_429

        self._api_url = config.api_url.rstrip("/")
        self._token: Optional[str] = None
        self._token_expiry: float = 0.0  # monotonic clock deadline

    # ── auth ────────────────────────────────────────────────────────────────

    def _token_valid(self) -> bool:
        return self._token is not None and self._clock() < self._token_expiry

    def _fetch_token(self) -> str:
        """POST the client credentials to ``/oauth2/token`` and cache the result."""
        url = f"{self._api_url}/oauth2/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": self._config.client_id,
            "client_secret": self._config.client_secret,
        }
        try:
            resp = self._session.post(
                url,
                data=data,
                headers={"Accept": "application/json"},
            )
        except requests.RequestException as exc:  # network failure
            raise AuthError(f"token request failed: {exc}") from exc

        status = resp.status_code
        if status < 200 or status >= 300:
            error_key, message = _extract_error(resp)
            raise AuthError(
                f"token request rejected (HTTP {status})"
                + (f" [{error_key}]" if error_key else "")
                + (f": {message}" if message else "")
            )

        try:
            body = resp.json()
        except ValueError as exc:
            raise AuthError("token response was not valid JSON") from exc
        access_token = body.get("access_token") if isinstance(body, dict) else None
        if not access_token:
            raise AuthError("token response missing access_token")

        # expires_in is seconds from now (standard OAuth2). Cache against the
        # monotonic clock with a small skew so we refresh just before expiry.
        try:
            expires_in = float(body.get("expires_in", 3600))
        except (TypeError, ValueError):
            expires_in = 3600.0
        self._token = str(access_token)
        self._token_expiry = self._clock() + max(0.0, expires_in - _TOKEN_EXPIRY_SKEW_S)
        return self._token

    def _bearer(self, force_refresh: bool = False) -> str:
        if force_refresh or not self._token_valid():
            return self._fetch_token()
        assert self._token is not None
        return self._token

    # ── requests ──────────────────────────────────────────────────────────

    def get(self, path: str, params: Optional[dict] = None) -> Any:
        """GET ``path`` (e.g. ``/api/company-data/connections``) → parsed body.

        Adds the bearer token + an ``Accept`` header matching ``config.format``,
        parses JSON or XML, and maps non-2xx responses to the SDK errors:
        401 → one refresh-and-retry then :class:`AuthError`; 429 → bounded
        Retry-After backoff then :class:`RateLimitError`; other non-2xx →
        :class:`ApiError` (carrying the body's ``error_key`` when present).
        """
        url = self._url(path)
        wants_xml = self._config.format == "xml"
        accept = "application/xml" if wants_xml else "application/json"

        retries_429 = 0
        refreshed_401 = False
        while True:
            token = self._bearer(force_refresh=False)
            try:
                resp = self._session.get(
                    url,
                    params=params,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": accept,
                    },
                )
            except requests.RequestException as exc:
                raise ApiError(0, None, f"request to {path} failed: {exc}") from exc

            status = resp.status_code

            if 200 <= status < 300:
                return self._parse_body(resp, wants_xml)

            if status == 401:
                # One refresh-and-retry, then give up as AuthError.
                if not refreshed_401:
                    refreshed_401 = True
                    self._bearer(force_refresh=True)
                    continue
                error_key, message = _extract_error(resp)
                raise AuthError(
                    "unauthorized after token refresh"
                    + (f" [{error_key}]" if error_key else "")
                    + (f": {message}" if message else "")
                )

            if status == 429:
                retry_after = _parse_retry_after(resp)
                if retries_429 < self._max_retries_429:
                    retries_429 += 1
                    self._sleep(_backoff_delay(retry_after, retries_429))
                    continue
                error_key, message = _extract_error(resp)
                raise RateLimitError(retry_after, error_key, message)

            # Any other non-2xx → ApiError with the body's error_key.
            error_key, message = _extract_error(resp)
            raise ApiError(status, error_key, message)

    def _url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return self._api_url + ("" if path.startswith("/") else "/") + path

    def _parse_body(self, resp: "requests.Response", wants_xml: bool) -> Any:
        text = resp.text
        if text is None or text.strip() == "":
            return {}
        if wants_xml:
            return _parse_xml(text)
        try:
            return resp.json()
        except ValueError as exc:
            raise ApiError(
                resp.status_code, None, f"response was not valid JSON: {exc}"
            ) from exc


# ── module-level helpers ─────────────────────────────────────────────────────


def _extract_error(resp: "requests.Response") -> tuple[Optional[str], Optional[str]]:
    """Pull ``error_key`` + a message out of a non-2xx body (JSON or XML)."""
    try:
        body = resp.json()
    except ValueError:
        # Maybe an XML error envelope; try a best-effort parse, else fall back.
        try:
            body = _parse_xml(resp.text)
        except Exception:  # pragma: no cover - truly opaque body
            return None, (resp.text or None)
    if isinstance(body, dict):
        error_key = body.get("error_key")
        message = body.get("error") or body.get("message")
        return (
            str(error_key) if error_key is not None else None,
            str(message) if message is not None else None,
        )
    return None, None


def _parse_retry_after(resp: "requests.Response") -> Optional[float]:
    """Parse the ``Retry-After`` header (delta-seconds form) → float seconds."""
    raw = resp.headers.get("Retry-After")
    if raw is None:
        return None
    raw = raw.strip()
    try:
        return float(raw)
    except ValueError:
        # An HTTP-date Retry-After is allowed by spec but the platform sends
        # delta-seconds; if we ever get a date, fall back to None (default backoff).
        return None


def _backoff_delay(retry_after: Optional[float], attempt: int) -> float:
    """Sleep duration before the next 429 retry.

    Honor ``Retry-After`` when present; otherwise exponential backoff capped at
    ``_MAX_BACKOFF_S``.
    """
    if retry_after is not None and retry_after >= 0:
        return min(retry_after, _MAX_BACKOFF_S)
    return min(_DEFAULT_BACKOFF_S * (2 ** (attempt - 1)), _MAX_BACKOFF_S)


def _parse_xml(text: str) -> Any:
    """Parse the platform's XML serialization back into Python data.

    Mirrors the platform serializer:

    * the document root is ``<response>``;
    * a PHP list (int keys) renders as repeated ``<item>`` children — so an
      element whose every child is ``<item>`` becomes a Python list;
    * an associative array renders as named child tags — a Python dict;
    * scalars are element text; booleans were written as ``"true"``/``"false"``.

    This is the minimal inverse needed for the company-data payloads (which are
    dicts of lists of dicts of scalars). It is intentionally small — JSON is the
    default wire format; XML is the opt-in alternative.
    """
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ApiError(0, None, f"response was not valid XML: {exc}") from exc
    return _xml_element_to_py(root)


def _xml_element_to_py(elem: ET.Element) -> Any:
    children = list(elem)
    if not children:
        # A leaf node: its text (or empty string). Callers coerce types from the
        # known schema; we keep the raw string (booleans came over as "true"/"false").
        return elem.text if elem.text is not None else ""

    # All children are <item> → a list (PHP int-keyed array).
    if all(child.tag == "item" for child in children):
        return [_xml_element_to_py(child) for child in children]

    # Otherwise an object: named tags → dict keys. Repeated tags collapse to a list.
    result: dict[str, Any] = {}
    for child in children:
        value = _xml_element_to_py(child)
        if child.tag in result:
            existing = result[child.tag]
            if isinstance(existing, list):
                existing.append(value)
            else:
                result[child.tag] = [existing, value]
        else:
            result[child.tag] = value
    return result
