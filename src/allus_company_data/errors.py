"""Error taxonomy — the same names across all six SDKs.

+--------------------------+--------------------------------------------------+
| Error                    | When                                             |
+==========================+==================================================+
| ConfigError              | Missing/invalid config or key file at            |
|                          | construction (fail fast).                        |
| AuthError                | Token fetch/refresh failed (bad client_id/       |
|                          | secret, revoked client).                         |
| ApiError(status,         | Any non-2xx from the API; carries the HTTP       |
|   error_key, message)    | status + the platform ``error_key`` + message.   |
| DecryptError             | Wrapper malformed, wrong key, or GCM tag         |
|                          | mismatch.                                        |
| WebhookError             | Signature verification failed or an envelope     |
|                          | couldn't be unwrapped.                           |
| RateLimitError(          | A 429 from a rate-limited endpoint (subclass of  |
|   retry_after)           | ApiError); carries ``Retry-After``.              |
+--------------------------+--------------------------------------------------+

``DecryptError`` is defined in :mod:`allus_company_data.crypto` (it is raised by
the decryption core) and re-exported here so the whole taxonomy is importable
from one module.
"""

from __future__ import annotations

from typing import Optional

# DecryptError lives with the decryption core; re-export it so callers can pull
# the full taxonomy from a single place.
from .crypto import DecryptError  # noqa: F401  (re-exported)


class ConfigError(Exception):
    """Missing or invalid configuration (or key file) at construction (fail fast).

    Canonical home for the error; :mod:`allus_company_data.config` re-exports it
    so ``from allus_company_data.config import ConfigError`` keeps working.
    """


class AuthError(Exception):
    """The ``client_credentials`` token fetch or refresh failed.

    Raised when ``/oauth2/token`` rejects the credentials, or when a 401 mid-flight
    survives the one automatic refresh-and-retry.
    """


class ApiError(Exception):
    """Any non-2xx from the API.

    Carries the HTTP ``status``, the platform ``error_key`` (when the body
    provided one), and a human-readable ``message``.
    """

    def __init__(
        self,
        status: int,
        error_key: Optional[str] = None,
        message: Optional[str] = None,
    ) -> None:
        self.status = status
        self.error_key = error_key
        self.message = message
        parts = [f"HTTP {status}"]
        if error_key:
            parts.append(f"({error_key})")
        if message:
            parts.append(f": {message}")
        super().__init__(" ".join(parts))


class WebhookError(Exception):
    """Signature verification failed, or a webhook envelope couldn't be unwrapped."""


class RateLimitError(ApiError):
    """A 429 from a rate-limited endpoint.

    Subclass of :class:`ApiError` with a fixed status of 429; carries the
    ``retry_after`` value parsed from the ``Retry-After`` response header (seconds,
    or ``None`` when absent).
    """

    def __init__(
        self,
        retry_after: Optional[float] = None,
        error_key: Optional[str] = None,
        message: Optional[str] = None,
    ) -> None:
        self.retry_after = retry_after
        super().__init__(429, error_key, message)


__all__ = [
    "ConfigError",
    "AuthError",
    "ApiError",
    "DecryptError",
    "WebhookError",
    "RateLimitError",
]
