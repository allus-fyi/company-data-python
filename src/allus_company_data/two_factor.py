"""#436 2FA-by-allme — the relying-party challenge API (spec §3).

On the SERVICE's data-client credentials (the same auth :class:`Client` uses). A service asks a person
(by ``share_code``) to approve a login inside the allme app, then polls for the outcome. The poll is the
record: the first read of a terminal state delivers it and burns it (a later read is ``gone``). A webhook
(``2fa_challenge_completed``) is the best-effort push equivalent; the poll remains authoritative.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import quote

from .errors import ApiError
from .http import HttpClient


@dataclass(frozen=True)
class TwoFactorChallenge:
    """A login-approval challenge returned by :meth:`TwoFactorClient.challenge`."""

    challenge_id: str
    status: str
    expires_at: str
    #: Present only when number matching is on — the two digits to DISPLAY on your login page. The
    #: person types them back into the allme app; the SERVER adjudicates them (they never leave here).
    matching_digits: Optional[str]

    @classmethod
    def from_api(cls, obj: dict) -> "TwoFactorChallenge":
        md = obj.get("matching_digits")
        return cls(
            challenge_id=str(obj.get("challenge_id") or ""),
            status=str(obj.get("status") or ""),
            expires_at=str(obj.get("expires_at") or ""),
            matching_digits=str(md) if md is not None else None,
        )


@dataclass(frozen=True)
class TwoFactorResult:
    """The outcome of :meth:`TwoFactorClient.result`."""

    #: pending | approved | denied | expired | revoked | gone (already consumed / TTL passed).
    status: str
    expires_at: Optional[str]
    completed_at: Optional[str]

    @classmethod
    def from_api(cls, obj: dict) -> "TwoFactorResult":
        return cls(
            status=str(obj.get("status") or ""),
            expires_at=str(obj["expires_at"]) if obj.get("expires_at") is not None else None,
            completed_at=str(obj["completed_at"]) if obj.get("completed_at") is not None else None,
        )


class TwoFactorClient:
    """Reached via :attr:`Client.two_factor`."""

    def __init__(self, http: HttpClient, *, sleep: Callable[[float], None] = time.sleep) -> None:
        self._http = http
        # Injectable so wait_for_result is unit-testable without real delays (matches OAuthClient).
        self._sleep = sleep

    def challenge(
        self, share_code: str, idempotency_key: str, context: Optional[str] = None
    ) -> TwoFactorChallenge:
        """Initiate a login-approval challenge.

        ``idempotency_key`` is required (<=64); a repeat within the TTL returns the SAME challenge and
        sends no second push. ``context`` is plain text shown to the person (<=200 chars).
        """
        body = self._http.post(
            "/api/service-2fa/challenges",
            json_body={
                "share_code": share_code,
                "context": context,
                "idempotency_key": idempotency_key,
            },
        )
        return TwoFactorChallenge.from_api(body if isinstance(body, dict) else {})

    def result(self, challenge_id: str) -> TwoFactorResult:
        """Poll a challenge. While pending, ``status`` is ``pending``; the first terminal read burns it."""
        body = self._http.get(f"/api/service-2fa/challenges/{quote(challenge_id, safe='')}")
        return TwoFactorResult.from_api(body if isinstance(body, dict) else {})

    def wait_for_result(
        self, challenge_id: str, timeout: float = 600, interval: float = 2
    ) -> TwoFactorResult:
        """Poll :meth:`result` until the status is terminal (no longer ``pending``) and return that
        first terminal :class:`TwoFactorResult`.

        Convenience over a manual :meth:`result` loop (#481; mirrors the §12c ``poll_result``
        precedent). Because the first terminal read burns the challenge, this returns as soon as the
        status leaves ``pending`` — it never re-reads a consumed result. Raises :class:`ApiError` if
        ``timeout`` seconds elapse while still pending; ``interval`` is the seconds between polls.
        """
        deadline = time.monotonic() + timeout
        while True:
            res = self.result(challenge_id)
            if res.status != "pending":
                return res
            if time.monotonic() >= deadline:
                raise ApiError(
                    0, None, f"2FA challenge {challenge_id} not completed within {timeout}s"
                )
            self._sleep(interval)
