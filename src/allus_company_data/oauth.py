"""``Sign in with allme`` — the RP-side OAuth client (#195).

A third-party site ("relying party") embeds a *Sign in with allme* button, sends the
person to the hosted consent screen, and — once the person approves — receives an
authorization code back at its redirect URI. This module wraps the RP half:

* :meth:`OAuthClient.authorize_url` builds the consent-screen URL (the button target),
* :meth:`OAuthClient.exchange_code` swaps the returned code for a token,
* :meth:`OAuthClient.userinfo` reads the signed-in identity (and any one_time values),
* :meth:`OAuthClient.complete_sign_in` chains both and DECRYPTS one_time values for you,
* :meth:`OAuthClient.poll_result` drives the ``detached`` response mode.

Config-only key handling still holds: the app private key + passphrase come from
:class:`~allus_company_data.config.Config` (the idw role), never a method argument.
"""

from __future__ import annotations

import json
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests

from .config import Config
from .crypto import decrypt, load_private_key
from .errors import ApiError, AuthError, ConfigError

# The hosted consent surface. The native apps claim this https link (universal/app
# link); the web app is the no-app fallback. Overridable for non-prod hosts.
DEFAULT_AUTHORIZE_URL = "https://web.allme.fyi/auth"

# Binary field types can't be requested as claims (they can't be encrypted inline).
_NON_CLAIMABLE = frozenset({"photo", "document", "legal_document"})
_MAX_CLAIMS = 15
_MODES = frozenset({"signin", "one_time", "connect"})
_RESPONSE_MODES = frozenset({"redirect", "detached"})


@dataclass
class Claim:
    """A single one_time claim the RP asks for: a field TYPE + an advisory suggestion."""

    type: str
    suggest: Optional[str] = None
    required: bool = False
    label: Optional[str] = None


class OAuthClient:
    """The RP-side "Sign in with allme" client.

    Construct from an idw-role config (:meth:`from_config` / :meth:`from_env`). A
    ``session`` may be injected for testing; otherwise a real ``requests.Session``.
    """

    def __init__(
        self,
        config: Config,
        session: Optional[requests.Session] = None,
        *,
        authorize_url: str = DEFAULT_AUTHORIZE_URL,
        sleep=time.sleep,
    ) -> None:
        if not config.oauth_client_id or not config.oauth_redirect_uri:
            raise ConfigError("OAuthClient requires oauth_client_id + oauth_redirect_uri (idw role)")
        self._config = config
        self._session = session if session is not None else requests.Session()
        self._api_url = config.api_url.rstrip("/")
        self._authorize_url = authorize_url
        self._sleep = sleep

    @classmethod
    def from_config(cls, path: str, **kwargs: Any) -> "OAuthClient":
        """Build from an idw-role JSON config file."""
        return cls(Config.from_idw_file(path), **kwargs)

    @classmethod
    def from_env(cls, **kwargs: Any) -> "OAuthClient":
        """Build from ``ALLUS_OAUTH_*`` env vars."""
        return cls(Config.from_idw_env(), **kwargs)

    # ── the button target ───────────────────────────────────────────────────

    def authorize_url(
        self,
        mode: str,
        *,
        claims: Optional[List[Claim]] = None,
        state: Optional[str] = None,
        response_mode: str = "redirect",
        code_challenge: Optional[str] = None,
        redirect_uri: Optional[str] = None,
    ) -> str:
        """Build the consent-screen URL — the "Sign in with allme" button target.

        ``mode`` is one of ``signin`` | ``one_time`` | ``connect``. ``claims`` (one_time)
        are validated: binary/unknown types are dropped and at most 15 are sent. Pass a
        PKCE ``code_challenge`` for a public RP; ``state`` is echoed back for CSRF.
        """
        if mode not in _MODES:
            raise ConfigError(f"invalid mode {mode!r} (expected one of {sorted(_MODES)})")
        if response_mode not in _RESPONSE_MODES:
            raise ConfigError(
                f"invalid response_mode {response_mode!r} (expected one of {sorted(_RESPONSE_MODES)})"
            )
        params: Dict[str, str] = {
            "client_id": self._config.oauth_client_id or "",
            "redirect_uri": redirect_uri or self._config.oauth_redirect_uri or "",
            "mode": mode,
            "response_mode": response_mode,
        }
        if state is not None:
            params["state"] = state
        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"
        cleaned = self._clean_claims(claims) if claims else []
        if cleaned:
            params["claims"] = json.dumps(cleaned, separators=(",", ":"))
        return self._authorize_url + "?" + urllib.parse.urlencode(params)

    @staticmethod
    def _clean_claims(claims: List[Claim]) -> List[dict]:
        out: List[dict] = []
        for c in claims:
            if not c.type or c.type in _NON_CLAIMABLE:
                continue
            entry: Dict[str, Any] = {"type": c.type}
            if c.suggest:
                entry["suggest"] = c.suggest
            if c.required:
                entry["required"] = True
            if c.label:
                entry["label"] = c.label
            out.append(entry)
            if len(out) >= _MAX_CLAIMS:
                break
        return out

    # ── code → token → identity ─────────────────────────────────────────────

    def exchange_code(self, code: str, code_verifier: Optional[str] = None) -> dict:
        """Swap the authorization ``code`` for a token (POST ``/oauth2/token``).

        Sends the PKCE ``code_verifier`` and/or the confidential client secret from
        config. Returns the token response (``access_token``, ``mode``, …).
        """
        data = {
            "grant_type": "authorization_code",
            "client_id": self._config.oauth_client_id,
            "code": code,
            "redirect_uri": self._config.oauth_redirect_uri,
        }
        if code_verifier:
            data["code_verifier"] = code_verifier
        if self._config.oauth_client_secret:
            data["client_secret"] = self._config.oauth_client_secret
        return self._post_form("/oauth2/token", data, what="token exchange")

    def userinfo(self, access_token: str) -> dict:
        """Read the signed-in identity (GET ``/api/oauth/userinfo``) with the RP token.

        Returns ``{sub, share_code, display_name, mode, two_factor, values?}`` — ``values``
        (one_time) are the raw app-key ciphertext wrappers; :meth:`complete_sign_in`
        decrypts them for you.
        """
        url = f"{self._api_url}/api/oauth/userinfo"
        try:
            resp = self._session.get(
                url, headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
            )
        except requests.RequestException as exc:
            raise ApiError(0, None, f"userinfo request failed: {exc}") from exc
        return self._parse(resp, "userinfo")

    def complete_sign_in(self, code: str, code_verifier: Optional[str] = None) -> dict:
        """Exchange + userinfo in one call, decrypting one_time values.

        Returns ``{"user": {...}, "mode": str, "values": {slug: plaintext}}``. Decryption
        uses the app private key from config (oauth_private_key + oauth_key_passphrase) —
        required only when the mode is ``one_time`` and values are present.
        """
        token = self.exchange_code(code, code_verifier)
        access_token = token.get("access_token")
        if not access_token:
            raise AuthError("token exchange returned no access_token")
        info = self.userinfo(str(access_token))
        mode = info.get("mode") or token.get("mode")
        result: Dict[str, Any] = {
            "user": {k: info.get(k) for k in ("sub", "share_code", "display_name")},
            "mode": mode,
            "two_factor": bool(info.get("two_factor")),
            "values": {},
        }
        raw_values = info.get("values")
        if raw_values:
            result["values"] = self._decrypt_values(raw_values)
        return result

    def _decrypt_values(self, raw_values: dict) -> Dict[str, str]:
        if not self._config.oauth_private_key or not self._config.oauth_key_passphrase:
            raise ConfigError(
                "one_time values present but oauth_private_key / oauth_key_passphrase not configured"
            )
        with open(self._config.oauth_private_key, "rb") as fh:
            pem = fh.read()
        private_key = load_private_key(pem, self._config.oauth_key_passphrase)
        out: Dict[str, str] = {}
        for slug, wrapper in raw_values.items():
            out[slug] = decrypt(wrapper, private_key)
        return out

    # ── detached mode ───────────────────────────────────────────────────────

    def poll_result(self, state: str, *, timeout: float = 600, interval: float = 2) -> dict:
        """Poll ``/oauth2/result`` for a detached sign-in (single-delivery).

        Loops on HTTP 202 (pending) until the code arrives (200 → returns ``{code, state}``),
        the result expires (410 → :class:`ApiError`), or ``timeout`` seconds elapse
        (:class:`ApiError`).
        """
        data: Dict[str, str] = {"client_id": self._config.oauth_client_id or "", "state": state}
        if self._config.oauth_client_secret:
            data["client_secret"] = self._config.oauth_client_secret
        url = f"{self._api_url}/oauth2/result"
        deadline = time.monotonic() + timeout
        while True:
            try:
                resp = self._session.post(url, data=data, headers={"Accept": "application/json"})
            except requests.RequestException as exc:
                raise ApiError(0, None, f"result poll failed: {exc}") from exc
            status = resp.status_code
            if status == 200:
                body = self._json(resp)
                if body.get("code"):
                    return body
            elif status == 410:
                raise ApiError(410, "oauth.result_expired", "detached sign-in expired before completion")
            elif status not in (202,):
                key, msg = _err(resp)
                raise ApiError(status, key, msg or f"result poll rejected (HTTP {status})")
            if time.monotonic() >= deadline:
                raise ApiError(0, None, f"detached sign-in not completed within {timeout}s")
            self._sleep(interval)

    # ── helpers ─────────────────────────────────────────────────────────────

    def _post_form(self, path: str, data: dict, *, what: str) -> dict:
        url = f"{self._api_url}{path}"
        try:
            resp = self._session.post(url, data=data, headers={"Accept": "application/json"})
        except requests.RequestException as exc:
            raise ApiError(0, None, f"{what} request failed: {exc}") from exc
        return self._parse(resp, what)

    def _parse(self, resp: "requests.Response", what: str) -> dict:
        status = resp.status_code
        if 200 <= status < 300:
            return self._json(resp)
        key, msg = _err(resp)
        if status in (401, 403):
            raise AuthError(f"{what} rejected (HTTP {status})" + (f" [{key}]" if key else "") + (f": {msg}" if msg else ""))
        raise ApiError(status, key, msg or f"{what} rejected (HTTP {status})")

    @staticmethod
    def _json(resp: "requests.Response") -> dict:
        try:
            body = resp.json()
        except ValueError:
            return {}
        return body if isinstance(body, dict) else {}


def _err(resp: "requests.Response") -> tuple[Optional[str], Optional[str]]:
    try:
        body = resp.json()
    except ValueError:
        return None, None
    if not isinstance(body, dict):
        return None, None
    return body.get("error_key"), body.get("error")
