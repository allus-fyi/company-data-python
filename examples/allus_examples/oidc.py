"""Scenarios 5 & 6 — standard OIDC login via a REAL third-party OIDC client.

This is a compliance demo: the point is that the identity leg goes through
an actual, well-known OIDC library rather than the allus SDK's bespoke OAuth
helper. We use **Authlib** (``authlib.integrations.requests_client.OAuth2Session``
+ ``authlib.jose`` for id_token verification). Authlib is declared ONLY in this
example's ``requirements.txt`` and is NOT a dependency of the published
``allus-company-data`` SDK package.

The library is driven with:
* discovery (``/.well-known/openid-configuration``) — issuer override supported,
* PKCE S256,
* ``client_secret_post`` token-endpoint auth,
* signed ``id_token`` verification (issuer + audience + nonce) against the JWKS.
"""

from __future__ import annotations

from typing import Any, Dict

import requests
from authlib.integrations.requests_client import OAuth2Session
from authlib.jose import jwt
from authlib.oidc.core import CodeIDToken

_SCOPE = "openid profile email"
_DISCOVERY_TIMEOUT = 5.0


class OidcClient:
    """A thin wrapper over Authlib's OAuth2Session for the two OIDC scenarios."""

    def __init__(self, issuer: str, client_id: str, client_secret: str, redirect_uri: str) -> None:
        self.issuer = (issuer or "").rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self._meta: Dict[str, Any] | None = None

    def _metadata(self) -> Dict[str, Any]:
        if self._meta is None:
            url = f"{self.issuer}/.well-known/openid-configuration"
            resp = requests.get(url, timeout=_DISCOVERY_TIMEOUT)
            resp.raise_for_status()
            self._meta = resp.json()
        return self._meta

    def _session(self) -> OAuth2Session:
        return OAuth2Session(
            client_id=self.client_id,
            client_secret=self.client_secret,
            redirect_uri=self.redirect_uri,
            scope=_SCOPE,
            code_challenge_method="S256",
            token_endpoint_auth_method="client_secret_post",
        )

    def authorization_url(self, state: str, nonce: str, code_verifier: str) -> str:
        """Build the OIDC authorization request URL (discovery + PKCE S256)."""
        meta = self._metadata()
        sess = self._session()
        uri, _ = sess.create_authorization_url(
            meta["authorization_endpoint"],
            state=state,
            nonce=nonce,
            code_verifier=code_verifier,
        )
        return uri

    def complete(self, code: str, state: str, code_verifier: str, nonce: str) -> Dict[str, Any]:
        """Exchange the code (client_secret_post) and verify the id_token; return its claims."""
        meta = self._metadata()
        sess = self._session()
        token = sess.fetch_token(
            meta["token_endpoint"],
            code=code,
            state=state,
            code_verifier=code_verifier,
        )
        id_token = token.get("id_token")
        if not id_token:
            raise ValueError("token response contained no id_token")
        claims = self._verify_id_token(id_token, meta, nonce)
        return dict(claims)

    def _verify_id_token(self, id_token: str, meta: Dict[str, Any], nonce: str) -> Any:
        jwks = requests.get(meta["jwks_uri"], timeout=_DISCOVERY_TIMEOUT).json()
        claims_options = {
            "iss": {"essential": True, "value": meta.get("issuer", self.issuer)},
            "aud": {"essential": True, "value": self.client_id},
        }
        claims = jwt.decode(
            id_token,
            jwks,
            claims_cls=CodeIDToken,
            claims_options=claims_options,
            claims_params={"nonce": nonce},
        )
        claims.validate()
        return claims
