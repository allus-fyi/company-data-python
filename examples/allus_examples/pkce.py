"""PKCE (RFC 7636) verifier + S256 challenge — pure local crypto, no network.

The SDK takes the ``code_challenge`` into
:meth:`allus_company_data.OAuthClient.authorize_url` and the ``code_verifier``
into :meth:`allus_company_data.OAuthClient.complete_sign_in`; the demo generates
the pair (mirrors the PHP reference ``Pkce``).
"""

from __future__ import annotations

import base64
import hashlib
import os
from typing import Tuple


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def generate() -> Tuple[str, str]:
    """Return ``(verifier, challenge)`` — a fresh S256 PKCE pair."""
    verifier = _b64url(os.urandom(32))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge
