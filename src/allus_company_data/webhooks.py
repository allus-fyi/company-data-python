"""Webhook receiver helpers.

The lower-latency push alternative to polling the changes feed. The platform
delivers each change event to the company's configured webhook URL with:

* ``X-Allus-Webhook-Id``  — which webhook this is (selects the HMAC secret).
* ``X-Allus-Signature``   — ``HMAC-SHA256(rawBody, secret)`` as lowercase hex.
* the body — the same slug-keyed :class:`Change` shape as the pull feed,
  JSON or XML. If the webhook has ``encrypt_payload`` on, the body is REPLACED
  by a ``{"_enc":1,...}`` envelope encrypted to the company **account** key (and
  the HMAC is then over that envelope — it is the final body that was sent).

All secrets/keys come from :class:`~allus_company_data.config.Config`.
**These helpers take NO key or secret arguments** — only the raw body, the
headers, the config, and (for value typing) the same decrypt/type closures the
:class:`~allus_company_data.client.Client` already holds.

The account-key envelope is webhook-specific: the platform wraps it with
OpenSSL's DEFAULT OAEP padding (MGF1-**SHA1**), NOT the SHA-256 wrapper used for
person field values. So unwrapping the envelope uses an OAEP-SHA1 path here,
while the inner field ``value`` (still a service-key wrapper) decrypts with the
normal SHA-256 :func:`crypto.decrypt`.
"""

from __future__ import annotations

import base64
import hmac
import json
from hashlib import sha256
from typing import Any, Callable, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import Config
from .crypto import GCM_IV_LEN, GCM_TAG_LEN, load_private_key
from .errors import WebhookError
from .http import _parse_xml  # reuse the platform XML inverse
from .models import Change

# Header names (case-insensitive lookup below).
_HDR_WEBHOOK_ID = "x-allus-webhook-id"
_HDR_SIGNATURE = "x-allus-signature"

# Account-key envelope marker key.
_ENC_MARKER = "_enc"


# ── header helpers ─────────────────────────────────────────────────────────────


def _header(headers: dict, name: str) -> Optional[str]:
    """Case-insensitive header lookup (frameworks normalize casing inconsistently)."""
    if not headers:
        return None
    target = name.lower()
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == target:
            return value if isinstance(value, str) else (str(value) if value is not None else None)
    return None


def _as_bytes(raw_body: Any) -> bytes:
    """Coerce the raw body to bytes (HMAC + parsing both need the exact bytes)."""
    if isinstance(raw_body, bytes):
        return raw_body
    if isinstance(raw_body, bytearray):
        return bytes(raw_body)
    if isinstance(raw_body, str):
        return raw_body.encode("utf-8")
    raise WebhookError("webhook raw_body must be bytes or str")


# ── verify ─────────────────────────────────────────────────────────────────────


def verify_webhook(raw_body: Any, headers: dict, config: Config) -> bool:
    """Verify a webhook against the SINGLE configured auth method.

    Mirrors the platform's per-webhook delivery auth (one method per webhook):

    * ``hmac``   — recompute ``HMAC-SHA256(rawBody, secret)`` (secret selected by
      ``X-Allus-Webhook-Id``) and constant-time-compare to ``X-Allus-Signature``.
    * ``bearer`` — ``Authorization`` equals ``Bearer <token>``.
    * ``basic``  — ``Authorization`` equals ``Basic <base64(user:pass)>``.
    * ``header`` — the configured custom header equals the configured value.
    * ``none``   — always ``True`` (explicit opt-out).

    All comparisons are constant-time. Returns ``False`` on a missing/mismatched
    credential, or when no method is configured — never raises for a bad
    credential (that is :func:`handle_webhook`'s job). Which method is used is
    decided entirely by config (:meth:`Config.webhook_auth_method`); config
    loading guarantees at most one is set.
    """
    method = config.webhook_auth_method()
    if method is None:
        return False
    if method == "none":
        return True

    if method == "bearer":
        got = _header(headers, "authorization")
        if got is None:
            return False
        return hmac.compare_digest(got, "Bearer " + (config.webhook_bearer_token or ""))

    if method == "basic":
        got = _header(headers, "authorization")
        if got is None:
            return False
        creds = f'{config.webhook_basic["username"]}:{config.webhook_basic["password"]}'
        token = base64.b64encode(creds.encode("utf-8")).decode("ascii")
        return hmac.compare_digest(got, "Basic " + token)

    if method == "header":
        got = _header(headers, config.webhook_header["name"])
        if got is None:
            return False
        return hmac.compare_digest(got, config.webhook_header["value"])

    # method == "hmac"
    body = _as_bytes(raw_body)
    signature = _header(headers, _HDR_SIGNATURE)
    if not signature:
        return False
    webhook_id = _header(headers, _HDR_WEBHOOK_ID)
    secret = config.webhook_secret(webhook_id)
    if not secret:
        return False
    expected = hmac.new(secret.encode("utf-8"), body, sha256).hexdigest()
    # Constant-time compare (case-insensitive hex, like the platform's hex output).
    return hmac.compare_digest(expected, signature.strip().lower())


# ── parse ──────────────────────────────────────────────────────────────────────


def parse_webhook(
    raw_body: Any,
    headers: dict,
    config: Config,
    *,
    type_for_slug: Callable[[str], Optional[str]],
    decrypt_value: Callable[[Any], str],
    binary_fetch: Optional[Callable[[str], Any]] = None,
    account_key: Optional[rsa.RSAPrivateKey] = None,
) -> Change:
    """Parse a webhook body → a typed :class:`Change`.

    Does NOT verify the signature (use :func:`handle_webhook` for verify+parse).
    Handles JSON and XML bodies, and an ``encrypt_payload`` account-key envelope:
    if the (JSON) body is a ``{"_enc":1,...}`` wrapper, it is first unwrapped with
    the account private key (OAEP-SHA1) into the inner serialized payload, which is
    then parsed. The inner field ``value`` (a service-key wrapper) is decrypted by
    the same model factory the feed uses, so a webhook ``Change`` is byte-identical
    to a feed ``Change``.

    ``account_key`` is an optional pre-loaded account private key (the
    :class:`~allus_company_data.client.Client` loads it ONCE and reuses it, so an
    ``encrypt_payload`` webhook doesn't re-read the PEM + re-run PBKDF2 ~100k iters
    per request). When ``None``, the key is loaded from config on demand (the
    standalone-call path) — config-only key handling either way.
    """
    body = _as_bytes(raw_body)
    payload = _decode_payload(body, config, account_key=account_key)

    if not isinstance(payload, dict):
        raise WebhookError("webhook payload is not a JSON/XML object")

    return Change.from_api(
        payload,
        type_for_slug=type_for_slug,
        decrypt_value=decrypt_value,
        binary_fetch=binary_fetch,
    )


def handle_webhook(
    raw_body: Any,
    headers: dict,
    config: Config,
    *,
    type_for_slug: Callable[[str], Optional[str]],
    decrypt_value: Callable[[Any], str],
    binary_fetch: Optional[Callable[[str], Any]] = None,
    account_key: Optional[rsa.RSAPrivateKey] = None,
) -> Change:
    """Verify + parse a webhook in one call.

    Raises :class:`WebhookError` on a bad/unknown signature; otherwise returns the
    typed :class:`Change`. The typical one-liner inside a webhook route.
    ``account_key`` (optional) is a pre-loaded account private key reused for the
    ``encrypt_payload`` envelope (see :func:`parse_webhook`).
    """
    if not verify_webhook(raw_body, headers, config):
        raise WebhookError("webhook signature verification failed")
    return parse_webhook(
        raw_body,
        headers,
        config,
        type_for_slug=type_for_slug,
        decrypt_value=decrypt_value,
        binary_fetch=binary_fetch,
        account_key=account_key,
    )


# ── payload decoding (JSON / XML / encrypt_payload envelope) ────────────────────


def _decode_payload(
    body: bytes,
    config: Config,
    *,
    account_key: Optional[rsa.RSAPrivateKey] = None,
) -> Any:
    """Decode the raw body into the change dict, unwrapping an account envelope first."""
    text = body.decode("utf-8", errors="replace").strip()

    # An encrypt_payload envelope is always JSON ({"_enc":1,...}). Detect + unwrap
    # it before anything else (the inner payload is then JSON or XML per format).
    if text.startswith("{"):
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as exc:
            raise WebhookError(f"webhook body is not valid JSON: {exc}") from exc
        if isinstance(obj, dict) and obj.get(_ENC_MARKER) == 1 and {"k", "iv", "d"} <= obj.keys():
            inner = _unwrap_account_envelope(obj, config, account_key=account_key)
            return _decode_inner(inner)
        return obj

    # Otherwise an XML body (the platform's <response> serialization).
    if text.startswith("<"):
        try:
            return _parse_xml(text)
        except Exception as exc:  # noqa: BLE001 - surface any XML problem as WebhookError
            raise WebhookError(f"webhook body is not valid XML: {exc}") from exc

    raise WebhookError("webhook body is neither JSON nor XML")


def _decode_inner(inner_text: str) -> Any:
    """Parse the decrypted inner payload (JSON or XML)."""
    stripped = inner_text.strip()
    if stripped.startswith("<"):
        try:
            return _parse_xml(stripped)
        except Exception as exc:  # noqa: BLE001
            raise WebhookError(f"decrypted webhook payload is not valid XML: {exc}") from exc
    try:
        return json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise WebhookError(
            f"decrypted webhook payload is not valid JSON: {exc}"
        ) from exc


# ── account-key envelope unwrap (OAEP-SHA1 — webhook-specific) ───────────────────


def load_account_key(config: Config) -> Optional[rsa.RSAPrivateKey]:
    """Load the account private key from config ONCE (or ``None`` if not configured).

    Reused by the :class:`~allus_company_data.client.Client` so an
    ``encrypt_payload`` webhook never re-reads the PEM + re-runs PBKDF2 (~100k
    iters) per request — the account key is loaded a single time at client
    construction, exactly like the service key. Returns ``None`` when no
    ``account_private_key`` is configured (the SDK only needs it for
    ``encrypt_payload`` webhooks). Raises :class:`WebhookError` on a read /
    passphrase / PEM problem.
    """
    if not config.account_private_key:
        return None
    try:
        with open(config.account_private_key, "rb") as fh:
            pem = fh.read()
    except OSError as exc:
        raise WebhookError(
            f"could not read account_private_key PEM: {config.account_private_key}: {exc}"
        ) from exc
    passphrase = config.account_passphrase or ""
    try:
        return load_private_key(pem, passphrase)
    except Exception as exc:  # noqa: BLE001 - load_private_key raises DecryptError
        raise WebhookError(f"could not load account private key: {exc}") from exc


def _unwrap_account_envelope(
    envelope: dict,
    config: Config,
    *,
    account_key: Optional[rsa.RSAPrivateKey] = None,
) -> str:
    """Decrypt an ``encrypt_payload`` envelope with the ACCOUNT key.

    The platform wraps the serialized payload to the company account PUBLIC key
    using OpenSSL's default OAEP (MGF1-**SHA1**) + AES-256-GCM. The hash here is
    SHA1 (NOT the SHA-256 used for person field values) — the account key is
    webhook-only, so the difference is intentional. Config-only key handling: the
    account key/passphrase come from config, never a public-method argument.

    ``account_key`` is the pre-loaded key the Client caches; when ``None`` it is
    loaded from config on demand (the standalone-call path).
    """
    key = account_key if account_key is not None else load_account_key(config)
    if key is None:
        raise WebhookError(
            "received an encrypt_payload webhook but no account_private_key is configured"
        )
    return _decrypt_oaep_sha1(envelope, key)


def _b64(value: Any, name: str) -> bytes:
    if not isinstance(value, str):
        raise WebhookError(f"envelope field {name!r} must be a base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise WebhookError(f"envelope field {name!r} is not valid base64") from exc


def _decrypt_oaep_sha1(wrapper: dict, private_key: rsa.RSAPrivateKey) -> str:
    """RSA-OAEP(**SHA-1**, MGF1-SHA1) unwrap + AES-256-GCM decrypt → utf-8 string.

    Mirrors :func:`crypto.decrypt` but pins SHA-1 for the OAEP/MGF1 hash to match
    the account-key envelope (the only place the platform uses SHA-1 OAEP).
    """
    enc_key = _b64(wrapper.get("k"), "k")
    iv = _b64(wrapper.get("iv"), "iv")
    ciphertext_with_tag = _b64(wrapper.get("d"), "d")

    if len(iv) != GCM_IV_LEN:
        raise WebhookError(f"envelope iv must be {GCM_IV_LEN} bytes, got {len(iv)}")
    if len(ciphertext_with_tag) < GCM_TAG_LEN:
        raise WebhookError("envelope ciphertext too short to contain a GCM tag")

    try:
        aes_key = private_key.decrypt(
            enc_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None,
            ),
        )
    except ValueError as exc:
        raise WebhookError(
            f"account-key envelope RSA-OAEP unwrap failed (wrong account key?): {exc}"
        ) from exc

    if len(aes_key) != 32:
        raise WebhookError(
            f"unwrapped envelope AES key must be 32 bytes, got {len(aes_key)}"
        )

    try:
        plaintext = AESGCM(aes_key).decrypt(iv, ciphertext_with_tag, None)
    except InvalidTag as exc:
        raise WebhookError("account-key envelope AES-GCM tag mismatch") from exc

    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WebhookError("decrypted account-key envelope is not valid UTF-8") from exc


__all__ = ["verify_webhook", "parse_webhook", "handle_webhook", "load_account_key"]
