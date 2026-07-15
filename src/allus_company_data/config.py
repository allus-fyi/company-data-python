"""Configuration loading.

Config-only key handling is a hard rule: **no SDK method ever takes a key,
passphrase, or secret as an argument.** Everything cryptographic — decrypting
the service PEM, decrypting field values, verifying the webhook HMAC,
unwrapping the account-key envelope — is driven entirely by this config. The
developer's only key responsibility is putting the right values here.

A single JSON file holds everything; any field may be overridden by an
``ALLUS_*`` env var, so secrets needn't live in the file.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Optional

# ConfigError is part of the shared error taxonomy and is defined in errors.py; it
# is re-exported here so ``from allus_company_data.config import ConfigError``
# (used by application code + tests) keeps working.
from .errors import ConfigError  # noqa: F401  (re-exported)


# Mapping from a Config attribute name to its ``ALLUS_*`` env-var override.
# (Secrets are the common overrides, but every field is overridable.)
_ENV_MAP = {
    "api_url": "ALLUS_API_URL",
    "client_id": "ALLUS_CLIENT_ID",
    "client_secret": "ALLUS_CLIENT_SECRET",
    "service_private_key": "ALLUS_SERVICE_PRIVATE_KEY",
    "key_passphrase": "ALLUS_KEY_PASSPHRASE",
    # Customer role (B2B, #168): the acct_* client pair the connecting company
    # authenticates with. Distinct from the per-service (client_id/secret) pair.
    "customer_client_id": "ALLUS_CUSTOMER_CLIENT_ID",
    "customer_client_secret": "ALLUS_CUSTOMER_CLIENT_SECRET",
    "account_private_key": "ALLUS_ACCOUNT_PRIVATE_KEY",
    "account_passphrase": "ALLUS_ACCOUNT_PASSPHRASE",
    # "Sign in with allme" idw role (#195): the idw_* app the RP embeds. oauth_private_key +
    # oauth_key_passphrase are only needed to DECRYPT one_time claim values (config-only keys).
    "oauth_client_id": "ALLUS_OAUTH_CLIENT_ID",
    "oauth_redirect_uri": "ALLUS_OAUTH_REDIRECT_URI",
    "oauth_client_secret": "ALLUS_OAUTH_CLIENT_SECRET",
    "oauth_private_key": "ALLUS_OAUTH_PRIVATE_KEY",
    "oauth_key_passphrase": "ALLUS_OAUTH_KEY_PASSPHRASE",
    "cache_dir": "ALLUS_CACHE_DIR",
    "format": "ALLUS_FORMAT",
}

# A single-webhook shortcut secret (the flat "webhook_secret" / its env override).
_WEBHOOK_SECRET_ENV = "ALLUS_WEBHOOK_SECRET"

# Required for any working client: the API base, the client credentials, and the
# service key material that makes decryption possible.
_REQUIRED = (
    "api_url",
    "client_id",
    "client_secret",
    "service_private_key",
    "key_passphrase",
)

# Customer role (#168): the acct_* pair + the account key that decrypts received
# documents/flow copies. No service PEM — a customer never decrypts a person's field.
_REQUIRED_CUSTOMER = (
    "api_url",
    "customer_client_id",
    "customer_client_secret",
    "account_private_key",
)

# "Sign in with allme" idw role (#195): only the client id + redirect are required. A secret is
# needed for confidential apps; the private key + passphrase are needed only to decrypt one_time
# claim values (checked lazily by OAuthClient.complete_sign_in, not here).
_REQUIRED_IDW = (
    "api_url",
    "oauth_client_id",
    "oauth_redirect_uri",
)

_VALID_FORMATS = ("json", "xml")


@dataclass
class Config:
    """The whole SDK configuration. Keys live here and nowhere else."""

    api_url: str
    # Service role (per-service data client). Optional so a CUSTOMER-role config
    # (which uses customer_client_id/secret instead) can omit them.
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    service_private_key: Optional[str] = None  # path to the OpenSSL-encrypted PKCS#8 PEM
    key_passphrase: Optional[str] = None       # decrypts the service PEM in memory

    # Customer role (#168): the acct_* client pair the connecting company uses.
    customer_client_id: Optional[str] = None
    customer_client_secret: Optional[str] = None

    # OPTIONAL — only needed if you receive encrypt_payload webhooks.
    account_private_key: Optional[str] = None
    account_passphrase: Optional[str] = None

    # "Sign in with allme" idw role (#195). The idw_* app the RP embeds. oauth_private_key is the
    # path to the app's OpenSSL-encrypted PKCS#8 PEM; oauth_key_passphrase decrypts it in memory —
    # both only needed to read one_time claim values (config-only key handling, as everywhere).
    oauth_client_id: Optional[str] = None
    oauth_redirect_uri: Optional[str] = None
    oauth_client_secret: Optional[str] = None
    oauth_private_key: Optional[str] = None
    oauth_key_passphrase: Optional[str] = None

    # OPTIONAL — per-webhook HMAC secrets keyed by webhook id; matched via the
    # X-Allus-Webhook-Id header. A single-webhook service can use the flat
    # "webhook_secret" shortcut, captured under the reserved key below.
    webhooks: dict = field(default_factory=dict)

    # OPTIONAL — alternative webhook auth methods, mirroring the platform's
    # per-webhook delivery auth. Configure AT MOST ONE family among
    # hmac (webhooks/webhook_secret) | bearer | basic | header | none;
    # two or more → ConfigError. See webhook_auth_method().
    webhook_bearer_token: Optional[str] = None      # "Authorization: Bearer <token>"
    webhook_basic: Optional[dict] = None            # {"username","password"} → Basic auth
    webhook_header: Optional[dict] = None           # {"name","value"} → custom header
    webhook_auth_none: bool = False                 # explicit opt-out — verify always true

    # Durable local buffer for the changes pump.
    cache_dir: str = "./allus-cache"

    # Wire format json|xml (default json) — invisible in the output.
    format: str = "json"

    # Reserved webhook-map key under which a flat "webhook_secret" is stored.
    SINGLE_WEBHOOK_KEY = "__single__"

    @classmethod
    def _load_json(cls, path: str) -> dict:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError as exc:
            raise ConfigError(f"config file not found: {path}") from exc
        except json.JSONDecodeError as exc:
            raise ConfigError(f"config file is not valid JSON: {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigError(f"config file must be a JSON object: {path}")
        return data

    @classmethod
    def from_file(cls, path: str) -> "Config":
        """Load a SERVICE-role config from a JSON file; env vars override file values."""
        return cls._build(cls._load_json(path))

    @classmethod
    def from_env(cls) -> "Config":
        """Build a SERVICE-role config entirely from ``ALLUS_*`` env vars."""
        return cls._build({})

    @classmethod
    def from_customer_file(cls, path: str) -> "Config":
        """Load a CUSTOMER-role config (#168) — requires the acct_* pair + account key,
        not the service PEM. Env vars override file values."""
        return cls._build(cls._load_json(path), role="customer")

    @classmethod
    def from_customer_env(cls) -> "Config":
        """Build a CUSTOMER-role config entirely from ``ALLUS_*`` env vars."""
        return cls._build({}, role="customer")

    @classmethod
    def from_idw_file(cls, path: str) -> "Config":
        """Load an IDW-role config (#195, "Sign in with allme") from a JSON file — requires the
        oauth_client_id + oauth_redirect_uri; env vars override file values."""
        return cls._build(cls._load_json(path), role="idw")

    @classmethod
    def from_idw_env(cls) -> "Config":
        """Build an IDW-role config entirely from ``ALLUS_*`` env vars."""
        return cls._build({}, role="idw")

    @classmethod
    def _build(cls, data: dict, role: str = "service") -> "Config":
        """Merge file values with env overrides, validate, and construct."""
        values: dict = {}

        # Scalar fields: env var (if set) overrides the file value.
        for attr, env_name in _ENV_MAP.items():
            env_val = os.environ.get(env_name)
            if env_val is not None:
                values[attr] = env_val
            elif attr in data and data[attr] is not None:
                values[attr] = data[attr]

        # Webhook secrets: the "webhooks" map plus the flat "webhook_secret"
        # shortcut (and its env override), normalized into a single dict.
        webhooks: dict = {}
        file_webhooks = data.get("webhooks")
        if file_webhooks is not None:
            if not isinstance(file_webhooks, dict):
                raise ConfigError('"webhooks" must be an object mapping webhook id -> secret')
            webhooks.update({str(k): str(v) for k, v in file_webhooks.items()})

        flat_secret = os.environ.get(_WEBHOOK_SECRET_ENV)
        if flat_secret is None:
            flat_secret = data.get("webhook_secret")
        if flat_secret is not None:
            webhooks[cls.SINGLE_WEBHOOK_KEY] = str(flat_secret)

        if webhooks:
            values["webhooks"] = webhooks

        # Alternative webhook auth methods (file-config). Validate object shapes.
        bearer = data.get("webhook_bearer_token")
        if bearer:
            values["webhook_bearer_token"] = str(bearer)

        basic = data.get("webhook_basic")
        if basic is not None:
            if not isinstance(basic, dict) or not basic.get("username") or not basic.get("password"):
                raise ConfigError(
                    '"webhook_basic" must be an object with non-empty "username" and "password"'
                )
            values["webhook_basic"] = {
                "username": str(basic["username"]),
                "password": str(basic["password"]),
            }

        hdr = data.get("webhook_header")
        if hdr is not None:
            if not isinstance(hdr, dict) or not hdr.get("name") or not hdr.get("value"):
                raise ConfigError(
                    '"webhook_header" must be an object with non-empty "name" and "value"'
                )
            values["webhook_header"] = {"name": str(hdr["name"]), "value": str(hdr["value"])}

        if data.get("webhook_auth_none") is True:
            values["webhook_auth_none"] = True

        # At most one webhook auth method may be configured.
        present = []
        if values.get("webhooks"):
            present.append("hmac")
        if values.get("webhook_bearer_token"):
            present.append("bearer")
        if values.get("webhook_basic"):
            present.append("basic")
        if values.get("webhook_header"):
            present.append("header")
        if values.get("webhook_auth_none"):
            present.append("none")
        if len(present) > 1:
            raise ConfigError(
                "configure at most one webhook auth method (found: " + ", ".join(present) + ")"
            )

        # Required fields (fail fast) — role-dependent.
        if role == "idw":
            required = _REQUIRED_IDW
        elif role == "customer":
            required = _REQUIRED_CUSTOMER
        else:
            required = _REQUIRED
        missing = [name for name in required if not values.get(name)]
        if missing:
            raise ConfigError(
                "missing required config field(s): " + ", ".join(missing)
            )

        # Validate the wire format if supplied.
        fmt = values.get("format")
        if fmt is not None:
            fmt = str(fmt).lower()
            if fmt not in _VALID_FORMATS:
                raise ConfigError(
                    f'invalid "format": {fmt!r} (expected one of {_VALID_FORMATS})'
                )
            values["format"] = fmt

        return cls(**values)

    def webhook_secret(self, webhook_id: Optional[str] = None) -> Optional[str]:
        """Resolve the HMAC secret for a webhook id.

        Falls back to the single-webhook shortcut secret when there is no id or
        no id-specific match. The webhook helpers read this — application code
        never passes a secret in.
        """
        if webhook_id is not None and webhook_id in self.webhooks:
            return self.webhooks[webhook_id]
        return self.webhooks.get(self.SINGLE_WEBHOOK_KEY)

    def webhook_auth_method(self) -> Optional[str]:
        """The single configured webhook auth method, or ``None`` if none is set.

        Returns one of ``"hmac"`` | ``"bearer"`` | ``"basic"`` | ``"header"`` |
        ``"none"``. Config loading guarantees at most one is configured, so the
        order here is only a tie-break that never triggers.
        """
        if self.webhook_auth_none:
            return "none"
        if self.webhook_bearer_token:
            return "bearer"
        if self.webhook_basic:
            return "basic"
        if self.webhook_header:
            return "header"
        if self.webhooks:
            return "hmac"
        return None
