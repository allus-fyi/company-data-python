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
    "account_private_key": "ALLUS_ACCOUNT_PRIVATE_KEY",
    "account_passphrase": "ALLUS_ACCOUNT_PASSPHRASE",
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

_VALID_FORMATS = ("json", "xml")


@dataclass
class Config:
    """The whole SDK configuration. Keys live here and nowhere else."""

    api_url: str
    client_id: str
    client_secret: str
    service_private_key: str  # path to the OpenSSL-encrypted PKCS#8 PEM
    key_passphrase: str       # decrypts the service PEM in memory

    # OPTIONAL — only needed if you receive encrypt_payload webhooks.
    account_private_key: Optional[str] = None
    account_passphrase: Optional[str] = None

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
    def from_file(cls, path: str) -> "Config":
        """Load from a JSON file; env vars override file values."""
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError as exc:
            raise ConfigError(f"config file not found: {path}") from exc
        except json.JSONDecodeError as exc:
            raise ConfigError(f"config file is not valid JSON: {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigError(f"config file must be a JSON object: {path}")
        return cls._build(data)

    @classmethod
    def from_env(cls) -> "Config":
        """Build entirely from ``ALLUS_*`` env vars."""
        return cls._build({})

    @classmethod
    def _build(cls, data: dict) -> "Config":
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

        # Required fields (fail fast).
        missing = [name for name in _REQUIRED if not values.get(name)]
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
