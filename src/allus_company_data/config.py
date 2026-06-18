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
