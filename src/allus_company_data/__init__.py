"""allus company-data SDK for Python.

This package wraps the allus company-data API: point it at a JSON config file
and it hands back typed, plaintext, your-slug-keyed conclusions with transparent
hybrid decryption.

Exported: config loading, the decryption core, the full error taxonomy, the
HTTP/auth layer, the output model, the crash-safe changes pump (durable file
buffer + pump), the :class:`Client` facade, and the webhook receiver helpers.
``Client`` is the one object an integrating company touches.
"""

from .buffer import FileBuffer
from .client import Client
from .config import Config
from .crypto import (
    BinaryHandle,
    decrypt,
    encrypt_for_public_key,
    load_private_key,
    load_public_key,
)
from .errors import (
    ApiError,
    AuthError,
    ConfigError,
    DecryptError,
    RateLimitError,
    WebhookError,
)
from .http import HttpClient
from .models import Change, Connection, Document, LogEntry, RequestField, Value
from .pump import Pump
from .webhooks import handle_webhook, parse_webhook, verify_webhook

__all__ = [
    # client facade — the main entry point
    "Client",
    # config
    "Config",
    # crypto
    "load_private_key",
    "load_public_key",
    "decrypt",
    "encrypt_for_public_key",
    "BinaryHandle",
    # errors
    "ConfigError",
    "AuthError",
    "ApiError",
    "DecryptError",
    "WebhookError",
    "RateLimitError",
    # transport
    "HttpClient",
    # output model
    "RequestField",
    "Connection",
    "Value",
    "Change",
    "Document",
    "LogEntry",
    # changes pump
    "FileBuffer",
    "Pump",
    # webhook receiver helpers
    "verify_webhook",
    "parse_webhook",
    "handle_webhook",
]

try:
    from importlib.metadata import version as _pkg_version
    __version__ = _pkg_version("allus-company-data")
except Exception:  # running from source, not installed
    __version__ = "0.0.5"  # keep in sync with pyproject
