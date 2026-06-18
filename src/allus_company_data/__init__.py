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
from .crypto import BinaryHandle, decrypt, load_private_key
from .errors import (
    ApiError,
    AuthError,
    ConfigError,
    DecryptError,
    RateLimitError,
    WebhookError,
)
from .http import HttpClient
from .models import Change, Connection, LogEntry, RequestField, Value
from .pump import Pump
from .webhooks import handle_webhook, parse_webhook, verify_webhook

__all__ = [
    # client facade — the main entry point
    "Client",
    # config
    "Config",
    # crypto
    "load_private_key",
    "decrypt",
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
    "LogEntry",
    # changes pump
    "FileBuffer",
    "Pump",
    # webhook receiver helpers
    "verify_webhook",
    "parse_webhook",
    "handle_webhook",
]

__version__ = "0.1.0"
