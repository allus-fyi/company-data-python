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
from .customer import CustomerClient
from .customer_models import CustomerConnection, CustomerServiceLink
from .config import Config
from .crypto import (
    BinaryFetchResult,
    BinaryHandle,
    BinaryPage,
    compute_plain_sha256,
    decrypt,
    encrypt_for_public_key,
    export_public_key_spki,
    generate_reply_key_pair,
    load_private_key,
    load_public_key,
    plugin_open_request,
    plugin_seal_reply,
)
from .errors import (
    ApiError,
    AuthError,
    ConfigError,
    DecryptError,
    PluginInputUnavailable,
    RateLimitError,
    ValidationError,
    WebhookError,
)
from .field_types import FieldTypeRegistry
from .field_validation import dial_code_for, is_valid_country_code
from .http import HttpClient
from .flow_condition import (
    compute_constants,
    eval_expr,
    evaluate,
    evaluate_flow_condition,
    expand_plugin_answers,
    plugin_answer_summary,
    plugin_answer_view,
    resolved_constants,
)
from .flow_plugins import PluginOptions, PluginOutputs, PluginPass, PluginPicksInvalid
from .models import (
    Change,
    Connection,
    Document,
    FlowRun,
    LogEntry,
    PluginValue,
    RequestField,
    RequestFieldPlugin,
    Value,
)
from .oauth import Attestation, Claim, OAuthClient, parse_plugin_value
from .two_factor import TwoFactorChallenge, TwoFactorClient, TwoFactorResult
from .pump import Pump
from .webhooks import handle_webhook, parse_webhook, verify_webhook

__all__ = [
    # client facade — the main entry point
    "Client",
    # customer role (b2b)
    "CustomerClient",
    "CustomerConnection",
    "CustomerServiceLink",
    # 2FA-by-allme
    "TwoFactorClient",
    "TwoFactorChallenge",
    "TwoFactorResult",
    # config
    "Config",
    # crypto
    "load_private_key",
    "load_public_key",
    "decrypt",
    "encrypt_for_public_key",
    "compute_plain_sha256",
    # a plugin server's own sealing (the builder routine) + reply keys
    "plugin_open_request",
    "plugin_seal_reply",
    "generate_reply_key_pair",
    "export_public_key_spki",
    "BinaryHandle",
    # One page of a multi-page binary answer, as `BinaryHandle.pages()` returns it.
    "BinaryPage",
    # What a custom `binary_fetch` must return (the three 200 shapes of the
    # company-facing file endpoint).
    "BinaryFetchResult",
    # errors
    "ConfigError",
    "AuthError",
    "ApiError",
    "DecryptError",
    "WebhookError",
    "RateLimitError",
    "ValidationError",
    "PluginInputUnavailable",
    # the field-type registry (value shape + value validation) + country helpers
    "FieldTypeRegistry",
    "is_valid_country_code",
    "dial_code_for",
    # transport
    "HttpClient",
    # output model
    "RequestField",
    "Connection",
    "Value",
    "Change",
    "Document",
    "FlowRun",
    "LogEntry",
    "PluginValue",
    "RequestFieldPlugin",
    # plugin fields on a flow step (the company party's calls through the forwarder)
    "PluginPass",
    "PluginOptions",
    "PluginOutputs",
    "PluginPicksInvalid",
    # "Sign in with allme" — RP-side OAuth
    "OAuthClient",
    "Attestation",
    "Claim",
    "parse_plugin_value",
    # contract-flow condition evaluator + computed constants
    "evaluate",
    "eval_expr",
    "compute_constants",
    "evaluate_flow_condition",
    "resolved_constants",
    "expand_plugin_answers",
    "plugin_answer_summary",
    "plugin_answer_view",
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
    __version__ = "0.0.17"  # keep in sync with pyproject
