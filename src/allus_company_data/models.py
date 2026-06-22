"""Output model — the conclusions.

The consumer works with these and nothing else. They are produced by factories
that turn a *hardened* API JSON object (slug-keyed ``values``; NO person source
field) into typed Python objects, decrypting ciphertext via the
injected crypto core.

    RequestField { slug, label, type, one_time, mandatory }   # YOUR request config
    Connection   { id, person_id, display_name, connected_at, values: {<slug>: Value} }
    Value        { value, live, updated_at }
    Change       { id, event, person_id, share_code?, slug?, value?, live?, at }   # id = stable dedup key
    LogEntry     { type, message, metadata, at }

Typed values:

* ``email``/``phone``/``url``/``text`` → ``str``
* ``address``/``bank``/``creditcard``  → ``dict`` (the decrypted plaintext is a
  JSON object string → parsed)
* ``date``/``date_of_birth``           → :class:`datetime.date`
* ``photo``/``document``/``legal_document`` → a lazy :class:`BinaryHandle`
  (``.bytes()`` fetches the slot file endpoint, decrypts, parses the envelope,
  base64-decodes the ``full``/``file`` data URI)

Every model carries ``.raw`` — the underlying (hardened) API dict — for debugging
or an edge case the SDK didn't model. It still never contains the person's source
field. The person's source field is never present anywhere.

Decryption is config-driven: the factory takes a ``decrypt_value``
callable (a closure over the loaded service private key) and, for binaries, a
``binary_fetch`` callable — never a key/secret argument.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Callable, Dict, List, Optional

from .crypto import BinaryHandle, DecryptError

# Field types whose decrypted plaintext is a JSON object → a parsed dict.
STRUCTURED_TYPES = ("address", "bank", "creditcard")
# Field types whose value is a lazy binary handle (served as a value_url).
BINARY_TYPES = ("photo", "document", "legal_document")
# Field types whose decrypted plaintext is an ISO date.
DATE_TYPES = ("date", "date_of_birth")

# A decrypt callable: takes the ciphertext wrapper (dict or JSON string) and
# returns the decrypted plaintext string. Closes over the service private key.
DecryptValue = Callable[[Any], str]
# A type resolver: slug -> the request field's type (e.g. "email", "photo").
TypeForSlug = Callable[[str], Optional[str]]


def _parse_iso_dt(value: Optional[str]) -> Optional[datetime]:
    """Parse an API ISO-8601 timestamp into a datetime (tolerant of 'Z')."""
    if not value:
        return None
    raw = str(value)
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def _coerce_bool(value: Any) -> Optional[bool]:
    """Coerce a JSON bool or an XML "true"/"false" string into a bool."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        low = value.strip().lower()
        if low in ("true", "1"):
            return True
        if low in ("false", "0", ""):
            return False
    return bool(value)


# ── definitions ──────────────────────────────────────────────────────────────


@dataclass
class RequestField:
    """A request-field DEFINITION — YOUR config, never the person's.

    ``mandatory`` folds the API's two flags: it is true when the field is
    mandatory to provide OR mandatory to stay connected.
    """

    slug: str
    label: str
    type: str
    one_time: bool
    mandatory: bool
    raw: dict = field(default_factory=dict, repr=False)

    @classmethod
    def from_api(cls, obj: dict) -> "RequestField":
        return cls(
            slug=obj.get("slug"),
            label=obj.get("label"),
            type=obj.get("type"),
            one_time=bool(_coerce_bool(obj.get("one_time"))),
            mandatory=bool(
                _coerce_bool(obj.get("mandatory_provide"))
                or _coerce_bool(obj.get("mandatory_connected"))
            ),
            raw=obj,
        )

    @classmethod
    def list_from_api(cls, body: Any) -> List["RequestField"]:
        """Parse the ``/request-fields`` response → a list of definitions."""
        items = body.get("request_fields", []) if isinstance(body, dict) else (body or [])
        return [cls.from_api(o) for o in items]


# ── values ───────────────────────────────────────────────────────────────────


@dataclass
class Value:
    """A single answer for one of YOUR request slots.

    ``value`` is the typed plaintext (str / dict / date / lazy BinaryHandle);
    ``live`` = the person chose "keep connected" (auto-updates) vs a one-time
    snapshot; ``updated_at`` = when this answer last changed. Both ride on the
    Value (per-answer), not the definition.
    """

    value: Any
    live: bool
    updated_at: Optional[datetime] = None
    raw: dict = field(default_factory=dict, repr=False)

    @classmethod
    def from_api(
        cls,
        slug: str,
        obj: dict,
        *,
        field_type: Optional[str],
        decrypt_value: DecryptValue,
        binary_fetch: Optional[Callable[[str], Any]] = None,
    ) -> "Value":
        """Build a typed Value from one hardened ``{value|value_url, live, updatedAt}`` entry."""
        live = bool(_coerce_bool(obj.get("live")))
        updated_at = _parse_iso_dt(obj.get("updatedAt") or obj.get("updated_at"))

        typed = _typed_value(
            obj,
            field_type=field_type,
            decrypt_value=decrypt_value,
            binary_fetch=binary_fetch,
        )
        return cls(value=typed, live=live, updated_at=updated_at, raw=obj)


def _typed_value(
    obj: dict,
    *,
    field_type: Optional[str],
    decrypt_value: DecryptValue,
    binary_fetch: Optional[Callable[[str], Any]],
) -> Any:
    """Decrypt + coerce one value entry to its typed Python form."""
    ftype = (field_type or "").lower()

    # Binary → a lazy handle over the slot value_url (no eager fetch/decrypt).
    if ftype in BINARY_TYPES or "value_url" in obj:
        value_url = obj.get("value_url")
        if value_url is None:
            # Binary type but no url (e.g. unanswered) → an empty handle.
            return BinaryHandle(envelope_json=None)
        return BinaryHandle(
            value_url=value_url,
            fetch=binary_fetch,
            decrypt=decrypt_value,
        )

    # Non-binary → decrypt the ciphertext wrapper to plaintext.
    ciphertext = obj.get("value")
    if ciphertext is None:
        return None
    plaintext = decrypt_value(ciphertext)

    if ftype in STRUCTURED_TYPES:
        try:
            parsed = json.loads(plaintext)
        except json.JSONDecodeError as exc:
            raise DecryptError(
                f"structured value for type {ftype!r} is not valid JSON"
            ) from exc
        return parsed

    if ftype in DATE_TYPES:
        parsed_date = _parse_date(plaintext)
        return parsed_date if parsed_date is not None else plaintext

    # text/email/phone/url and anything unknown → the plaintext string.
    return plaintext


def _parse_date(value: str) -> Optional[date]:
    try:
        return date.fromisoformat(value.strip()[:10])
    except (ValueError, AttributeError):
        return None


# ── connection ─────────────────────────────────────────────────────────────


@dataclass
class Connection:
    """A connected person — identity + the slug-keyed value map.

    NO source field anywhere: ``values`` is keyed by YOUR request slug.
    """

    id: str
    person_id: str
    display_name: Optional[str]
    connected_at: Optional[datetime]
    values: Dict[str, Value] = field(default_factory=dict)
    raw: dict = field(default_factory=dict, repr=False)

    @classmethod
    def from_api(
        cls,
        obj: dict,
        *,
        type_for_slug: TypeForSlug,
        decrypt_value: DecryptValue,
        binary_fetch: Optional[Callable[[str], Any]] = None,
        identity: Optional[dict] = None,
    ) -> "Connection":
        """Build a Connection from a hardened ``connectionDetail`` (or list) object.

        ``connectionDetail`` returns ``{connection_id, user_id, values}`` and no
        display_name/connected_at, so those can be supplied via ``identity`` (the
        matching row from the list endpoint, which carries them).
        """
        identity = identity or {}
        conn_id = obj.get("connection_id") or obj.get("id") or identity.get("connection_id")
        person_id = (
            obj.get("user_id")
            or obj.get("person_id")
            or obj.get("person_user_id")
            or identity.get("user_id")
        )
        display_name = obj.get("display_name") or identity.get("display_name")
        connected_at = _parse_iso_dt(
            obj.get("connected_at") or identity.get("connected_at")
        )

        values: Dict[str, Value] = {}
        for slug, entry in (obj.get("values") or {}).items():
            if not isinstance(entry, dict):
                continue
            values[slug] = Value.from_api(
                slug,
                entry,
                field_type=type_for_slug(slug),
                decrypt_value=decrypt_value,
                binary_fetch=binary_fetch,
            )

        return cls(
            id=conn_id,
            person_id=person_id,
            display_name=display_name,
            connected_at=connected_at,
            values=values,
            raw=obj,
        )


# ── change ───────────────────────────────────────────────────────────────────


@dataclass
class Change:
    """A change feed / webhook event.

    ``id`` is the stable server change-row id (the pump dedupes on it after a
    crash/replay); ``at`` is the change time (there is NO separate
    ``updated_at`` on a change). ``slug``/``value``/``live`` are present only on
    ``field_updated`` (connection/consent events carry no slot/value).
    """

    id: str
    event: str
    person_id: Optional[str]
    share_code: Optional[str] = None  # the person's profile share code (every event; may be null)
    slug: Optional[str] = None
    value: Any = None
    live: Optional[bool] = None
    document_id: Optional[str] = None  # set on document_status_changed
    status: Optional[str] = None       # set on document_status_changed
    at: Optional[datetime] = None
    raw: dict = field(default_factory=dict, repr=False)

    @classmethod
    def from_api(
        cls,
        obj: dict,
        *,
        type_for_slug: TypeForSlug,
        decrypt_value: DecryptValue,
        binary_fetch: Optional[Callable[[str], Any]] = None,
    ) -> "Change":
        """Build a Change from one hardened changes-feed / webhook event object."""
        slug = obj.get("slug")
        event = obj.get("event")
        live = _coerce_bool(obj.get("live")) if "live" in obj else None

        value: Any = None
        if event == "field_updated" and slug is not None:
            # Reuse the Value typing path so feed + connection produce identical
            # typed values (incl. the same lazy BinaryHandle for binaries).
            if "value" in obj or "value_url" in obj:
                value = _typed_value(
                    obj,
                    field_type=type_for_slug(slug),
                    decrypt_value=decrypt_value,
                    binary_fetch=binary_fetch,
                )

        return cls(
            id=obj.get("id"),
            event=event,
            person_id=obj.get("person_user_id") or obj.get("person_id"),
            share_code=obj.get("share_code"),
            slug=slug,
            value=value,
            live=live,
            document_id=obj.get("document_id"),
            status=obj.get("status") if event == "document_status_changed" else None,
            at=_parse_iso_dt(obj.get("at")),
            raw=obj,
        )

    @classmethod
    def list_from_api(
        cls,
        body: Any,
        *,
        type_for_slug: TypeForSlug,
        decrypt_value: DecryptValue,
        binary_fetch: Optional[Callable[[str], Any]] = None,
    ) -> List["Change"]:
        """Parse the ``/changes`` response → a list of typed Change events."""
        items = body.get("changes", []) if isinstance(body, dict) else (body or [])
        return [
            cls.from_api(
                o,
                type_for_slug=type_for_slug,
                decrypt_value=decrypt_value,
                binary_fetch=binary_fetch,
            )
            for o in items
        ]


# ── document ─────────────────────────────────────────────────────────────────


@dataclass
class Document:
    """A company document the SDK created/queried (company-data side).

    value semantics mirror the connection-payload contract — keyed on
    BROADCAST(plaintext) vs PER-PERSON(always encrypted), NOT on is_private:
      broadcast file   -> {file, original_name, mime_type, size}   (plaintext)
      per-person file  -> {"_enc_file": "enc_…json"}   (ciphertext blob, ANY is_private)
      broadcast json   -> the JSON object   (plaintext)
      per-person json  -> {"_enc":1,k,iv,d}   (ciphertext wrapper, ANY is_private;
                                               decrypt on demand via .json())
    is_private is device-display-only (lock vs decrypt-on-load), not the value shape.
    """

    id: str
    kind: str
    name: str
    description: Optional[str]
    status: str
    payload_kind: str          # 'file' | 'json'
    is_private: bool
    value: Any
    metadata: Optional[dict]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    _decrypt_value: Optional[DecryptValue] = field(default=None, repr=False)
    raw: dict = field(default_factory=dict, repr=False)

    def json(self) -> Any:
        """For a json document, return the plaintext object.

        Decryption is keyed on the value shape (per-person → encrypted wrapper),
        NOT on is_private: a per-person json doc (ANY is_private) is an {"_enc":1,…}
        wrapper and is decrypted with the SDK's own private key; a broadcast json doc
        is already plaintext and returned as-is.
        """
        if self.payload_kind != "json":
            raise DecryptError("json() is only valid for payload_kind='json' documents")
        if isinstance(self.value, dict) and self.value.get("_enc") == 1:
            if self._decrypt_value is None:
                raise DecryptError("no decrypt wiring for an encrypted (per-person) document")
            return json.loads(self._decrypt_value(self.value))
        return self.value

    @classmethod
    def from_api(cls, obj: dict, *, decrypt_value: Optional[DecryptValue] = None) -> "Document":
        return cls(
            id=obj.get("id"), kind=obj.get("kind"), name=obj.get("name"),
            description=obj.get("description"), status=obj.get("status"),
            payload_kind=obj.get("payload_kind"),
            is_private=bool(_coerce_bool(obj.get("is_private"))),
            value=obj.get("value"), metadata=obj.get("metadata"),
            created_at=_parse_iso_dt(obj.get("created_at")),
            updated_at=_parse_iso_dt(obj.get("updated_at")),
            _decrypt_value=decrypt_value, raw=obj,
        )

    @classmethod
    def list_from_api(cls, body: Any, *, decrypt_value: Optional[DecryptValue] = None):
        items = body.get("items", []) if isinstance(body, dict) else (body or [])
        return [cls.from_api(o, decrypt_value=decrypt_value) for o in items]


# ── log ────────────────────────────────────────────────────────────────────


@dataclass
class LogEntry:
    """A service activity-log entry — ops events only, never person data."""

    type: str
    message: Optional[str]
    metadata: Any
    at: Optional[datetime] = None
    raw: dict = field(default_factory=dict, repr=False)

    @classmethod
    def from_api(cls, obj: dict) -> "LogEntry":
        return cls(
            type=obj.get("type"),
            message=obj.get("message"),
            metadata=obj.get("metadata"),
            at=_parse_iso_dt(obj.get("at") or obj.get("created_at")),
            raw=obj,
        )

    @classmethod
    def list_from_api(cls, body: Any) -> List["LogEntry"]:
        """Parse the ``/logs`` response → a list of log entries."""
        items = body.get("items", []) if isinstance(body, dict) else (body or [])
        return [cls.from_api(o) for o in items]


__all__ = [
    "RequestField",
    "Value",
    "Connection",
    "Change",
    "LogEntry",
    "STRUCTURED_TYPES",
    "BINARY_TYPES",
    "DATE_TYPES",
]
