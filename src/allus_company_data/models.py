"""Output model — the conclusions.

The consumer works with these and nothing else. They are produced by factories
that turn a *hardened* API JSON object (slug-keyed ``values``; NO person source
field) into typed Python objects, decrypting ciphertext via the
injected crypto core.

    RequestField { slug, label, type, one_time, mandatory, verified, verified_max_age_days }
    Connection   { id, person_id, display_name, connected_at, values: {<slug>: Value} }
    Value        { value, live, updated_at, verified, verified_at, verified_expires_at }
    Change       { id, event, person_id, share_code?, slug?, value?, live?, at }   # id = stable dedup key
    LogEntry     { type, message, metadata, at }

Typed values:

* ``email``/``phone``/``url``/``text`` → ``str``
* ``address``/``bank``/``creditcard``  → ``dict`` (the decrypted plaintext is a
  JSON object string → parsed)
* ``date``/``date_of_birth``           → :class:`datetime.date`
* ``photo``/``document``/``legal_document`` and the ID-document subtypes
  ``passport``/``photo_id``/``drivers_license`` → a lazy :class:`BinaryHandle`
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

from .crypto import BinaryFetchResult, BinaryHandle, DecryptError, hash_matches

# Field types whose decrypted plaintext is a JSON object → a parsed dict.
STRUCTURED_TYPES = ("address", "bank", "creditcard")
# Field types whose value is a lazy binary handle (served as a value_url) — the
# ID-document subtypes are children of ``legal_document`` and share its envelope.
BINARY_TYPES = (
    "photo",
    "document",
    "legal_document",
    "passport",
    "photo_id",
    "drivers_license",
)
# Field types whose decrypted plaintext is an ISO date.
DATE_TYPES = ("date", "date_of_birth")

# A decrypt callable: takes the ciphertext wrapper (dict or JSON string) and
# returns the decrypted plaintext string. Closes over the service private key.
DecryptValue = Callable[[Any], str]
# A type resolver: slug -> the request field's type (e.g. "email", "photo").
TypeForSlug = Callable[[str], Optional[str]]
# A binary fetch callable: takes the slot-keyed value_url and returns the CLASSIFIED
# response — the file endpoint has an encrypted and a plaintext 200 shape, and
# only the caller of the HTTP layer can see the Content-Type that tells them apart.
BinaryFetch = Callable[[str], BinaryFetchResult]


def _parse_iso_dt(value: Optional[str]) -> Optional[datetime]:
    """Parse an API ISO-8601 timestamp into a datetime (tolerant of 'Z')."""
    if not value:
        return None
    raw = str(value)
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def expiry_passed(value: Any) -> bool:
    """Whether a verification expiry stamp has already passed.

    Absent → ``False``: a verification with no expiry never lapses. Present but
    unparseable → ``True``: an expiry that cannot be evaluated cannot be used to claim
    the value is still verified today.
    """
    if value is None or value == "":
        return False
    when = _parse_iso_dt(str(value))
    if when is None:
        return True
    now = datetime.now(when.tzinfo) if when.tzinfo is not None else datetime.now()
    return when <= now


def _coerce_int(value: Any) -> Optional[int]:
    """Coerce a JSON number or an XML numeric string into an int, or None."""
    if value is None or value == "":
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
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
    # Which customer TYPE this request row applies to: "person" | "company" | "both"
    # (B2B). Absent on an older API → None (treat as "person").
    audience: Optional[str] = None
    # This row DEMANDS a verified answer: only a value the person verified satisfies it,
    # and an unverified candidate is refused at the accepting act rather than downgraded.
    verified: bool = False
    # The oldest verification the demand accepts, in days; None = no age limit. Enforced
    # at the accepting act only — a standing live link is not re-enforced afterwards, so
    # apply your own policy from each Value's ``verified_at``.
    verified_max_age_days: Optional[int] = None
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
            audience=obj.get("audience"),
            verified=bool(_coerce_bool(obj.get("verified"))),
            verified_max_age_days=_coerce_int(obj.get("verified_max_age_days")),
            raw=obj,
        )

    @classmethod
    def list_from_api(cls, body: Any) -> List["RequestField"]:
        """Parse the ``/request-fields`` response → a list of definitions."""
        items = body.get("request_fields", []) if isinstance(body, dict) else (body or [])
        return [cls.from_api(o) for o in items]


# ── values ───────────────────────────────────────────────────────────────────


def _verified_from(obj: dict, plaintext) -> bool:
    """Recompute the verified flag from the just-decrypted plaintext (text values only).

    Two conditions, both required: the hash recomputes over the exact plaintext, AND the
    verification has not lapsed (``verified_expires_at`` absent or still in the future).
    A document-backed verification lapses when the document itself expires, so a stale
    binding reads false here without any lookup.
    """
    if not isinstance(plaintext, str):
        return False
    vhash = obj.get("verified_hash")
    vsalt = obj.get("verified_salt")
    if not vhash or not vsalt:
        return False
    if expiry_passed(obj.get("verified_expires_at")):
        return False
    return hash_matches(vsalt, vhash, plaintext)


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
    verified: bool = False  # True iff the hash matches the plaintext AND the verification has not lapsed
    # When the person's answering field was verified. None when the value carries no
    # verification. It is a stamp, not a promise about today — read it with ``verified``.
    verified_at: Optional[datetime] = None
    # When that verification lapses (a document-backed verification dies with the
    # document). None = it does not lapse. Past → ``verified`` reads False.
    verified_expires_at: Optional[datetime] = None
    raw: dict = field(default_factory=dict, repr=False)

    @classmethod
    def from_api(
        cls,
        slug: str,
        obj: dict,
        *,
        field_type: Optional[str],
        decrypt_value: DecryptValue,
        binary_fetch: Optional[BinaryFetch] = None,
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
        return cls(
            value=typed,
            live=live,
            updated_at=updated_at,
            verified=_verified_from(obj, typed),
            verified_at=_parse_iso_dt(obj.get("verified_at")),
            verified_expires_at=_parse_iso_dt(obj.get("verified_expires_at")),
            raw=obj,
        )


def _typed_value(
    obj: dict,
    *,
    field_type: Optional[str],
    decrypt_value: DecryptValue,
    binary_fetch: Optional[BinaryFetch],
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
    # The connected customer's TYPE: "person" | "company" (B2B). Absent on an
    # older API → None (treat as "person"). ``person_id`` keeps its name (the wire
    # field ``person_user_id``) but semantically holds the customer's user id.
    customer_type: Optional[str] = None
    # The customer's profile share code (previously only reachable via ``.raw``).
    share_code: Optional[str] = None
    raw: dict = field(default_factory=dict, repr=False)

    @classmethod
    def from_api(
        cls,
        obj: dict,
        *,
        type_for_slug: TypeForSlug,
        decrypt_value: DecryptValue,
        binary_fetch: Optional[BinaryFetch] = None,
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
            customer_type=obj.get("customer_type") or identity.get("customer_type"),
            share_code=obj.get("share_code") or identity.get("share_code"),
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
    ``request_id`` is set only on the service-initiated connect-request outcome
    events (``connection_request_accepted`` / ``connection_request_rejected``),
    correlating back to the request_id returned by :meth:`Client.send_connect_request`.
    ``connection_id``/``message_id``/``person_public_key``/``message_body`` are set
    only on ``message_received`` — a person's message to the service, decrypted with
    the service private key; the event's ``created_at`` stays in ``raw``.
    """

    id: str
    event: str
    person_id: Optional[str]
    share_code: Optional[str] = None  # the person's profile share code (every event; may be null)
    customer_type: Optional[str] = None  # "person" | "company" (B2B); absent on older API → None
    slug: Optional[str] = None
    value: Any = None
    live: Optional[bool] = None
    document_id: Optional[str] = None  # set on document_status_changed
    status: Optional[str] = None       # set on document_status_changed
    action: Optional[str] = None       # set on document_status_changed: signed | accepted | cancelled
    note: Optional[str] = None         # set on document_status_changed: the person's optional cancellation note
    method: Optional[str] = None       # set on a signature: biometric | twofa | email | custodian
    content_sha256: Optional[str] = None  # set on a signature: SHA-256 of the signed content
    signed_at: Optional[str] = None    # set on a signature: ISO timestamp the signature was recorded
    cancel_effective_date: Optional[str] = None  # set on a cancelled document_status_changed: ISO date the cancellation takes effect
    request_id: Optional[str] = None   # set on connection_request_accepted | connection_request_rejected
    public_key_sha256: Optional[str] = None  # set on key_rotated — SHA-256 fingerprint of the person's NEW public key
    connection_id: Optional[str] = None  # set on message_received — the connection to reply/ack on
    message_id: Optional[str] = None     # set on message_received — the ack boundary (up_to_message_id)
    person_public_key: Optional[str] = None  # set on message_received — base64 SPKI to encrypt the reply to
    message_body: Optional[str] = None   # set on message_received — the DECRYPTED message text
    verified: bool = False  # True iff a field_updated value's hash matches AND the verification has not lapsed
    verified_at: Optional[datetime] = None         # when the answering field was verified (None when unverified)
    verified_expires_at: Optional[datetime] = None  # when that verification lapses (None = it does not)
    at: Optional[datetime] = None
    raw: dict = field(default_factory=dict, repr=False)

    @classmethod
    def from_api(
        cls,
        obj: dict,
        *,
        type_for_slug: TypeForSlug,
        decrypt_value: DecryptValue,
        binary_fetch: Optional[BinaryFetch] = None,
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

        is_message = event == "message_received"
        message_body: Optional[str] = None
        if is_message:
            # The message ciphertext is carried under ``body``, never ``value``: on every
            # other event ``value`` means field ciphertext, which a message body is not.
            # It is encrypted for the SERVICE key, so the ordinary decrypt opens it.
            cipher = obj.get("body")
            if cipher is not None:
                message_body = decrypt_value(cipher)

        return cls(
            id=obj.get("id"),
            event=event,
            person_id=obj.get("person_user_id") or obj.get("person_id"),
            share_code=obj.get("share_code"),
            customer_type=obj.get("customer_type"),
            slug=slug,
            value=value,
            live=live,
            document_id=obj.get("document_id"),
            # 2fa_challenge_completed carries the outcome in `status` (approved|denied|revoked);
            # its challenge_id/completed_at stay in `raw`. The poll is the record (spec §3).
            status=obj.get("status")
            if event in ("document_status_changed", "2fa_challenge_completed")
            else None,
            action=obj.get("action") if event == "document_status_changed" else None,
            note=obj.get("note") if event == "document_status_changed" else None,
            method=obj.get("method") if event == "document_status_changed" else None,
            content_sha256=obj.get("content_sha256") if event == "document_status_changed" else None,
            signed_at=obj.get("signed_at") if event == "document_status_changed" else None,
            cancel_effective_date=obj.get("cancel_effective_date") if event == "document_status_changed" else None,
            request_id=obj.get("request_id")
            if event in ("connection_request_accepted", "connection_request_rejected")
            else None,
            public_key_sha256=obj.get("public_key_sha256") if event == "key_rotated" else None,
            connection_id=obj.get("connection_id") if is_message else None,
            message_id=obj.get("message_id") if is_message else None,
            person_public_key=obj.get("person_public_key") if is_message else None,
            message_body=message_body,
            verified=_verified_from(obj, value),
            verified_at=_parse_iso_dt(obj.get("verified_at")),
            verified_expires_at=_parse_iso_dt(obj.get("verified_expires_at")),
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
        binary_fetch: Optional[BinaryFetch] = None,
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
    requires_signature: bool = False
    requires_acceptance: bool = False
    signatures: list = field(default_factory=list)  # contract audit trail (action/method/content_sha256/...)
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
            requires_signature=bool(_coerce_bool(obj.get("requires_signature"))),
            requires_acceptance=bool(_coerce_bool(obj.get("requires_acceptance"))),
            signatures=obj.get("signatures") or [],
            _decrypt_value=decrypt_value, raw=obj,
        )

    @classmethod
    def list_from_api(cls, body: Any, *, decrypt_value: Optional[DecryptValue] = None):
        items = body.get("items", []) if isinstance(body, dict) else (body or [])
        return [cls.from_api(o, decrypt_value=decrypt_value) for o in items]


# ── flow run ─────────────────────────────────────────────────────────────────


@dataclass
class FlowRun:
    """A contract-flow run (company-data side).

    The company is one of the two bound parties. ``bindings`` maps each party
    key to the bound ``user_id`` (the company's own ``user_id`` is
    ``company_user_id``); ``answers`` are the per-party encrypted answer copies
    (the company reads the rows whose ``for_user_id == company_user_id``,
    decryptable with the service private key); ``definition`` is the pinned
    flow-version graph (``nodes``, ``edges``, ``parties``, ``output_mode``).

    ``answers`` is kept as the raw list of ``{slug, for_user_id, value}`` rows;
    the client decrypts the company's copies on demand.
    """

    id: str
    flow_id: Optional[str]
    flow_version: Any
    service_id: Optional[str]
    connection_id: Optional[str]
    company_user_id: Optional[str]
    bindings: Dict[str, Any]
    status: Optional[str]
    current_node: Optional[str]
    document_id: Optional[str]
    output_mode: Optional[str]
    definition: dict
    answers: List[dict]
    reference_date: Optional[str] = None  # immutable run "today" (raw YYYY-MM-DD string)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    raw: dict = field(default_factory=dict, repr=False)

    @property
    def company_party_key(self) -> Optional[str]:
        """The party key the company is bound to (``bindings[key] == company_user_id``)."""
        for key, uid in (self.bindings or {}).items():
            if uid == self.company_user_id:
                return key
        return None

    @property
    def service_user_id(self) -> Optional[str]:
        """The company's bound user_id — its answer copies use this ``for_user_id``."""
        return self.company_user_id

    @classmethod
    def from_api(cls, obj: dict) -> "FlowRun":
        if not isinstance(obj, dict):
            obj = {}
        definition = obj.get("definition")
        if not isinstance(definition, dict):
            # The company-data run payload nests the pinned graph as ``definition``;
            # tolerate a flatter shape where the graph parts ride at the top level.
            definition = {
                "nodes": obj.get("nodes", []),
                "edges": obj.get("edges", []),
                "parties": obj.get("parties", []),
                "output_mode": obj.get("output_mode"),
            }
        answers = obj.get("answers")
        return cls(
            id=obj.get("id"),
            flow_id=obj.get("flow_id"),
            flow_version=obj.get("flow_version"),
            service_id=obj.get("service_id"),
            connection_id=obj.get("connection_id"),
            company_user_id=obj.get("company_user_id"),
            bindings=dict(obj.get("bindings") or {}),
            status=obj.get("status"),
            current_node=obj.get("current_node"),
            document_id=obj.get("document_id"),
            output_mode=obj.get("output_mode") or (definition.get("output_mode") if isinstance(definition, dict) else None),
            definition=definition if isinstance(definition, dict) else {},
            answers=[a for a in (answers or []) if isinstance(a, dict)],
            reference_date=obj.get("reference_date"),
            created_at=_parse_iso_dt(obj.get("created_at")),
            updated_at=_parse_iso_dt(obj.get("updated_at")),
            raw=obj,
        )


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
    "FlowRun",
    "LogEntry",
    "STRUCTURED_TYPES",
    "BINARY_TYPES",
    "DATE_TYPES",
]
