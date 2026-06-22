"""Client facade.

The one object an integrating company touches. Build it from config (the keys
live there and nowhere else), then call:

    client.request_fields()          -> cached list[RequestField]  (slug -> meta)
    client.connections(limit, offset)-> lazy generator of Connection (auto-paged)
    client.connection(id)            -> one Connection
    client.logs(limit, offset)       -> list[LogEntry]
    client.process_changes(handler)  -> the crash-safe pump
    client.drain_batch(max)          -> raw unbuffered drain (advanced)
    client.dead_letters() / client.retry_dead_letters(handler)

Plus the webhook receiver helpers, exposed as methods that delegate
to :mod:`allus_company_data.webhooks` (all config-driven, no key/secret args):

    client.verify_webhook(raw_body, headers) -> bool
    client.parse_webhook(raw_body, headers)  -> Change
    client.handle_webhook(raw_body, headers) -> Change

How it is wired (the "everything else the SDK hides"):

* **Auth + transport** — an :class:`~allus_company_data.http.HttpClient` owns the
  ``client_credentials`` token, the JSON/XML accept+parse, and the error
  mapping (incl. 429 backoff).
* **Decryption** — the service private key is loaded **once** at construction
  from the configured encrypted PEM + passphrase into an in-memory RSA key; a
  ``decrypt_value`` closure over it is handed to every model factory and the
  pump (config-only key handling — the key never appears in a method signature).
* **Slug catalog** — ``request_fields()`` is fetched once and cached; its
  slug→type map types every value (so ``address`` parses to a dict, ``photo``
  becomes a lazy binary handle, etc.).
* **Binary** — a value's ``BinaryHandle.bytes()`` GETs the slot file endpoint,
  unwraps the API's ``{"encrypted":true,"value":<wrapper>}`` envelope, and runs
  the same service-key decrypt → the file bytes.
* **Changes feed** — ``process_changes`` delegates to the
  :class:`~allus_company_data.pump.Pump`, injecting a ``fetch_changes`` closure
  (``GET /changes?limit=``, returning the raw ciphertext events) and a
  ``decrypt`` closure that builds a typed :class:`Change`.
"""

from __future__ import annotations

import base64
import json
import logging
import time
from typing import Any, Callable, Iterator, List, Optional

import requests

from .config import Config
from .crypto import decrypt as crypto_decrypt
from .crypto import encrypt_for_public_key, load_private_key, load_public_key
from .errors import ApiError, ConfigError, DecryptError, RateLimitError
from .http import HttpClient
from .models import Change, Connection, Document, LogEntry, RequestField
from .pump import Pump
from . import webhooks as _webhooks

# Endpoint paths (the API base comes from Config; HttpClient joins them).
_BASE = "/api/company-data"
_CONNECTIONS = f"{_BASE}/connections"
_CHANGES = f"{_BASE}/changes"
_REQUEST_FIELDS = f"{_BASE}/request-fields"
_LOGS = f"{_BASE}/logs"
_DOCUMENTS = f"{_BASE}/documents"
_KEYS = "/api/keys"

# Default page size for the connections iterator. The endpoint is heavily
# rate-limited, so we keep pages reasonably large to minimize
# the number of requests for a full sync, while the iterator stays lazy.
_DEFAULT_CONN_PAGE = 100

# Bounded extra backoff for the connections iterator on a surfaced 429. The
# HttpClient already retries a 429 internally; if it still surfaces a
# RateLimitError we honor Retry-After once more here (the connections endpoints
# are expensive snapshots, not a poll target) before re-raising.
_CONN_MAX_429_BACKOFFS = 5
_CONN_DEFAULT_BACKOFF_S = 5.0
_CONN_MAX_BACKOFF_S = 120.0


class Client:
    """The company-data SDK client facade."""

    def __init__(
        self,
        config: Config,
        *,
        http: Optional[HttpClient] = None,
        logger: Optional[logging.Logger] = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._config = config
        self._log = logger or logging.getLogger("allus_company_data.client")
        self._sleep = sleep

        # Transport (auth + JSON/XML + errors). Injectable for tests.
        self._http = http if http is not None else HttpClient(config)

        # Load the service private key ONCE from the configured encrypted PEM +
        # passphrase (config-only key handling). This is the single
        # place the key material is read; a closure over it does every decrypt.
        self._private_key = _load_service_key(config)

        # Load the ACCOUNT private key ONCE too (None unless configured). Reused for
        # every encrypt_payload webhook so we don't re-read the PEM + re-run PBKDF2
        # (~100k iters) per request — same one-time-load discipline as the service
        # key. Config-only key handling: still never a public-method argument.
        self._account_key = _webhooks.load_account_key(config)

        # The slug catalog, fetched once on first request_fields() and cached.
        self._request_fields: Optional[List[RequestField]] = None
        self._type_by_slug: dict[str, Optional[str]] = {}

        # Recipient RSA public keys (by share_code) — cached for per-person document
        # encryption. A public key is immutable + not a secret (fetched live, never configured).
        self._pubkey_cache: dict[str, Any] = {}

    # ── constructors (config-only keys) ────────────────────────────────────────

    @classmethod
    def from_config(cls, path: str, **kwargs: Any) -> "Client":
        """Build from a JSON config file (env vars override secrets)."""
        return cls(Config.from_file(path), **kwargs)

    @classmethod
    def from_env(cls, **kwargs: Any) -> "Client":
        """Build entirely from ``ALLUS_*`` env vars."""
        return cls(Config.from_env(), **kwargs)

    # ── decryption wiring (closures over the loaded key — never a method arg) ──

    def _decrypt_value(self, wrapper: Any) -> str:
        """Decrypt a service-key ciphertext wrapper → plaintext (closes over the key)."""
        return crypto_decrypt(wrapper, self._private_key)

    def _binary_fetch(self, value_url: str) -> Any:
        """Fetch a slot file endpoint and unwrap its ``{"encrypted":true,"value":...}`` envelope.

        Returns the inner ``{"_enc":1,...}`` wrapper, which the
        :class:`~allus_company_data.crypto.BinaryHandle` then decrypts with the
        same service key.
        """
        body = self._http.get(value_url)
        if isinstance(body, dict) and "value" in body:
            return body["value"]
        # Defensive: some shapes might return the wrapper directly.
        return body

    def _type_for_slug(self, slug: str) -> Optional[str]:
        """Resolve a request slug to its field type (loads the catalog once)."""
        if self._request_fields is None:
            self.request_fields()
        return self._type_by_slug.get(slug)

    # ── definitions ────────────────────────────────────────────────────────────

    def request_fields(self) -> List[RequestField]:
        """The cached request-field DEFINITIONS.

        Fetched once from ``GET /api/company-data/request-fields`` and cached for
        the life of the client (it's the company's static config, and it types
        every value). Returns YOUR request config — never the person's fields.
        """
        if self._request_fields is None:
            body = self._http.get(_REQUEST_FIELDS)
            fields = RequestField.list_from_api(body)
            self._request_fields = fields
            self._type_by_slug = {f.slug: f.type for f in fields if f.slug is not None}
        return self._request_fields

    # ── connections (heavily rate-limited — initial sync / reconciliation) ─────

    def connections(
        self, limit: int = _DEFAULT_CONN_PAGE, offset: int = 0
    ) -> Iterator[Connection]:
        """A lazy generator paging the list endpoint, yielding one Connection at a time.

        ``limit`` is the page size; ``offset`` the starting offset. The generator
        auto-pages ``GET /api/company-data/connections?limit&offset`` and yields
        typed :class:`Connection` objects (each ``values[slug]`` already decrypted
        / a lazy binary handle) one at a time — bounded memory for a large book.

        The connections endpoints are **heavily rate-limited**:
        use this for the initial full sync + occasional reconciliation, never as a
        poll substitute for the changes feed. On a surfaced
        :class:`RateLimitError` the generator backs off per ``Retry-After`` and
        retries the page a bounded number of times before re-raising — so it
        paces itself within the limit rather than hammering.
        """
        page = max(1, int(limit))
        cur = max(0, int(offset))
        # Ensure the slug catalog is loaded so values are typed correctly.
        self.request_fields()

        while True:
            body = self._get_connections_page(page, cur)
            items = _list_items(body)
            if not items:
                return
            for obj in items:
                if not isinstance(obj, dict):
                    continue
                yield Connection.from_api(
                    obj,
                    type_for_slug=self._type_for_slug,
                    decrypt_value=self._decrypt_value,
                    binary_fetch=self._binary_fetch,
                    # The list row carries identity (display_name/connected_at) AND
                    # the values map, so the same object is both detail + identity.
                    identity=obj,
                )
            # A short page means we reached the end (no more rows than asked for).
            if len(items) < page:
                return
            cur += page

    def _get_connections_page(self, page: int, offset: int) -> Any:
        """GET one connections page, backing off on a surfaced 429."""
        attempts = 0
        while True:
            try:
                return self._http.get(
                    _CONNECTIONS, params={"limit": page, "offset": offset}
                )
            except RateLimitError as exc:
                attempts += 1
                if attempts > _CONN_MAX_429_BACKOFFS:
                    raise
                delay = _conn_backoff(exc.retry_after, attempts)
                self._log.warning(
                    "connections rate-limited (offset=%d); backoff %.1fs (attempt %d)",
                    offset,
                    delay,
                    attempts,
                )
                if delay:
                    self._sleep(delay)

    def connection(self, id: str) -> Connection:
        """Fetch a single connection by id → one :class:`Connection`.

        ``GET /api/company-data/connections/{id}`` returns ``{connection_id,
        user_id, values}`` and no display_name/connected_at; those identity fields
        simply stay ``None`` (the list endpoint carries them).
        """
        self.request_fields()
        body = self._http.get(f"{_CONNECTIONS}/{id}")
        if isinstance(body, dict) and "items" in body and "values" not in body:
            # Defensive: a single-item list shape.
            items = _list_items(body)
            body = items[0] if items else {}
        return Connection.from_api(
            body,
            type_for_slug=self._type_for_slug,
            decrypt_value=self._decrypt_value,
            binary_fetch=self._binary_fetch,
        )

    # ── logs (moderate rate-limit) ──────────────────────────────────────────────

    def logs(self, limit: int = 50, offset: int = 0) -> List[LogEntry]:
        """The service's activity log → ``list[LogEntry]``.

        ``GET /api/company-data/logs?limit&offset``. Ops events only (email /
        purge / webhook) — never person field data.
        """
        body = self._http.get(
            _LOGS, params={"limit": max(1, int(limit)), "offset": max(0, int(offset))}
        )
        return LogEntry.list_from_api(body)

    # ── changes feed — the crash-safe pump ──────────────────────────────────────

    @property
    def pump(self) -> Pump:
        """The crash-safe changes :class:`~allus_company_data.pump.Pump` (built lazily)."""
        if getattr(self, "_pump", None) is None:
            self._pump = Pump(
                self._config,
                fetch_changes=self._fetch_changes,
                decrypt=self._decrypt_change,
                logger=self._log,
                sleep=self._sleep,
            )
        return self._pump

    def _fetch_changes(self, limit: int) -> List[dict]:
        """The pump's drain source: ``GET /changes?limit=`` → raw ciphertext events.

        The feed is drain-on-fetch — this call deletes exactly the
        returned rows server-side, so the pump persists them durably before
        delivery.
        """
        body = self._http.get(_CHANGES, params={"limit": int(limit)})
        items = body.get("changes", []) if isinstance(body, dict) else (body or [])
        return [o for o in items if isinstance(o, dict)]

    def _decrypt_change(self, event: dict) -> Change:
        """The pump's decrypt: a raw event dict → a typed :class:`Change` (value at delivery)."""
        return Change.from_api(
            event,
            type_for_slug=self._type_for_slug,
            decrypt_value=self._decrypt_value,
            binary_fetch=self._binary_fetch,
        )

    def process_changes(self, handler: Callable[[Change], None], **options: Any) -> None:
        """Drain the changes feed through ``handler`` one at a time, crash-safely.

        Delegates to the :class:`~allus_company_data.pump.Pump`: replay the durable
        buffer, drain ≤500 at a time, persist-before-deliver, per-item ack,
        retry→dead-letter→continue, until the feed is empty then return (no daemon
        mode — schedule re-runs yourself). ``handler`` must be idempotent
        (at-least-once; dedup on ``Change.id``). Options:
        ``batch_size`` (≤500), ``max_retries``, ``on_error`` (``deadletter``|``halt``),
        ``backoff``.
        """
        self.request_fields()  # ensure the catalog is loaded for value typing
        self.pump.process_changes(handler, **options)

    def drain_batch(self, max: int = _DEFAULT_CONN_PAGE) -> List[Change]:
        """Raw, UNBUFFERED drain → ``list[Change]`` (advanced — you own durability)."""
        self.request_fields()
        return self.pump.drain_batch(max)

    def dead_letters(self) -> List[dict]:
        """The local dead-letter store."""
        return self.pump.dead_letters()

    def retry_dead_letters(self, handler: Callable[[Change], None], **options: Any) -> int:
        """Re-drive dead-lettered events through ``handler``."""
        self.request_fields()
        return self.pump.retry_dead_letters(handler, **options)

    # ── webhook receiver helpers (config-driven, no key args) ───────────────────

    def verify_webhook(self, raw_body: bytes, headers: dict) -> bool:
        """Verify a webhook's ``X-Allus-Signature`` HMAC."""
        return _webhooks.verify_webhook(raw_body, headers, self._config)

    def parse_webhook(self, raw_body: bytes, headers: dict) -> Change:
        """Parse a webhook body → a typed :class:`Change`."""
        return _webhooks.parse_webhook(
            raw_body,
            headers,
            self._config,
            type_for_slug=self._type_for_slug,
            decrypt_value=self._decrypt_value,
            binary_fetch=self._binary_fetch,
            account_key=self._account_key,  # cached once; no per-webhook PBKDF2
        )

    def handle_webhook(self, raw_body: bytes, headers: dict) -> Change:
        """Verify + parse a webhook in one call → :class:`Change`."""
        return _webhooks.handle_webhook(
            raw_body,
            headers,
            self._config,
            type_for_slug=self._type_for_slug,
            decrypt_value=self._decrypt_value,
            binary_fetch=self._binary_fetch,
            account_key=self._account_key,  # cached once; no per-webhook PBKDF2
        )

    # ── company documents (write) ───────────────────────────────────────────────

    def _recipient_public_key(self, share_code: str):
        """Fetch + cache the recipient RSA public key by share_code (GET /api/keys/{shareCode})."""
        cached = self._pubkey_cache.get(share_code)
        if cached is not None:
            return cached
        body = self._http.get(f"{_KEYS}/{share_code}")
        spki = body.get("public_key") if isinstance(body, dict) else None
        if not spki:
            raise ApiError(0, "keys.not_found", f"no public_key for share_code {share_code}")
        key = load_public_key(spki)
        self._pubkey_cache[share_code] = key
        return key

    def _resolve_share_code(
        self, connection_id: Optional[str], person_user_id: Optional[str]
    ) -> str:
        """Resolve a target's share_code (the recipient public-key handle).

        Prefers a single-connection fetch (carries ``share_code``); falls back to a
        connections scan by ``user_id``. Pass ``share_code=`` to skip this entirely.
        """
        if connection_id:
            body = self._http.get(f"{_CONNECTIONS}/{connection_id}")
            sc = body.get("share_code") if isinstance(body, dict) else None
            if sc:
                return str(sc)
        if person_user_id:
            for conn in self.connections():
                raw = getattr(conn, "raw", {}) or {}
                if raw.get("user_id") == person_user_id or conn.person_id == person_user_id:
                    sc = raw.get("share_code")
                    if sc:
                        return str(sc)
        raise ConfigError(
            "could not resolve a share_code for the target — pass share_code= explicitly"
        )

    def create_document(
        self, *, kind: str = "document", name: str, payload_kind: str,
        is_private: bool = False, description: Optional[str] = None,
        connection_id: Optional[str] = None, person_user_id: Optional[str] = None,
        share_code: Optional[str] = None,            # recipient handle for per-person encryption
        json_value: Any = None, file_bytes: Optional[bytes] = None,
        file_mime: Optional[str] = None,
        metadata: Optional[dict] = None, status: Optional[str] = None,
    ) -> Document:
        """Create a company document for a connection / person (PER-PERSON), or BROADCAST (no target).

        payload_kind='json' → json_value (object). payload_kind='file' → file_bytes (+ file_mime).

        Encryption is decided by the TARGET, not by is_private:
          PER-PERSON (connection_id/person_user_id given) → the value is ALWAYS encrypted FOR
            THE RECIPIENT (share_code resolved from connection_id/person_user_id when not given)
            before it leaves the process — for EVERY per-person doc, private or not. The server
            stores ciphertext. NO key argument.
          BROADCAST (no target) → the value is sent PLAINTEXT (you cannot single-key-encrypt to
            all of a service's connections). A broadcast MUST be non-private (a plaintext value
            cannot be locked); is_private=True therefore requires a per-person target.

        is_private is a DISPLAY-ONLY flag passed through to the API — it governs the recipient
        device's lock vs decrypt-on-load behaviour, NOT whether the value is encrypted.
        """
        if payload_kind not in ("json", "file"):
            raise ConfigError("payload_kind must be 'json' or 'file'")
        target = None
        if connection_id:
            target = {"connection_id": connection_id}
        elif person_user_id:
            target = {"person_user_id": person_user_id}
        # (else: broadcast — target stays None)

        per_person = target is not None
        if is_private and not per_person:
            # A plaintext broadcast cannot be locked — is_private needs a per-person target.
            raise ConfigError("is_private=True requires a per-person target (broadcast is plaintext)")

        pubkey = None
        if per_person:
            # EVERY per-person doc is encrypted, private or not — fetch the recipient key.
            sc = share_code or self._resolve_share_code(connection_id, person_user_id)
            pubkey = self._recipient_public_key(sc)

        body: dict = {"kind": kind, "name": name, "payload_kind": payload_kind,
                      "is_private": bool(is_private), "target": target}
        if description is not None:
            body["description"] = description
        if metadata is not None:
            body["metadata"] = metadata
        if status is not None:
            body["status"] = status

        if payload_kind == "json":
            if json_value is None:
                raise ConfigError("json_value is required for payload_kind='json'")
            body["value"] = (
                encrypt_for_public_key(json.dumps(json_value), pubkey) if per_person else json_value
            )
            created = self._http.post(_DOCUMENTS, json_body=body)
            return Document.from_api(_doc_obj(created), decrypt_value=self._decrypt_value)

        # file: create the metadata row first, then upload bytes to /{id}/file.
        if file_bytes is None:
            raise ConfigError("file_bytes is required for payload_kind='file'")
        created = self._http.post(_DOCUMENTS, json_body=body)
        doc = Document.from_api(_doc_obj(created), decrypt_value=self._decrypt_value)
        if per_person:
            # Encrypt the file bytes (EVERY per-person doc): wrap the file envelope string,
            # then send the wrapper as bytes.
            envelope = json.dumps({"file": _data_uri(file_bytes, file_mime)})
            wrapper = encrypt_for_public_key(envelope, pubkey)
            self._http.post(f"{_DOCUMENTS}/{doc.id}/file",
                            raw_body=json.dumps(wrapper).encode("utf-8"),
                            content_type="application/json")
        else:
            # Broadcast — raw plaintext bytes.
            self._http.post(f"{_DOCUMENTS}/{doc.id}/file",
                            raw_body=file_bytes,
                            content_type=file_mime or "application/octet-stream")
        return doc

    def list_documents(self, *, person_user_id: Optional[str] = None,
                       status: Optional[str] = None, limit: int = 100, offset: int = 0):
        """List this service's documents → ``list[Document]`` (paged; optional person/status filter)."""
        params: dict = {"limit": max(1, int(limit)), "offset": max(0, int(offset))}
        if person_user_id:
            params["person_user_id"] = person_user_id
        if status:
            params["status"] = status
        body = self._http.get(_DOCUMENTS, params=params)
        return Document.list_from_api(body, decrypt_value=self._decrypt_value)

    def document(self, document_id: str) -> Document:
        """Fetch one document by id → :class:`Document`."""
        body = self._http.get(f"{_DOCUMENTS}/{document_id}")
        return Document.from_api(_doc_obj(body), decrypt_value=self._decrypt_value)

    def update_document_status(self, document_id: str, status: str) -> Document:
        """Set a document's lifecycle status (offering|ready_to_sign|active|active_but_ending|ended)."""
        body = self._http.put(f"{_DOCUMENTS}/{document_id}", json_body={"status": status})
        return Document.from_api(_doc_obj(body), decrypt_value=self._decrypt_value)

    def update_document_metadata(self, document_id: str, *, metadata: Optional[dict] = None,
                                 name: Optional[str] = None, description: Optional[str] = None) -> Document:
        """Update a document's metadata / name / description."""
        payload: dict = {}
        if metadata is not None:
            payload["metadata"] = metadata
        if name is not None:
            payload["name"] = name
        if description is not None:
            payload["description"] = description
        if not payload:
            raise ConfigError("update_document_metadata needs metadata, name, or description")
        body = self._http.put(f"{_DOCUMENTS}/{document_id}", json_body=payload)
        return Document.from_api(_doc_obj(body), decrypt_value=self._decrypt_value)

    def delete_document(self, document_id: str) -> None:
        """Delete a document (and its on-disk file)."""
        self._http.delete(f"{_DOCUMENTS}/{document_id}")


# ── module-level helpers ──────────────────────────────────────────────────────


def _load_service_key(config: Config):
    """Read the configured encrypted PEM and decrypt it with the passphrase (once)."""
    try:
        with open(config.service_private_key, "rb") as fh:
            pem_bytes = fh.read()
    except OSError as exc:
        raise ConfigError(
            f"could not read service_private_key PEM: {config.service_private_key}: {exc}"
        ) from exc
    try:
        return load_private_key(pem_bytes, config.key_passphrase)
    except DecryptError as exc:
        # A bad passphrase / malformed PEM is a configuration problem (fail fast).
        raise ConfigError(f"could not load service private key: {exc}") from exc


def _doc_obj(body: Any) -> dict:
    """Pull the document object out of a create/get/update response.

    The API returns the bare document object; tolerate a ``{"document": {...}}`` wrapper too.
    """
    if isinstance(body, dict):
        inner = body.get("document")
        if isinstance(inner, dict):
            return inner
        return body
    return {}


def _data_uri(file_bytes: bytes, mime: Optional[str]) -> str:
    """Build a ``data:<mime>;base64,<…>`` URI for the per-person file envelope."""
    b64 = base64.b64encode(file_bytes).decode("ascii")
    return f"data:{mime or 'application/octet-stream'};base64,{b64}"


def _list_items(body: Any) -> List[Any]:
    """Pull the ``items`` array out of a ``{total, items}`` list response."""
    if isinstance(body, dict):
        items = body.get("items")
        if items is None:
            return []
        return list(items)
    if isinstance(body, list):
        return body
    return []


def _conn_backoff(retry_after: Optional[float], attempt: int) -> float:
    """Backoff before retrying a rate-limited connections page."""
    if retry_after is not None and retry_after >= 0:
        return min(retry_after, _CONN_MAX_BACKOFF_S)
    return min(_CONN_DEFAULT_BACKOFF_S * (2 ** (attempt - 1)), _CONN_MAX_BACKOFF_S)


__all__ = ["Client"]
