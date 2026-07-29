"""The CUSTOMER-role client.

``CustomerClient`` is what a *connecting company* uses to consume and answer
another company's service over its ``acct_*`` credentials: list its company↔company
connections, provide/edit typed answers to consent requests, read (and decrypt)
issued documents, run contract flows, drain the account change feed, and verify
account-level webhooks. It reuses the same crash-safe pump, webhook helpers, and
hybrid-crypto core as the service :class:`~allus_company_data.client.Client`.

**No sign/accept methods (spec D6).** Signing/accepting a contract is a deliberate
human step-up that stays portal-only; a machine ``acct_*`` token is rejected by the
API for those routes, so this SDK deliberately exposes no ``sign``/``accept``.

Key sourcing (config-only, never a method argument):
  * typed answers to a service      → the TARGET service public key (``/api/keys/{c}/{s}``)
  * a flow party that is the customer itself → the customer's own ACCOUNT public key (``/api/keys/batch``)
  * a flow party that is the owning company  → that service's key (``/api/keys/{c}/{s}``)
  * a flow party that is a person             → the person key (``/api/keys/batch``)
  * received documents / flow copies → decrypted with the customer's ACCOUNT private key
"""

from __future__ import annotations

import dataclasses
import json
import threading
import logging
import time
from typing import Any, Callable, List, Optional

from . import webhooks as _webhooks
from .config import Config
from .crypto import decrypt as crypto_decrypt, encrypt_for_public_key, load_public_key
from .customer_models import CustomerConnection
from .errors import ConfigError, ValidationError
from .field_validation import is_field_value_valid
from .http import HttpClient
from .models import Change, Document, FlowRun
from .pump import Pump

_CONN = "/api/company-connections"
_CONSENTS = "/api/company-connections/consents"
_CUSTOMER_CHANGES = "/api/customer/changes"
_KEYS = "/api/keys"
_DEFAULT_PAGE = 100


class CustomerClient:
    """B2B customer-side facade. See the module docstring; NO sign/accept (D6)."""

    def __init__(
        self,
        config: Config,
        *,
        http: Optional[HttpClient] = None,
        logger: Optional[logging.Logger] = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not config.customer_client_id or not config.customer_client_secret:
            raise ConfigError(
                "CustomerClient requires customer_client_id + customer_client_secret "
                "(load with Config.from_customer_file / from_customer_env)"
            )
        self._config = config
        self._log = logger or logging.getLogger("allus_company_data.customer")
        self._sleep = sleep
        # The transport authenticates as the acct_* client. HttpClient reads
        # config.client_id/secret, so hand it a copy pointed at the customer pair.
        http_config = dataclasses.replace(
            config,
            client_id=config.customer_client_id,
            client_secret=config.customer_client_secret,
        )
        self._http = http if http is not None else HttpClient(http_config)
        # ACCOUNT private key — decrypts received documents/flow copies. Loaded once.
        self._account_key = _webhooks.load_account_key(config)
        self._pubkey_cache: dict[str, Any] = {}
        # A per-key GENERATION counter plus a real LOCK, bumped/held by every invalidation.
        #
        # The fetch path is check -> HTTP -> store, and ``invalidate_public_key`` -- which the
        # README tells webhook consumers to call from their own handler -- may run in that window
        # from another thread. Its pop would then be silently undone by the store that follows, the
        # ``key_rotated`` event has already been consumed, and with no TTL the process encrypts to
        # the dead key for the rest of its life.
        #
        # The lock is NOT optional and the GIL is not a substitute: the invariant spans multiple
        # bytecodes (compare the generation, then assign), so a thread can pass the comparison, be
        # switched out, let another thread delete + increment, then resume and write the
        # pre-rotation key back. Individual dict ops being atomic does not help. The lock therefore
        # covers invalidation's delete+increment, and the fetch's check/snapshot and its
        # compare-and-store -- but is never held across the HTTP call.
        self._pubkey_gen: dict[str, int] = {}
        self._pubkey_lock = threading.Lock()
        self._service_key_cache: dict[str, Any] = {}
        # The SERVICE key cache has an invalidator too (``invalidate_service_key``, driven by
        # the ``service_key_rotated`` change), so it needs the same generation counter and
        # lock, for exactly the reason spelled out above — a separate lock so a person-key
        # fetch and a service-key fetch never serialise on each other.
        self._service_key_gen: dict[str, int] = {}
        self._service_key_lock = threading.Lock()
        # _request_type_cache: "company_code/service_code" → {request_field_id: field_type},
        # resolved from the connect-screen lookup for typed-answer validation.
        self._request_type_cache: dict[str, dict[str, str]] = {}
        self._pump: Optional[Pump] = None

    # ── constructors (config-only keys) ─────────────────────────────────────────

    @classmethod
    def from_config(cls, path: str, **kwargs: Any) -> "CustomerClient":
        """Build from a customer-role JSON config file."""
        return cls(Config.from_customer_file(path), **kwargs)

    @classmethod
    def from_env(cls, **kwargs: Any) -> "CustomerClient":
        """Build entirely from ``ALLUS_*`` env vars (customer role)."""
        return cls(Config.from_customer_env(), **kwargs)

    # ── connections ─────────────────────────────────────────────────────────────

    def connections(self) -> List[CustomerConnection]:
        """List the customer's company↔company connections (``GET /api/company-connections``).

        Received company profile + per-service shared values are plaintext; the
        customer's OWN typed answers are never re-read (it typed them).
        """
        return CustomerConnection.list_from_api(self._http.get(_CONN))

    def connection(self, id: str) -> CustomerConnection:
        """One connection's full structure (``GET /api/company-connections/{id}``)."""
        return CustomerConnection.from_api(self._http.get(f"{_CONN}/{id}"))

    # ── consents (typed answers) ────────────────────────────────────────────────

    def pending_consents(self) -> List[dict]:
        """Pending consent requests (``GET /api/company-connections/consents``)."""
        body = self._http.get(_CONSENTS)
        if isinstance(body, dict):
            return body.get("consents") or body.get("items") or []
        return body or []

    def provide_consent(
        self, consent_id: str, answers: List[dict], *, company_code: str, service_code: str
    ) -> Any:
        """Answer a consent's request rows by TYPING values (kind ``typed``/``one_time``).

        Each ``answers`` entry is ``{request_field_id, value, kind?}``; ``value`` is
        the plaintext the customer types — it is encrypted here to the target
        SERVICE public key before sending. Each value is validated against its request
        row's field type (resolved from the connect-screen lookup, cached) first.
        """
        decisions = self._encrypt_typed(answers, company_code, service_code)
        return self._http.post(
            f"{_CONSENTS}/{consent_id}/provide", json_body={"decisions": decisions}
        )

    def decline_consent(self, consent_id: str) -> Any:
        """Decline a consent (grandfathered — the connection stays active)."""
        return self._http.post(f"{_CONSENTS}/{consent_id}/decline")

    def edit_answers(
        self, connection_id: str, service_link_id: str, answers: List[dict],
        *, company_code: str, service_code: str,
    ) -> Any:
        """Re-type + re-encrypt already-answered mappings (``PUT .../mappings``)."""
        decisions = self._encrypt_typed(answers, company_code, service_code)
        return self._http.put(
            f"{_CONN}/{connection_id}/services/{service_link_id}/mappings",
            json_body={"decisions": decisions},
        )

    # ── documents (account-key decrypt; NO sign/accept — D6) ─────────────────────

    def documents(self, connection: CustomerConnection) -> List[Document]:
        """The documents issued to this connection (from its payload)."""
        docs: List[Document] = []
        for svc in connection.services:
            for d in svc.raw.get("documents") or []:
                if isinstance(d, dict):
                    docs.append(Document.from_api(d, decrypt_value=self._decrypt_account))
        for d in connection.raw.get("documents") or []:
            if isinstance(d, dict):
                docs.append(Document.from_api(d, decrypt_value=self._decrypt_account))
        return docs

    def document_file(self, connection_id: str, document_id: str) -> Any:
        """Fetch + decrypt a document's file blob with the ACCOUNT private key.

        Broadcast files are plaintext; per-person (per-customer) files are an
        ``{"_enc":1,…}`` / ``{"_enc_file":…}`` wrapper decrypted here.
        """
        body = self._http.get(f"{_CONN}/{connection_id}/documents/{document_id}/file")
        if isinstance(body, dict) and body.get("encrypted") and "value" in body:
            return json.loads(self._decrypt_account(body["value"]))
        if isinstance(body, dict) and body.get("_enc") == 1:
            return json.loads(self._decrypt_account(body))
        return body

    def cancel_document(self, connection_id: str, document_id: str, *, note: Optional[str] = None) -> Any:
        """Cancel an in-app-cancellable document (``POST .../documents/{id}/cancel``)."""
        payload = {"note": note} if note else None
        return self._http.post(
            f"{_CONN}/{connection_id}/documents/{document_id}/cancel", json_body=payload
        )

    # ── contract flows ──────────────────────────────────────────────────────────

    def flow_runs(self, connection_id: str) -> List[FlowRun]:
        """The flow runs on a connection (``GET /api/company-connections/{id}/flow-runs``)."""
        body = self._http.get(f"{_CONN}/{connection_id}/flow-runs")
        items = body.get("runs") if isinstance(body, dict) else body
        return [FlowRun.from_api(o) for o in (items or []) if isinstance(o, dict)]

    def flow_run(self, connection_id: str, run_id: str) -> FlowRun:
        """One flow run (``GET /api/company-connections/{id}/flow-runs/{runId}``)."""
        return FlowRun.from_api(self._http.get(f"{_CONN}/{connection_id}/flow-runs/{run_id}"))

    def submit_flow_answers(
        self, connection_id: str, run_id: str, body: dict
    ) -> Any:
        """Submit this party's turn. ``body`` carries the already-encrypted per-party
        ``answers``/``links``/``next_node``; use :meth:`encrypt_flow_answer` to build the
        per-party copies with the correct keys.
        """
        return self._http.post(
            f"{_CONN}/{connection_id}/flow-runs/{run_id}/answers", json_body=body
        )

    def decline_flow_run(self, connection_id: str, run_id: str) -> Any:
        """Decline a flow run (``POST .../flow-runs/{runId}/decline``)."""
        return self._http.post(f"{_CONN}/{connection_id}/flow-runs/{run_id}/decline")

    def encrypt_flow_answer(
        self, plaintext: str, party: dict, *, company_code: str, service_code: str
    ) -> dict:
        """Encrypt one answer value for one flow ``party`` per the P4 key rule.

        ``party`` = ``{user_id, type, is_owner?}``: the owning company → that
        service's key; the customer itself or a person → the ``/keys/batch`` key
        (which returns account keys for company ids post-P1).
        """
        if party.get("is_owner"):
            pub = self._service_key(company_code, service_code)
        else:
            pub = self._batch_key(str(party.get("user_id")))
        if pub is None:
            raise ConfigError(f"no public key available for party {party.get('user_id')}")
        return encrypt_for_public_key(plaintext, pub)

    # ── change feed (P2 account feed) ───────────────────────────────────────────

    @property
    def pump(self) -> Pump:
        if self._pump is None:
            self._pump = Pump(
                self._config,
                fetch_changes=self._fetch_changes,
                decrypt=self._decrypt_change,
                logger=self._log,
                sleep=self._sleep,
            )
        return self._pump

    def _fetch_changes(self, limit: int) -> List[dict]:
        body = self._http.get(_CUSTOMER_CHANGES, params={"limit": int(limit)})
        items = body.get("changes", []) if isinstance(body, dict) else (body or [])
        return [o for o in items if isinstance(o, dict)]

    def invalidate_public_key(self, user_id: str) -> None:
        """Drop a person's cached RSA public key, by user id.

        See :meth:`Client.invalidate_public_key`; the changes feed calls this for you, webhook
        consumers must call it themselves.
        """
        with self._pubkey_lock:
            self._pubkey_cache.pop(user_id, None)
            # Any fetch already in flight must not write its stale result back.
            self._pubkey_gen[user_id] = self._pubkey_gen.get(user_id, 0) + 1

    def invalidate_service_key(self, company_code: str, service_code: str) -> None:
        """Drop a SERVICE's cached RSA public key.

        The mirror of :meth:`invalidate_public_key` in the service→customer direction: the next
        answer or document encrypted to that service refetches its key. The changes feed calls this
        for you on a ``service_key_rotated`` event; webhook consumers must call it themselves with
        the body's ``company_share_code`` and ``service_share_code``.
        """
        key = f"{company_code}/{service_code}"
        with self._service_key_lock:
            self._service_key_cache.pop(key, None)
            # Any fetch already in flight must not write its stale result back.
            self._service_key_gen[key] = self._service_key_gen.get(key, 0) + 1

    def _decrypt_change(self, event: dict) -> Change:
        # Customer events are self-describing (about a company/service); there is
        # no person slug catalog, and any encrypted value is account-key material.
        #
        # This cache also stores a negative (None) result, so without invalidation a person
        # who had not generated keys yet would stay unresolvable for the process lifetime too.
        # The pull feed names it `event`; a raw webhook body names it `action` (and on
        # document rows `action` carries signed|accepted|cancelled instead) - so match either key.
        if "key_rotated" in (event.get("event"), event.get("action")):
            person_id = event.get("person_user_id") or event.get("person_id")
            if isinstance(person_id, str) and person_id:
                self.invalidate_public_key(person_id)
        # A service this customer connects to replaced its keypair — drop the cached copy so
        # the next encryption refetches. Same either-key match as above.
        if "service_key_rotated" in (event.get("event"), event.get("action")):
            company_code = event.get("company_share_code")
            service_code = event.get("service_share_code")
            if (
                isinstance(company_code, str)
                and company_code
                and isinstance(service_code, str)
                and service_code
            ):
                self.invalidate_service_key(company_code, service_code)
        return Change.from_api(
            event, type_for_slug=lambda slug: None, decrypt_value=self._decrypt_account
        )

    def process_changes(self, handler: Callable[[Change], None], **options: Any) -> None:
        """Crash-safe drain of ``GET /api/customer/changes`` through ``handler``."""
        self.pump.process_changes(handler, **options)

    def drain_batch(self, max: int = _DEFAULT_PAGE) -> List[Change]:
        """Raw, unbuffered drain → ``list[Change]`` (advanced — you own durability)."""
        return self.pump.drain_batch(max)

    def dead_letters(self) -> List[dict]:
        return self.pump.dead_letters()

    def retry_dead_letters(self, handler: Callable[[Change], None], **options: Any) -> int:
        return self.pump.retry_dead_letters(handler, **options)

    # ── account-level webhook receiver helpers (config-driven) ───────────────────

    def verify_webhook(self, raw_body: bytes, headers: dict) -> bool:
        return _webhooks.verify_webhook(raw_body, headers, self._config)

    def parse_webhook(self, raw_body: bytes, headers: dict) -> Change:
        return _webhooks.parse_webhook(
            raw_body, headers, self._config, account_key=self._account_key
        )

    def handle_webhook(self, raw_body: bytes, headers: dict) -> Change:
        return _webhooks.handle_webhook(
            raw_body, headers, self._config, account_key=self._account_key
        )

    # ── internals ────────────────────────────────────────────────────────────────

    def _decrypt_account(self, wrapper: Any) -> str:
        if self._account_key is None:
            raise ConfigError("account_private_key is required to decrypt this value")
        return crypto_decrypt(wrapper, self._account_key)

    def _request_field_types(self, company_code: str, service_code: str) -> dict[str, str]:
        """Resolve ``{request_field_id: field_type}`` for a service from the connect-screen
        lookup, cached per company/service. Best-effort — a lookup failure yields an empty
        map so typed-answer validation is simply skipped."""
        key = f"{company_code}/{service_code}"
        cached = self._request_type_cache.get(key)
        if cached is not None:
            return cached
        out: dict[str, str] = {}
        try:
            body = self._http.get(f"{_CONN}/lookup/{company_code}/{service_code}")
            rows = body.get("request_fields") if isinstance(body, dict) else None
            for r in rows or []:
                if not isinstance(r, dict):
                    continue
                rid = r.get("id")
                ftype = r.get("field_type") or r.get("type")
                if rid and ftype:
                    out[str(rid)] = str(ftype)
        except Exception:  # noqa: BLE001 — best-effort; a failed lookup skips validation
            out = {}
        self._request_type_cache[key] = out
        return out

    def _encrypt_typed(self, answers: List[dict], company_code: str, service_code: str) -> List[dict]:
        pub = self._service_key(company_code, service_code)
        if pub is None:
            raise ConfigError(f"no service key for {company_code}/{service_code}")
        # Validate each typed answer against its request row's field type BEFORE
        # encryption. The type is resolved server-side from the connect-screen lookup
        # (cached per service); an answer whose type can't be resolved is skipped —
        # never invent one.
        types = self._request_field_types(company_code, service_code)
        out: List[dict] = []
        for a in answers:
            plain = str(a["value"])
            ftype = types.get(str(a["request_field_id"]))
            if ftype and not is_field_value_valid(ftype, plain):
                raise ValidationError(a.get("request_field_id"), ftype)
            entry = {
                "request_field_id": a["request_field_id"],
                "kind": a.get("kind", "typed"),
                "value": encrypt_for_public_key(plain, pub),
            }
            out.append(entry)
        return out

    def _service_key(self, company_code: str, service_code: str):
        key = f"{company_code}/{service_code}"
        # ``in``, not a None check: a None value is a CACHED NEGATIVE and must still count as a hit.
        with self._service_key_lock:
            if key in self._service_key_cache:
                return self._service_key_cache[key]
            gen = self._service_key_gen.get(key, 0)
        body = self._http.get(f"{_KEYS}/{company_code}/{service_code}")
        spki = body.get("public_key") if isinstance(body, dict) else None
        loaded = load_public_key(spki) if spki else None
        # Store ONLY if no invalidation happened while the request was in flight. The compare
        # and the assignment must be one critical section — see the note on the lock above.
        with self._service_key_lock:
            if self._service_key_gen.get(key, 0) == gen:
                self._service_key_cache[key] = loaded
        return loaded

    def _batch_key(self, user_id: str):
        # ``in``, not a None check: a None value is a CACHED NEGATIVE (person has no key yet) and
        # must still count as a hit.
        with self._pubkey_lock:
            if user_id in self._pubkey_cache:
                return self._pubkey_cache[user_id]
            gen = self._pubkey_gen.get(user_id, 0)
        body = self._http.post(f"{_KEYS}/batch", json_body={"user_ids": [user_id]})
        keys = body.get("keys") if isinstance(body, dict) else None
        spki = keys.get(user_id) if isinstance(keys, dict) else None
        loaded = load_public_key(spki) if spki else None
        # Store ONLY if no invalidation happened while the request was in flight. The compare and
        # the assignment must be one critical section — see the note on the lock above.
        with self._pubkey_lock:
            if self._pubkey_gen.get(user_id, 0) == gen:
                self._pubkey_cache[user_id] = loaded
        return loaded
