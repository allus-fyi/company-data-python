"""Company-data scenario handlers (contract family: ``companydata:*``).

Five scenarios, all built from the SERVICE-role data :class:`Client`, all through the
INTENDED allus SDK surface (no raw platform HTTP, no SDK internals):

    read        — Client.connections()     -> connection-grouped decrypted values
    definitions — Client.request_fields()   -> your request-field catalog
    changes     — Client.process_changes()  -> a crash-safe pump drain (idempotent on Change.id)
    webhook     — verify_webhook()+parse_webhook() -> a public POST /webhook receiver + a
                                              drain_batch() feed fallback; ONE accumulating run
    documents   — Client.create_document() ×6 -> the six document/contract types

``config()`` writes the browser's setup values to a canonical SDK config FILE;
``start()`` builds the Client from that file (``Client.from_config`` ->
``Config.from_file``) and runs OFF it. A ``/start`` with no saved config -> ``409
not_configured``.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any, Callable, Dict, List, Optional, Set

from allus_company_data import Client, Config, HttpClient, WebhookError
from allus_company_data.crypto import BinaryHandle

from ..common import (
    Response,
    TimeoutSession,
    header,
    json_response,
    parse_body,
    text_response,
)
from ..runtime import Runtime, record_call

READ = "companydata:read"
DEFINITIONS = "companydata:definitions"
CHANGES = "companydata:changes"
WEBHOOK = "companydata:webhook"
DOCUMENTS = "companydata:documents"

# id -> "runnable". Every company-data scenario runs synchronously (data) or accumulates (webhook).
SCENARIOS: Dict[str, str] = {
    READ: "runnable",
    DEFINITIONS: "runnable",
    CHANGES: "runnable",
    WEBHOOK: "runnable",
    DOCUMENTS: "runnable",
}

# Scenarios whose SDK Client uses the pump (needs a cache_dir for its buffer/dead-letters).
PUMP_SCENARIOS = (CHANGES, WEBHOOK)

DEFAULT_API_URL = "https://api.allme.fyi"

# The webhook change-feed fallback runs one drain_batch() per poll; a small network
# timeout on its SDK session keeps a blackholed feed from pinning the single worker.
FEED_TIMEOUT_S = 3.0

# ── the "what just happened" trace (#578) ─────────────────────────────────────
# Every entry is ``<SDK method> — <what that call did in THIS scenario>``, appended AT
# the call site, in the order the calls were made; an entry wrapped in parentheses is a
# step that is deliberately NOT an SDK call. The annotations are byte-identical in all
# six SDK examples — only the method reference is written in the language's own idiom —
# so one scenario teaches one thing whichever example a reader starts. Keep them in step
# when this handler changes.
CALL_SERVICE_BUILD = (
    "Client.from_config — builds the SERVICE-role data client from the saved config file: "
    "client credentials plus the service private key, decrypted with its passphrase"
)
# The webhook scenario needs a network-timeout session, which the from_config wrapper
# cannot set, so it constructs the same service-role client the long way round.
CALL_SERVICE_BUILD_FILE = (
    "Client(Config.from_file(…)) — builds the SERVICE-role data client from the saved config "
    "file: client credentials plus the service private key, decrypted with its passphrase"
)
CALL_CONNECTIONS = (
    "Client.connections — pages GET /api/company-data/connections: loads your request-field "
    "catalog first for value typing, then decrypts each person's values with the service key"
)
CALL_REQUEST_FIELDS = (
    "Client.request_fields — GET /api/company-data/request-fields: your own request-field "
    "catalog, fetched once and cached for the life of the client"
)
CALL_PROCESS_CHANGES = (
    "Client.process_changes — drains the change feed through the crash-safe pump: handler "
    "before ack, at-least-once (dedup on Change.id), failures to the local dead-letter store"
)
CALL_CREATE_DOCUMENT = "Client.create_document — {label}"
CALL_WEBHOOK_STARTED = (
    "(webhook run started) — POST /webhook receives each delivery; every poll also drains the "
    "change feed as a fallback"
)
CALL_VERIFY_WEBHOOK = (
    "Client.verify_webhook — checks the delivery's X-Allus-Signature HMAC against the secret "
    "configured for its X-Allus-Webhook-Id; a failure answers 401"
)
CALL_PARSE_WEBHOOK = (
    "Client.parse_webhook — turns the verified body into a typed Change, decrypting its value "
    "with the service key"
)
CALL_DRAIN_BATCH = (
    "Client.drain_batch — the per-poll feed fallback: one unbuffered drain, so events still show "
    "up when no delivery can reach this machine"
)

_HDR_WEBHOOK_ID = "x-allus-webhook-id"


class CompanyDataHandlers:
    """The company-data family, bound to the shared runtime."""

    def __init__(self, rt: Runtime) -> None:
        self.rt = rt

    def scenario_list(self) -> List[Dict[str, Any]]:
        return [{"id": i, "kind": k} for i, k in SCENARIOS.items()]

    def is_scenario(self, scenario_id: str) -> bool:
        return scenario_id in SCENARIOS

    def clear(self, scenario_id: str) -> Response:
        """Delete the scenario's run files + config + meta, drop the route (webhook), wipe
        the pump cache, then GC unreferenced key PEMs."""
        if not self.is_scenario(scenario_id):
            return json_response({"error": "not_found"}, 404)
        self.rt.clear_scenario(scenario_id)
        if scenario_id == WEBHOOK:
            self.rt.clear_route()
        self.rt.wipe_cache()
        return json_response({"ok": True})

    # ── POST /api/scenarios/{id}/config ──────────────────────────────────────

    def config(self, scenario_id: str, body: bytes) -> Response:
        """Write the browser's setup values to a canonical SDK config FILE. Every company-data
        scenario uses the SERVICE-role Client, so the config always carries
        client_id/secret + the service PEM (by path) + passphrase. The webhook scenario adds
        the ``webhooks: {id: secret}`` map (the SDK selects the secret by the
        ``X-Allus-Webhook-Id`` header) and records the webhook id in the meta sidecar (the
        routing key ``/start`` needs). The documents scenario records the target share code."""
        if scenario_id not in SCENARIOS:
            return json_response({"error": "not_found"}, 404)
        data = parse_body(body)

        # Canonical SDK config — the service role for every company-data scenario.
        cfg: Dict[str, Any] = {
            "api_url": (str(data.get("apiUrl") or "") or DEFAULT_API_URL).rstrip("/"),
            "client_id": str(data.get("clientId") or ""),
            "client_secret": str(data.get("clientSecret") or ""),
            "key_passphrase": str(data.get("keyPassphrase") or ""),
        }
        pem = str(data.get("servicePrivateKeyPem") or "")
        if pem:
            cfg["service_private_key"] = self.rt.materialize_config_key(pem)

        # Pump scenarios persist their buffer/dead-letters under .runtime/cache (Config.cache_dir).
        if scenario_id in PUMP_SCENARIOS:
            cfg["cache_dir"] = self.rt.cache_dir

        meta: Dict[str, Any] = {}
        if scenario_id == WEBHOOK:
            # The verifier selects the secret by the delivery's X-Allus-Webhook-Id header, so the
            # config's webhooks map must be keyed by the real webhook id.
            webhook_id = str(data.get("webhookId") or "")
            secret = str(data.get("webhookSecret") or "")
            if webhook_id and secret:
                cfg["webhooks"] = {webhook_id: secret}
            if webhook_id:
                meta["webhook_id"] = webhook_id  # the routing key /start writes into the route record
        if scenario_id == DOCUMENTS:
            meta["share_code"] = str(data.get("shareCode") or "")  # the per-person/contract target

        config_path = self.rt.write_config(scenario_id, cfg)
        self.rt.write_config_meta(scenario_id, meta)

        return json_response({"ok": True, "configPath": config_path})

    # ── POST /api/scenarios/{id}/start ────────────────────────────────────────

    def start(self, scenario_id: str) -> Response:
        if scenario_id not in SCENARIOS:
            return json_response({"error": "not_found"}, 404)
        if not self.rt.has_config(scenario_id):
            # The run is built from the persisted config file, not the request body.
            return json_response({"error": "not_configured"}, 409)

        if scenario_id == READ:
            return self._data_run(scenario_id, self._do_read)
        if scenario_id == DEFINITIONS:
            return self._data_run(scenario_id, self._do_definitions)
        if scenario_id == CHANGES:
            return self._data_run(scenario_id, self._do_changes)
        if scenario_id == DOCUMENTS:
            return self._data_run(scenario_id, self._do_documents)
        if scenario_id == WEBHOOK:
            return self._start_webhook()
        return json_response({"error": "not_found"}, 404)  # unreachable

    def _data_run(
        self, scenario_id: str, do: Callable[[Client, List[str]], Dict[str, Any]]
    ) -> Response:
        """Run a synchronous data scenario: build the Client from the config file, run the SDK
        call, store the terminal result. The outcome is read once via GET /api/runs
        (action {type:"data"}). A start-time failure surfaces as a ``failed`` run."""
        run_id = self.rt.new_run_id()
        calls: List[str] = []
        try:
            calls.append(CALL_SERVICE_BUILD)
            client = Client.from_config(self.rt.config_path_for(scenario_id))
            result = do(client, calls)
            self.rt.write_run(run_id, {"scenario": scenario_id, "status": "done", "result": result, "calls": calls})
        except Exception as exc:  # noqa: BLE001
            self.rt.write_run(run_id, {"scenario": scenario_id, "status": "failed", "error": str(exc), "calls": calls})
        return json_response({"runId": run_id, "action": {"type": "data"}})

    # companydata:read — Client.connections() grouped BY connection (one card per person), so two
    # people who both filled the same slug stay distinguishable.
    def _do_read(self, client: Client, calls: List[str]) -> Dict[str, Any]:
        calls.append(CALL_CONNECTIONS)
        connections = []
        for conn in client.connections():
            values = [
                {
                    "slug": str(slug),
                    "value": _stringify(v.value),
                    "live": v.live,
                    "at": _iso(v.updated_at),
                }
                for slug, v in conn.values.items()
            ]
            connections.append({
                "connectionId": conn.id,
                "personId": conn.person_id,
                "displayName": conn.display_name,
                "customerType": conn.customer_type,
                "shareCode": conn.share_code,
                "values": values,
            })
        return {"connections": connections}

    # companydata:definitions — Client.request_fields() → your request-field catalog (the folded
    # mandatory bool + one_time; the raw split flags are debug-only, off the intended surface).
    def _do_definitions(self, client: Client, calls: List[str]) -> Dict[str, Any]:
        calls.append(CALL_REQUEST_FIELDS)
        fields = [
            {"slug": f.slug, "label": f.label, "type": f.type, "mandatory": f.mandatory, "one_time": f.one_time}
            for f in client.request_fields()
        ]
        return {"fields": fields}

    # companydata:changes — Client.process_changes() drains the feed on start through the crash-safe
    # pump (handler-before-ack, at-least-once), so the append handler is idempotent on the pull-feed
    # Change.id.
    def _do_changes(self, client: Client, calls: List[str]) -> Dict[str, Any]:
        calls.append(CALL_PROCESS_CHANGES)
        events: List[Dict[str, Any]] = []
        seen: Set[str] = set()

        def handler(c) -> None:
            if c.id is not None:
                if c.id in seen:
                    return  # idempotent: the pump may replay after a crash — dedup on Change.id
                seen.add(c.id)
            events.append(_project_change(c, None))

        client.process_changes(handler)
        return {"events": events, "drained": True}

    # companydata:documents — Client.create_document() for each of the six document/contract types
    # (payloads verbatim from apitests/php/documents.php). The per-person / private / contract types
    # target the connected person by share code (from the setup sidecar).
    def _do_documents(self, client: Client, calls: List[str]) -> Dict[str, Any]:
        share_code = str(self.rt.read_config_meta(DOCUMENTS).get("share_code") or "")
        specs = _document_specs()
        docs = []
        for i, spec in enumerate(specs):
            opts = dict(spec["opts"])
            if spec["perPerson"]:
                if not share_code:
                    raise RuntimeError(
                        "this document type targets a connected person — set a target person "
                        "share code in the setup, then re-run"
                    )
                opts["share_code"] = share_code
            calls.append(CALL_CREATE_DOCUMENT.format(label=spec["label"]))
            doc = client.create_document(**opts)
            docs.append({"index": i + 1, "label": spec["label"], "document_id": doc.id, "status": doc.status})
        return {"docs": docs}

    # ── companydata:webhook — the accumulating run + public receiver ──────────

    def _start_webhook(self) -> Response:
        """Start the single accumulating webhook run. Persists the routing record
        webhookId -> runId (superseding any prior active webhook run) and returns
        {action:{type:"none"}} — there is NO long-poll (it would wedge the single worker).
        Events arrive via POST /webhook and via a per-poll drain_batch() feed fallback."""
        webhook_id = str(self.rt.read_config_meta(WEBHOOK).get("webhook_id") or "")
        if not webhook_id:
            return json_response({"error": "not_configured"}, 409)
        run_id = self.rt.new_run_id()
        self.rt.write_run(run_id, {
            "scenario": WEBHOOK,
            "status": "pending",  # accumulating — the v1 enum is unchanged
            "webhookId": webhook_id,
            "events": [],
            "seenFeedIds": [],  # feed-only dedup set for the drain_batch() fallback
            "unparseable": 0,
            "calls": [CALL_WEBHOOK_STARTED],
        })
        self.rt.write_route(webhook_id, run_id)
        return json_response({"runId": run_id, "action": {"type": "none"}})

    def webhook(self, body: bytes, headers: Dict[str, str]) -> Response:
        """POST /webhook — the PUBLIC inbound delivery. The exact call/status sequence (never the
        combined handle_webhook(), which raises one WebhookError for BOTH bad-HMAC and a parse
        failure):
          (1) read X-Allus-Webhook-Id; unknown/stale id or no active run -> 200 acknowledge-and-discard.
          (2) verify_webhook(): False -> 401 (a genuine signature failure; misconfiguration is loud).
          (3) parse_webhook(): success -> append (source:"webhook") + 200; a WebhookError here is a
              VERIFIED-but-unparseable delivery -> 200 acknowledge-and-note (increment unparseable).
        All accepted-and-dropped cases return 200 because the platform worker counts EXACTLY 200 as
        success (202/401/other = failure -> retry + circuit-break)."""
        webhook_id = header(headers, _HDR_WEBHOOK_ID)
        route = self.rt.read_route()
        if route is None or webhook_id is None or webhook_id != route["webhookId"]:
            return text_response("discarded: unknown or stale webhook id", 200)
        run = self.rt.read_run(route["runId"])
        if run is None:
            return text_response("discarded: no active webhook run", 200)

        record_call(run, CALL_SERVICE_BUILD_FILE)
        client = self._webhook_client()
        record_call(run, CALL_VERIFY_WEBHOOK)
        if not client.verify_webhook(body, headers):
            # A genuine signature failure — persist the attempted verify so the calls trace stays
            # truthful even on the reject path.
            self.rt.write_run(route["runId"], run)
            return text_response("signature verification failed", 401)
        try:
            record_call(run, CALL_PARSE_WEBHOOK)
            change = client.parse_webhook(body, headers)
            run["events"].append(_project_change(change, "webhook"))
        except WebhookError as exc:
            # Verified but unparseable/undecryptable — acknowledge (200) and note it in the raw view.
            run["unparseable"] = int(run.get("unparseable", 0)) + 1
            run["events"].append({
                "source": "webhook", "event": None, "id": None,
                "note": "received, could not parse", "raw": {"error": str(exc)},
            })
        self.rt.write_run(route["runId"], run)
        return text_response("ok", 200)

    # ── GET /api/runs/{runId} ─────────────────────────────────────────────────

    def run(self, run_id: str, run: Dict[str, Any]) -> Response:
        # The accumulating webhook run: each poll also does ONE immediate drain_batch() raw feed
        # fetch (NOT process_changes(), which loops the pump to empty and could stall the single
        # worker) so events generated AFTER start still appear in deployed-no-tunnel mode.
        if str(run.get("scenario") or "") == WEBHOOK:
            run = self._webhook_feed_fallback(run_id, run)
            return json_response({
                "status": run.get("status", "pending"),
                "calls": run.get("calls", []),
                "result": {
                    "webhookId": run.get("webhookId", ""),
                    "events": run.get("events", []),
                    "unparseable": int(run.get("unparseable", 0)),
                },
            })

        out: Dict[str, Any] = {"status": run.get("status", "pending"), "calls": run.get("calls", [])}
        if "result" in run:
            out["result"] = run["result"]
        if "error" in run:
            out["error"] = run["error"]
        return json_response(out)

    def _webhook_feed_fallback(self, run_id: str, run: Dict[str, Any]) -> Dict[str, Any]:
        """One immediate drain_batch() fetch per poll for the active webhook run, appending new
        source:"feed" events deduped on the pull-feed Change.id. Only the CURRENT active run pulls
        (a superseded run stops receiving). A transport/API error is swallowed so a blackholed feed
        never fails the accumulating run — the webhook path still works."""
        route = self.rt.read_route()
        if route is None or route["runId"] != run_id:
            return run  # superseded/cleared — this run no longer pulls
        seen: Set[str] = set(run.get("seenFeedIds", []))
        try:
            build_new = record_call(run, CALL_SERVICE_BUILD_FILE)
            client = self._webhook_client()
            # Every poll ATTEMPTS the feed pull — record the call now (deduped), so an empty poll
            # still reports the drain_batch it performed rather than claiming no call.
            drain_new = record_call(run, CALL_DRAIN_BATCH)
            appended = False
            for change in client.drain_batch():
                cid = change.id
                if cid is not None:
                    if cid in seen:
                        continue
                    seen.add(cid)
                    run["seenFeedIds"].append(cid)
                run["events"].append(_project_change(change, "feed"))
                appended = True
            if appended or drain_new or build_new:
                self.rt.write_run(run_id, run)
        except Exception:  # noqa: BLE001 — a blackholed/failed feed must not fail the run
            pass
        return run

    # ── SDK client builder — built from the persisted config FILE ─────────────

    def _webhook_client(self) -> Client:
        """The webhook scenario's Client, built from its config file with a network-timeout
        session so the per-poll drain_batch() fallback can never pin the single worker."""
        cfg = Config.from_file(self.rt.config_path_for(WEBHOOK))
        return Client(cfg, http=HttpClient(cfg, session=TimeoutSession(FEED_TIMEOUT_S)))


# ── change projection / value rendering ────────────────────────────────────────


def _project_change(c, source: Optional[str]) -> Dict[str, Any]:
    """The rendered-column projection of a Change PLUS a raw object holding the full public Change
    fields, so the frontend's JSON.stringify(result) Raw view can show the event-specific extras.
    ``source`` labels a webhook delivery vs a pull-feed row (None for the changes scenario)."""
    event: Dict[str, Any] = {
        "event": c.event,
        "personId": c.person_id,
        "shareCode": c.share_code,
        "customerType": c.customer_type,
        "slug": c.slug,
        "value": _stringify(c.value),
        "live": c.live,
        "at": _iso(c.at),
        "documentId": c.document_id,
        "status": c.status,
        "action": c.action,
        "id": c.id,
        "raw": {
            "id": c.id,
            "event": c.event,
            "personId": c.person_id,
            "shareCode": c.share_code,
            "customerType": c.customer_type,
            "slug": c.slug,
            "value": _stringify(c.value),
            "live": c.live,
            "documentId": c.document_id,
            "status": c.status,
            "action": c.action,
            "note": c.note,
            "method": c.method,
            "contentSha256": c.content_sha256,
            "signedAt": c.signed_at,
            "cancelEffectiveDate": c.cancel_effective_date,
            "requestId": c.request_id,
            "publicKeySha256": c.public_key_sha256,
            "verified": c.verified,
            "at": _iso(c.at),
        },
    }
    if source is not None:
        return {"source": source, **event}
    return event


def _stringify(v: Any) -> Any:
    """Render a decrypted value for JSON. A binary value is a lazy BinaryHandle — resolve to a
    short descriptor rather than dumping raw bytes; a structured value stays an array/object."""
    if v is None or isinstance(v, (bool, int, float, str, list, dict)):
        return v
    if isinstance(v, (datetime, date)):
        return v.isoformat()
    if isinstance(v, BinaryHandle):
        try:
            return f"[binary {len(v.bytes())} bytes]"
        except Exception:  # noqa: BLE001
            return "[binary value]"
    return str(v)


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt is not None else None


# ── the six document/contract specs (payloads verbatim from apitests/php/documents.php) ─────────


def _document_specs() -> List[Dict[str, Any]]:
    return [
        {"label": "Broadcast plaintext JSON (no target)", "perPerson": False, "opts": {
            "name": "Service notice", "payload_kind": "json",
            "json_value": {"msg": "Scheduled maintenance Sunday"},
        }},
        {"label": "Broadcast PDF file (no target)", "perPerson": False, "opts": {
            "name": "Price list", "payload_kind": "file",
            "file_bytes": _minimal_pdf("Price list"), "file_mime": "application/pdf",
        }},
        {"label": "Per-person NON-private file", "perPerson": True, "opts": {
            "name": "Your invoice", "payload_kind": "file",
            "file_bytes": _minimal_pdf("Your invoice"), "file_mime": "application/pdf",
        }},
        {"label": "Per-person PRIVATE file (lock → reveal)", "perPerson": True, "opts": {
            "name": "Confidential report", "payload_kind": "file", "is_private": True,
            "file_bytes": _minimal_pdf("Confidential report"), "file_mime": "application/pdf",
        }},
        {"label": "CONTRACT requiring SIGNATURE", "perPerson": True, "opts": {
            "name": "Service agreement", "kind": "agreement", "payload_kind": "file",
            "requires_signature": True,
            "file_bytes": _minimal_pdf("Service agreement"), "file_mime": "application/pdf",
            "metadata": {"can_be_cancelled_in_app": True},
        }},
        {"label": "CONTRACT requiring ACCEPTANCE", "perPerson": True, "opts": {
            "name": "Terms update", "kind": "agreement", "payload_kind": "json",
            "requires_acceptance": True, "json_value": {"version": "2.0"},
            "metadata": {
                "plan_name": "Pro Plan", "price": "9.99", "currency": "EUR",
                "renewal_term": "Monthly", "renewal_date": "2026-07-30",
                "valid_until": "2027-06-30", "can_be_cancelled_in_app": True,
                "management_url": "https://example.com/manage",
            },
        }},
    ]


def _minimal_pdf(label: str) -> bytes:
    """A tiny valid one-page PDF carrying ``label`` (verbatim shape from apitests/php/documents.php)
    — so the broadcast/per-person/contract file docs upload real bytes without a fixture file."""
    safe = label.replace("(", "[").replace(")", "]")
    stream = f"BT /F1 18 Tf 40 90 Td ({safe}) Tj ET"
    objs = {
        1: "<< /Type /Catalog /Pages 2 0 R >>",
        2: "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: ("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 420 160] "
            "/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"),
        4: "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        5: f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream",
    }
    pdf = b"%PDF-1.4\n"
    offsets: Dict[int, int] = {}
    for n, body in objs.items():
        offsets[n] = len(pdf)
        pdf += f"{n} 0 obj\n{body}\nendobj\n".encode("latin-1")
    xref_pos = len(pdf)
    pdf += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode("latin-1")
    for n in objs:
        pdf += f"{offsets[n]:010d} 00000 n \n".encode("latin-1")
    pdf += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF".encode("latin-1")
    return pdf
