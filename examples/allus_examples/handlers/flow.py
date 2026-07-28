"""Flow scenario handler (contract family: ``flow:run``).

ONE runnable scenario. Every call goes through the INTENDED allus SDK flow surface
only (``identity`` / ``trigger_flow_run`` / ``flow_run`` / ``process_flow_run`` /
``flow_run_answers`` / ``flow_run_document``) — never internals, never raw platform
HTTP.

There is NO cross-card flow-run-id handoff: the platform flow run lives entirely
INSIDE this one demo run's ``.runtime`` file — the demo runId is the backend run and
the platform flowRunId is stored inside it, never exposed as a separate input.

``config()`` writes the browser's setup values to a canonical SDK config FILE
(service role); ``start()`` builds the service ``Client`` from it via
``Client.from_config`` and runs OFF the config. The ``GET /api/runs/{runId}`` poll
(``run()``) is the drive loop AND the resume: each poll reads the platform run and,
if it is the company's turn, drives exactly ONE company step; otherwise it reports
waiting/running and touches nothing (the next poll after the person answers on their
phone resumes automatically).
"""

from __future__ import annotations

from typing import Any, Dict, List

from allus_company_data import (
    ApiError,
    Client,
    ConfigError,
    ValidationError,
)

from ..common import Response, failure_response, jsonable, json_response, parse_body
from ..runtime import Runtime, add_call

# The single public scenario id (the flow family) and the internal store key its
# runtime files use (kept distinct from the identity int ids in the shared tree).
SCENARIO = "flow:run"
STORE_KEY = "flow_run"

DEFAULT_API_URL = "https://api.allme.fyi"

# The flow party keys the fixtures pin.
PARTY_COMPANY = "company"
PARTY_CUSTOMER = "customer"

# The canned INVALID value the validation-demo submits once for an email field.
INVALID_EMAIL = "not-an-email"


# ── the "what just happened" trace (#578) ─────────────────────────────────────
# Every entry is ``<SDK method> — <what that call did in THIS scenario>``, appended AT
# the call site, in the order the calls were made. The annotations are byte-identical in
# all six SDK examples — only the method reference is written in the language's own idiom
# — so one scenario teaches one thing whichever example a reader starts. Keep them in
# step when this handler changes.
CALL_SERVICE_BUILD = (
    "Client.from_config — builds the SERVICE-role data client from the saved config file: "
    "client credentials plus the service private key, decrypted with its passphrase"
)
CALL_IDENTITY = (
    "Client.identity — GET /api/company-data/whoami: this service's own company_user_id, "
    "which the COMPANY party binds to"
)
CALL_CONNECTION = (
    "Client.connection — reads the configured connection; the connected person's id on it is "
    "what the CUSTOMER party binds to"
)
CALL_TRIGGER = (
    "Client.trigger_flow_run — starts a run of the published flow for that connection, pinning "
    "the flow's latest published version"
)
CALL_FLOW_RUN = "Client.flow_run — re-read on every poll to see whose turn the run is on"
CALL_PROCESS = (
    "Client.process_flow_run — drives ONE company step: decrypts the answers so far, fills the "
    "node, type-checks the values, encrypts a copy per party, submits — and generates the "
    "document when the submit lands on a document-mode leaf"
)
CALL_ANSWERS = (
    "Client.flow_run_answers — the completed run's answers, decrypted with the service key"
)
CALL_DOCUMENT = (
    "Client.flow_run_document — downloads the company's own copy of the generated contract and "
    "decrypts it with the service key"
)


class FlowHandlers:
    """The flow family, bound to the shared runtime."""

    def __init__(self, rt: Runtime) -> None:
        self.rt = rt

    def scenario_list(self) -> List[Dict[str, Any]]:
        return [{"id": SCENARIO, "kind": "runnable"}]

    def is_scenario(self, scenario_id: str) -> bool:
        return scenario_id == SCENARIO

    def clear(self, scenario_id: str) -> Response:
        if not self.is_scenario(scenario_id):
            return json_response({"error": "not_found"}, 404)
        self.rt.clear_scenario(STORE_KEY)
        return json_response({"ok": True})

    # ── POST /api/scenarios/{id}/config ──────────────────────────────────────

    def config(self, scenario_id: str, body: bytes) -> Response:
        """Write the browser's setup values to a canonical SDK config FILE (service
        role — client_credentials + service PEM). The demo-only run parameters
        (published flow id, connection id, fixture choice) go to the meta sidecar so
        the config file stays a pure SDK config the run executes off."""
        if not self.is_scenario(scenario_id):
            return json_response({"error": "not_found"}, 404)
        data = parse_body(body)

        cfg: Dict[str, Any] = {
            "api_url": (str(data.get("apiUrl") or "") or DEFAULT_API_URL).rstrip("/"),
            "client_id": str(data.get("clientId") or ""),
            "client_secret": str(data.get("clientSecret") or ""),
            "key_passphrase": str(data.get("keyPassphrase") or ""),
        }
        pem = str(data.get("servicePrivateKeyPem") or "")
        if pem:
            cfg["service_private_key"] = self.rt.materialize_config_key(pem)
        config_path = self.rt.write_config(STORE_KEY, cfg)

        # Demo-only run parameters (NOT SDK Config fields) -> meta sidecar.
        self.rt.write_config_meta(STORE_KEY, {
            "flow_id": str(data.get("flowId") or ""),
            "connection_id": str(data.get("connectionId") or ""),
            "fixture": str(data.get("fixture") or ""),
        })

        return json_response({"ok": True, "configPath": config_path})

    # ── POST /api/scenarios/{id}/start ────────────────────────────────────────

    def start(self, scenario_id: str) -> Response:
        """Trigger the flow run. Build the service Client from the persisted config
        file, construct the bindings via the intended SDK surface (company ->
        identity()['company_user_id']; customer -> Connection.person_id), call
        trigger_flow_run, and store the returned platform flowRunId in the demo run
        file. Returns {runId, action:{"type":"none"}} — the drive happens on the GET
        /api/runs poll."""
        if not self.is_scenario(scenario_id):
            return json_response({"error": "not_found"}, 404)
        if not self.rt.has_config(STORE_KEY):
            # The run is built from the persisted config file, not the request body.
            return json_response({"error": "not_configured"}, 409)

        meta = self.rt.read_config_meta(STORE_KEY)
        flow_id = str(meta.get("flow_id") or "")
        connection_id = str(meta.get("connection_id") or "")
        if not flow_id or not connection_id:
            return json_response(
                {"error": "not_configured", "message": "flow id and connection id are required"},
                409,
            )

        calls: List[str] = []
        try:
            calls.append(CALL_SERVICE_BUILD)
            client = self._service_client()

            # The COMPANY party binds to this service's own company_user_id.
            calls.append(CALL_IDENTITY)
            identity = client.identity()
            company_user_id = str(identity.get("company_user_id") or "")
            if not company_user_id:
                return failure_response(
                    "identity() returned no company_user_id", "identity_error", 502
                )

            # The CUSTOMER party binds to the connected person's public person_id.
            calls.append(CALL_CONNECTION)
            connection = client.connection(connection_id)
            person_id = connection.person_id
            if not person_id:
                return failure_response(
                    f"connection {connection_id} has no person_id (not found or not connected)",
                    "connection_error",
                    502,
                )

            bindings = {PARTY_COMPANY: company_user_id, PARTY_CUSTOMER: person_id}
            calls.append(CALL_TRIGGER)
            flow_run = client.trigger_flow_run(flow_id, connection_id=connection_id, bindings=bindings)

            flow_run_id = str(flow_run.id or "")
            if not flow_run_id:
                return failure_response("trigger_flow_run returned no run id", "trigger_error", 502)
        except (ApiError, ConfigError) as exc:
            return failure_response(exc, "start_failed", 502)

        run_id = self.rt.new_run_id()
        self.rt.write_run(run_id, {
            "scenario": STORE_KEY,
            "flowRunId": flow_run_id,
            "steps": [],
            "rejectedNodes": [],
            "calls": calls,
            "completed": False,
        })

        return json_response({"runId": run_id, "action": {"type": "none"}})

    # ── GET /api/runs/{runId} ─────────────────────────────────────────────────

    def run(self, run_id: str, run: Dict[str, Any]) -> Response:
        """The idempotent, short-cycled poll that IS the drive loop and the resume.
        Reads the platform run; if it is the company's turn drives exactly ONE step;
        on completion fetches the answers and (document-mode) downloads the generated
        contract. A terminal run returns its cached result on every poll until
        TTL/Clear."""
        # Idempotent: once terminal (completed OR errored) the outcome is returned
        # unchanged on every subsequent poll — a failed run stays failed.
        terminal = run.get("completed") is True or "error" in run
        if not terminal:
            run = self._advance(run)
            self.rt.write_run(run_id, run)

        return json_response(self._result(run))

    def _advance(self, run: Dict[str, Any]) -> Dict[str, Any]:
        """One poll's worth of work. Returns the (possibly mutated) run dict."""
        flow_run_id = str(run.get("flowRunId") or "")
        if not flow_run_id:
            run["status"] = "error"
            run["error"] = "run has no platform flowRunId"
            return run

        try:
            run["calls"] = add_call(run.get("calls", []), CALL_SERVICE_BUILD)
            client = self._service_client()
            run["calls"] = add_call(run.get("calls", []), CALL_FLOW_RUN)
            flow_run = client.flow_run(flow_run_id)

            status = str(flow_run.status or "")
            company_party = flow_run.company_party_key
            company_turn = company_party is not None and status == f"awaiting_{company_party}"

            if status == "completed":
                return self._complete(run, client, flow_run, flow_run_id)
            if company_turn:
                return self._drive_step(run, client, flow_run, flow_run_id)
            if status.startswith("awaiting_"):
                # The person's turn (or the phone signature) — wait; the next poll resumes.
                run["status"] = "waiting_person"
                return run
            # Any transient in-between state (e.g. generating) — keep polling.
            run["status"] = "running"
            return run
        except (ApiError, ConfigError) as exc:
            run["status"] = "error"
            run["error"] = str(exc)
            return run

    def _drive_step(
        self, run: Dict[str, Any], client: Client, flow_run: Any, flow_run_id: str
    ) -> Dict[str, Any]:
        """Drive ONE company step via process_flow_run. The validation demo: for an
        email field whose node has not yet been rejected once, fill_node returns the
        canned INVALID value, which process_flow_run rejects with a ValidationError
        BEFORE any submit — recorded as accepted:false without advancing. The next
        poll (node marked rejected) fills the VALID value -> advances -> accepted:true."""
        node_key = str(flow_run.current_node or "")
        rejected_nodes = [str(x) for x in (run.get("rejectedNodes") or [])]

        filled: List[Dict[str, str]] = []

        def fill_node(node: Dict[str, Any], answers: Dict[str, Any]) -> Dict[str, Any]:
            nk = str(node.get("key") or "")
            fill: Dict[str, Any] = {}
            for el in node.get("elements") or []:
                if not isinstance(el, dict) or el.get("kind") != "field":
                    continue
                slug = str(el.get("slug") or "")
                if not slug:
                    continue
                ftype = str(el.get("field_type") or "text")
                reject_demo = ftype == "email" and nk not in rejected_nodes
                value = INVALID_EMAIL if reject_demo else _canned_value(ftype)
                fill[slug] = value
                filled.append({"slug": slug, "type": ftype, "submitted": value})
            return fill

        run["calls"] = add_call(run.get("calls", []), CALL_PROCESS)
        try:
            client.process_flow_run(flow_run_id, fill_node)
            # Advanced: every field filled for this node was accepted.
            steps = list(run.get("steps") or [])
            for f in filled:
                steps.append({
                    "slug": f["slug"],
                    "type": f["type"],
                    "submitted": f["submitted"],
                    "accepted": True,
                })
            run["steps"] = steps
            run["status"] = "running"
            return run
        except ValidationError as exc:
            # The canned invalid value was rejected BEFORE submit — record it and mark
            # the node so the next poll submits the valid value. The node did NOT advance.
            submitted = INVALID_EMAIL
            for f in filled:
                if f["slug"] == exc.slug:
                    submitted = f["submitted"]
                    break
            steps = list(run.get("steps") or [])
            steps.append({
                "slug": str(exc.slug or ""),
                "type": str(exc.field_type or "email"),
                "submitted": submitted,
                "accepted": False,
                "error": str(exc),
            })
            run["steps"] = steps
            if node_key and node_key not in rejected_nodes:
                rejected_nodes.append(node_key)
            run["rejectedNodes"] = rejected_nodes
            run["status"] = "running"
            return run

    def _complete(
        self, run: Dict[str, Any], client: Client, flow_run: Any, flow_run_id: str
    ) -> Dict[str, Any]:
        """Terminal: fetch the decrypted answers and, for a document-mode run, download
        the generated contract's company copy (the run-scoped, service-key-decryptable
        surface)."""
        run["calls"] = add_call(run.get("calls", []), CALL_ANSWERS)
        answers = client.flow_run_answers(flow_run)
        run["answers"] = [{"slug": str(slug), "value": jsonable(value)} for slug, value in answers.items()]

        if flow_run.output_mode == "document":
            try:
                run["calls"] = add_call(run.get("calls", []), CALL_DOCUMENT)
                data = client.flow_run_document(flow_run_id)
                run["document"] = {"status": "downloaded", "downloaded": True, "bytes": len(data)}
            except ApiError as exc:
                # The run completed but the document is not retrievable yet — report, don't fail.
                run["document"] = {"status": "unavailable", "downloaded": False, "error": str(exc)}

        run["status"] = "completed"
        run["completed"] = True
        return run

    def _result(self, run: Dict[str, Any]) -> Dict[str, Any]:
        """The GET /api/runs/{runId} response: the SHARED run envelope (outer
        {status:"pending"|"done"|"failed", result?, error?, calls}) with the pinned
        FLOW shape nested under ``result`` ({status:"running"|"waiting_person"|
        "completed", steps, answers?, document?}). The shared frontend reads progress
        ONLY from ``run.result`` and keeps polling ONLY while the outer status is
        "pending", so the inner flow status must NOT sit at the top level — it drives
        under "pending" until the platform run completes ("done") or errors
        ("failed")."""
        flow_status = str(run.get("status") or "running")
        outer = "failed" if "error" in run else ("done" if flow_status == "completed" else "pending")

        result: Dict[str, Any] = {
            "status": flow_status,
            "steps": list(run.get("steps") or []),
        }
        if "answers" in run:
            result["answers"] = run["answers"]
        if "document" in run:
            result["document"] = run["document"]

        out: Dict[str, Any] = {
            "status": outer,
            "result": result,
            "calls": list(run.get("calls") or []),
        }
        if "error" in run:
            out["error"] = run["error"]
        return out

    # ── SDK client builder — built from the persisted config FILE ─────────────

    def _service_client(self) -> Client:
        """Build the service data client OFF the scenario's config file (service role)."""
        return Client.from_config(self.rt.config_path_for(STORE_KEY))


# ── module helpers ────────────────────────────────────────────────────────────


def _canned_value(ftype: str) -> str:
    """A canned VALID plaintext for a field type (demo values over already-supported
    answerable types). An unknown / text type accepts anything."""
    if ftype == "email":
        return "billing@acme.example"
    if ftype == "number":
        return "42"
    if ftype == "boolean":
        return "true"
    if ftype == "date":
        return "2024-01-15"
    if ftype == "date_of_birth":
        return "1990-05-01"
    if ftype == "phone":
        return "+31201234567"
    if ftype == "url":
        return "https://acme.example"
    if ftype == "address":
        import json

        return json.dumps({
            "street": "Herengracht 1",
            "city": "Amsterdam",
            "postal_code": "1011AB",
            "country": "NL",
        })
    return "Acme Corporation"
