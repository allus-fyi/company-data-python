"""The single demo-backend server (contract v3) for the Python SDK example suite.

ONE server serves the static portal bundle + the whole contract API + the public
``POST /webhook`` (company-data) + ``GET /callback`` (identity) on ONE port. This
module is pure SCAFFOLDING: it parses the request, aggregates ``GET /api/meta``
across the three families, and DISPATCHES each scenario request to its family's
handler by the scenario id (ints -> identity, ``flow:*`` -> flow, ``companydata:*``
-> company-data). The SDK example itself lives in the per-family handler files under
``handlers/`` — open one and you see the SDK calls.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from .common import Response, json_response, mime
from .handlers.company_data import CompanyDataHandlers
from .handlers.flow import FlowHandlers
from .handlers.identity import IdentityHandlers
from .runtime import Runtime

# The single implemented contract version. The startup guard refuses a bundle whose
# contract.json version differs.
CONTRACT_VERSION = 3
SDK = "python"

_INT_ID_RE = re.compile(r"^\d+$")
_SCENARIO_ROUTE_RE = re.compile(r"^/api/scenarios/([^/]+)/(config|start|enroll|clear)$")
_RUN_ROUTE_RE = re.compile(r"^/api/runs/([0-9a-f]{32})$")


class Server:
    def __init__(self, rt: Runtime, frontend_dir: str, sdk_version: str, port: int) -> None:
        self.rt = rt
        self.frontend_dir = frontend_dir
        self.sdk_version = sdk_version
        self.port = port
        # The three families share the ONE runtime + this server's port.
        self.identity = IdentityHandlers(rt, port)
        self.flow = FlowHandlers(rt)
        self.company = CompanyDataHandlers(rt)

    # ── entry point ──────────────────────────────────────────────────────────

    def dispatch(self, method: str, raw_path: str, body: bytes, headers: Dict[str, str]) -> Response:
        self.rt.ensure_dirs()
        self.rt.sweep()  # lazy TTL sweep on every request

        parsed = urlparse(raw_path)
        path = parsed.path
        query = parse_qs(parsed.query)

        try:
            # ── shared endpoints ────────────────────────────────────────────
            if path == "/api/meta" and method == "GET":
                return self._meta()
            if path == "/webhook" and method == "POST":
                return self.company.webhook(body, headers)  # PUBLIC inbound delivery (company-data)
            if path == "/callback" and method == "GET":
                return self.identity.callback(query)  # PUBLIC OAuth return leg (identity)
            if path == "/api/clear" and method == "POST":
                self.rt.clear_all()
                return json_response({"ok": True})

            # ── scenario-scoped routes -> the owning family's handler ───────
            m = _SCENARIO_ROUTE_RE.match(path)
            if m and method == "POST":
                return self._scenario_route(m.group(1), m.group(2), body, headers)

            # ── run polls -> the family that owns the run (by its scenario) ─
            m = _RUN_ROUTE_RE.match(path)
            if m and method == "GET":
                return self._run(m.group(1))

            if path.startswith("/api/"):
                return json_response({"error": "not_found"}, 404)
            return self._serve_static(path)
        except Exception as exc:  # noqa: BLE001 — top-level guard, mirrors PHP
            return json_response({"error": "server_error", "message": str(exc)}, 500)

    # ── GET /api/meta (aggregated across all three families) ───────────────────

    def _meta(self) -> Response:
        scenarios: List[Dict[str, Any]] = []
        scenarios.extend(self.identity.scenario_list())   # ids 1–8 (7 = guide)
        scenarios.extend(self.flow.scenario_list())       # flow:run
        scenarios.extend(self.company.scenario_list())    # the five companydata:*
        return json_response({
            "sdk": SDK,
            "sdkVersion": self.sdk_version,
            "contractVersion": CONTRACT_VERSION,
            "scenarios": scenarios,
        })

    # ── scenario dispatch ──────────────────────────────────────────────────────

    def _scenario_route(
        self, scenario_id: str, action: str, body: bytes, headers: Dict[str, str]
    ) -> Response:
        """Route POST /api/scenarios/{id}/{config|start|enroll|clear} to the family that
        owns ``scenario_id`` (ints -> identity, flow:* -> flow, companydata:* -> company).

        ``headers`` reaches identity's config handler only: it derives the OAuth redirect URI
        from the origin the browser used, so a phone on the LAN registers its own (#553)."""
        family = _family_for_id(scenario_id)

        if family == "identity":
            sid = int(scenario_id)
            if not self.identity.is_scenario(sid):
                return json_response({"error": "not_found"}, 404)
            if action == "config":
                return self.identity.config(sid, body, headers)
            if action == "start":
                return self.identity.start(sid)
            if action == "enroll":
                return self.identity.enroll(sid, body)
            if action == "clear":
                self.identity.clear(sid)
                return json_response({"ok": True})

        elif family == "flow":
            if action == "config":
                return self.flow.config(scenario_id, body)
            if action == "start":
                return self.flow.start(scenario_id)
            if action == "clear":
                return self.flow.clear(scenario_id)
            # enroll is identity-only
            return json_response({"error": "not_found"}, 404)

        elif family == "company":
            if action == "config":
                return self.company.config(scenario_id, body)
            if action == "start":
                return self.company.start(scenario_id)
            if action == "clear":
                return self.company.clear(scenario_id)
            # enroll is identity-only
            return json_response({"error": "not_found"}, 404)

        return json_response({"error": "not_found"}, 404)

    # ── GET /api/runs/{runId} — routed by the run's owning family ──────────────

    def _run(self, run_id: str) -> Response:
        run = self.rt.read_run(run_id)
        if run is None:
            return json_response({"error": "not_found"}, 404)
        family = _family_for_id(str(run.get("scenario") or ""))
        if family == "identity":
            return self.identity.run(run_id, run)
        if family == "flow":
            return self.flow.run(run_id, run)
        if family == "company":
            return self.company.run(run_id, run)
        return json_response({"error": "not_found"}, 404)

    # ── static bundle ───────────────────────────────────────────────────────────

    def _serve_static(self, path: str) -> Response:
        rel = "index.html" if path in ("", "/") else path.lstrip("/")
        root = os.path.realpath(self.frontend_dir)
        full = os.path.realpath(os.path.join(root, rel))
        # Path-traversal guard + SPA fallback to index.html.
        if not full.startswith(root) or not os.path.isfile(full):
            index = os.path.join(root, "index.html")
            if os.path.isfile(index):
                with open(index, "rb") as fh:
                    return Response(200, {"Content-Type": "text/html; charset=utf-8"}, fh.read())
            return Response(404, {"Content-Type": "text/plain"}, b"bundle not found")
        with open(full, "rb") as fh:
            return Response(200, {"Content-Type": mime(full)}, fh.read())


# ── family routing ──────────────────────────────────────────────────────────────


def _family_for_id(scenario_id: str) -> Optional[str]:
    """Which family owns a scenario id. Accepts the PUBLIC id ("1", "flow:run",
    "companydata:read") or a run's internal scenario key ("flow_run")."""
    s = str(scenario_id)
    if _INT_ID_RE.match(s):
        return "identity"
    if s.startswith("flow"):
        return "flow"
    if s.startswith("companydata"):
        return "company"
    return None
