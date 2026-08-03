"""Identity scenario handlers (contract family: ids ``1``-``5``, ``7``-``8``).

The seven *Sign in with allme* / OIDC / service-2FA scenarios, each mapped to the
INTENDED allus SDK surface (or Authlib for the OIDC scenario 5). Handlers never
perform raw platform HTTP and never block on the SDK's long defaults: detached /
challenge waits are short-cycled (``timeout=2``) inside ``run()``.

Settings flow (config-file model): ``config()`` writes the browser's setup values
to a canonical SDK config FILE; ``start()`` / ``enroll()`` then build the SDK from
that file via the role-appropriate file constructor (``OAuthClient.from_config`` ->
``Config.from_idw_file``; ``Client.from_config`` -> ``Config.from_file``) and run
OFF the config — exactly as a real integrator wires the SDK. A ``/start`` with no
saved config -> ``409 not_configured``.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from allus_company_data import (
    ApiError,
    Claim,
    Client,
    Config,
    HttpClient,
    OAuthClient,
)
from allus_company_data.oauth import DEFAULT_AUTHORIZE_URL

from .. import pkce
from ..common import (
    Response,
    TimeoutSession,
    jsonable,
    json_response,
    parse_body,
    query_one,
    redirect,
)
from ..runtime import Runtime, add_call

# id -> "runnable" | "guide". Scenario 7 is the one guide card (no /start).
SCENARIOS: Dict[int, str] = {
    1: "runnable", 2: "runnable", 3: "runnable", 4: "runnable",
    5: "runnable", 7: "guide", 8: "runnable",
}
SERVICE_SCENARIOS = (4, 8)      # also read live values via the service data Client
OAUTH_URL_SCENARIOS = (1, 2, 3, 4, 8)  # build a consent URL via OAuthClient
# Scenarios whose complete_sign_in() response can carry claim values (userinfo "values"
# non-empty) and therefore need the OAuth app private key configured to decrypt them: mode
# one_time and mode connect, both delivered as app-key ciphertext through userinfo. Mode signin
# (scenarios 1, 2) never carries values; scenario 8 never calls this leg at all; scenario 5
# runs Authlib instead of this SDK's decrypt path.
CLAIM_VALUE_SCENARIOS = (3, 4)

DEFAULT_API_URL = "https://api.allme.fyi"

# The short-cycled polls must not pin the single worker on a blackholed request for
# the transport's default (unbounded) wait, so their HTTP session carries a 2s
# network timeout. The SDK's poll helpers separately bound their LOGICAL loop.
POLL_TIMEOUT_S = 2.0

# Refusal when the request carries no Host header, so the browser's origin is unknown.
# There is NO default host: substituting one (localhost) silently sends the round-trip to a
# DIFFERENT origin than the browser is on — a different localStorage and a redirect URI the
# OAuth app never registered.
NO_ORIGIN = (
    "no_origin — this request carried no Host header, so the OAuth redirect URI cannot be "
    "derived from the origin your browser is using. Open the example by its address "
    "(http://<host>:<port>/) and save the setup again."
)

# Refusal when the scenario's saved config holds no redirect URI to complete the exchange with.
NO_STORED_ORIGIN = (
    "no_origin — the saved config has no oauth_redirect_uri. Save the scenario setup again "
    "from the browser you will complete the sign-in in."
)

# ── the "what just happened" trace ────────────────────────────────────────────
# Every entry is ``<SDK method> — <what that call did in THIS scenario>``, appended AT
# the call site, in the order the calls were made; an entry wrapped in parentheses is a
# step that is deliberately NOT an SDK call. These annotations follow a shared teaching
# format so one scenario teaches one thing whichever example a reader starts. Keep them
# in step when this handler changes: the panel is headed "What just happened", and a list
# that no longer matches the code is worse than a short one.
CALL_IDW_BUILD = (
    "OAuthClient.from_config — builds the RP client from the saved config file: "
    "client id, secret and the registered redirect URI"
)
CALL_IDW_BUILD_LOCAL = (
    "OAuthClient(Config.from_idw_file(…)) — builds the RP client from the saved config file: "
    "client id, secret and the registered redirect URI"
)
CALL_AUTH_SIGNIN = (
    "OAuthClient.authorize_url — the consent URL the person is sent to "
    "(mode signin, response_mode redirect, PKCE S256, state = this run id)"
)
CALL_AUTH_SIGNIN_DETACHED = (
    "OAuthClient.authorize_url — the sign-in URL behind the link + QR "
    "(mode signin, response_mode detached, PKCE S256, state = this run id)"
)
CALL_AUTH_ONE_TIME = (
    "OAuthClient.authorize_url — the consent URL the person is sent to "
    "(mode one_time, claims email + phone, PKCE S256, state = this run id)"
)
CALL_AUTH_CONNECT = (
    "OAuthClient.authorize_url — the consent URL the person is sent to "
    "(mode connect, PKCE S256, state = this run id)"
)
CALL_AUTH_ENROLL = (
    "OAuthClient.authorize_url — the enrollment URL the person is sent to "
    "(mode 2fa_enroll, response_mode redirect)"
)
CALL_AUTH_ENROLL_DETACHED = (
    "OAuthClient.authorize_url — the enrollment URL behind the link + QR "
    "(mode 2fa_enroll, response_mode detached)"
)
CALL_POLL_SIGNIN = (
    "OAuthClient.poll_result — polls POST /oauth2/result until the phone delivers the code "
    "(one 2s-bounded call per browser poll)"
)
CALL_POLL_ENROLL = (
    "OAuthClient.poll_result — polls POST /oauth2/result until the phone delivers "
    "{enrolled: true} (one 2s-bounded call per browser poll)"
)
CALL_COMPLETE_SIGNIN = (
    "OAuthClient.complete_sign_in — exchanges the code + PKCE verifier at POST /oauth2/token, "
    "then reads GET /api/oauth/userinfo; mode signin returns the identity only, no claim values"
)
CALL_COMPLETE_ONE_TIME = (
    "OAuthClient.complete_sign_in — exchanges the code + PKCE verifier at POST /oauth2/token, "
    "reads GET /api/oauth/userinfo, and decrypts every claim value with the OAuth app private key"
)
CALL_COMPLETE_CONNECT = (
    "OAuthClient.complete_sign_in — exchanges the code + PKCE verifier at POST /oauth2/token, "
    "reads GET /api/oauth/userinfo, and decrypts the consented claim values with the OAuth app "
    "private key; the connection's live values still come separately from the data client below"
)
CALL_ENROLLED_CALLBACK = (
    "(callback ?enrolled=true) — the redirect-leg enrollment outcome; there is nothing to "
    "exchange, so no further SDK call"
)
CALL_SERVICE_BUILD = (
    "Client.from_config — builds the SERVICE-role data client from the saved config file: "
    "client credentials plus the service private key, decrypted with its passphrase"
)
CALL_CONNECTIONS_LIVE = (
    "Client.connections — pages GET /api/company-data/connections and decrypts each person's "
    "values with the service key; the run keeps the one whose share code just signed in"
)
CALL_TWO_FACTOR = (
    "Client.two_factor — the service-2FA sub-client, on the same data-client credentials"
)
CALL_CHALLENGE = (
    "TwoFactorClient.challenge — POST /api/service-2fa/challenges for the person's share code "
    "with a per-run idempotency key; returns the challenge id, plus matching digits when the "
    "service has number matching on"
)
CALL_WAIT_RESULT = (
    "TwoFactorClient.wait_for_result — polls GET /api/service-2fa/challenges/{id} until the "
    "status leaves pending: approved, denied, expired or revoked (one 2s-bounded call per "
    "browser poll; the first terminal read burns the result)"
)
CALL_OIDC_DISCOVERY = (
    "(oidc) requests.get(/.well-known/openid-configuration) — discovery: fetches "
    "/.well-known/openid-configuration from the configured API base"
)
CALL_OIDC_AUTH_URL = (
    "(oidc) OAuth2Session.create_authorization_url — the authorization URL "
    "(scope openid profile email, PKCE S256, nonce, state = this run id)"
)
CALL_OIDC_TOKEN = (
    "(oidc) OAuth2Session.fetch_token — exchanges the code at the discovered token endpoint "
    "(client_secret_post + PKCE verifier)"
)
CALL_OIDC_VERIFY = (
    "(oidc) jwt.decode — verifies the id_token against the JWKS: signature, issuer, audience "
    "and nonce; the claims shown are that verified token's"
)


class IdentityHandlers:
    """The identity family, bound to the shared runtime. The OAuth redirect URI is derived
    from each request's own Host header — never from the server's port."""

    def __init__(self, rt: Runtime) -> None:
        self.rt = rt

    def scenario_list(self) -> List[Dict[str, Any]]:
        return [{"id": i, "kind": k} for i, k in SCENARIOS.items()]

    def is_scenario(self, scenario_id: int) -> bool:
        return scenario_id in SCENARIOS

    def clear(self, scenario_id: int) -> None:
        self.rt.clear_scenario(scenario_id)

    # ── POST /api/scenarios/{id}/config ──────────────────────────────────────

    def config(
        self, scenario_id: int, body: bytes, headers: Optional[Dict[str, str]] = None
    ) -> Response:
        if SCENARIOS.get(scenario_id) != "runnable":
            return json_response({"error": "not_found"}, 404)
        # The redirect URI is derived from THIS request's origin and from nothing else.
        # Refuse rather than invent a host: the suite renders this sentence on Save.
        if not _request_host(headers):
            return json_response({"error": NO_ORIGIN}, 400)
        data = parse_body(body)

        cfg: Dict[str, Any] = {
            "api_url": (str(data.get("apiUrl") or "") or DEFAULT_API_URL).rstrip("/"),
            "oauth_client_id": str(data.get("oauthClientId") or ""),
            "oauth_redirect_uri": self._redirect_uri(headers),
        }
        secret = str(data.get("oauthClientSecret") or "")
        if secret:
            cfg["oauth_client_secret"] = secret

        # Any scenario whose run can carry claim values (CLAIM_VALUE_SCENARIOS) needs the OAuth
        # app private key to decrypt them.
        if scenario_id in CLAIM_VALUE_SCENARIOS:
            pem = str(data.get("oauthPrivateKeyPem") or "")
            if pem:
                cfg["oauth_private_key"] = self.rt.materialize_config_key(pem)
            passphrase = str(data.get("oauthKeyPassphrase") or "")
            if passphrase:
                cfg["oauth_key_passphrase"] = passphrase

        # Scenarios 4/8 also read live values via the service data Client.
        if scenario_id in SERVICE_SCENARIOS:
            cfg["client_id"] = str(data.get("clientId") or "")
            cfg["client_secret"] = str(data.get("clientSecret") or "")
            s_pem = str(data.get("servicePrivateKeyPem") or "")
            if s_pem:
                cfg["service_private_key"] = self.rt.materialize_config_key(s_pem)
            cfg["key_passphrase"] = str(data.get("keyPassphrase") or "")

        config_path = self.rt.write_config(scenario_id, cfg)

        # Demo-only run parameters (NOT SDK Config fields) -> meta sidecar.
        meta: Dict[str, Any] = {}
        if scenario_id in OAUTH_URL_SCENARIOS:
            meta["authorize_base"] = str(data.get("authorizeBase") or "") or DEFAULT_AUTHORIZE_URL
        if scenario_id == 3:
            meta["claims"] = _claims(data)
        if scenario_id == 8:
            meta["share_code"] = str(data.get("shareCode") or "")
            if data.get("context"):
                meta["context"] = str(data.get("context"))
        self.rt.write_config_meta(scenario_id, meta)

        return json_response({"ok": True, "configPath": config_path})

    # ── POST /api/scenarios/{id}/start ────────────────────────────────────────

    def start(self, scenario_id: int) -> Response:
        if SCENARIOS.get(scenario_id) != "runnable":
            return json_response({"error": "not_found"}, 404)
        if not self.rt.has_config(scenario_id):
            return json_response({"error": "not_configured"}, 409)

        run_id = self.rt.new_run_id()
        run: Dict[str, Any] = {
            "scenario": scenario_id, "status": "pending", "state": run_id, "calls": [],
        }

        if scenario_id in (1, 3, 4):  # sign-in / one_time / connect — redirect leg
            verifier, challenge = pkce.generate()
            run["verifier"] = verifier
            mode = {1: "signin", 3: "one_time", 4: "connect"}[scenario_id]
            claims = _claim_objects(self.rt.read_config_meta(scenario_id).get("claims") or []) \
                if scenario_id == 3 else None
            run["calls"] = [self._idw_build_call(scenario_id), {3: CALL_AUTH_ONE_TIME, 4: CALL_AUTH_CONNECT}.get(
                scenario_id, CALL_AUTH_SIGNIN)]
            oauth = self._oauth_client_for(scenario_id)
            url = oauth.authorize_url(
                mode, claims=claims, state=run_id, response_mode="redirect", code_challenge=challenge,
            )
            self.rt.write_run(run_id, run)
            return json_response({"runId": run_id, "action": {"type": "redirect", "url": url}})

        if scenario_id == 2:  # sign-in — detached
            verifier, challenge = pkce.generate()
            run["verifier"] = verifier
            run["wait"] = "detached_signin"
            run["calls"] = [self._idw_build_call(scenario_id), CALL_AUTH_SIGNIN_DETACHED]
            oauth = self._oauth_client_for(scenario_id)
            url = oauth.authorize_url(
                "signin", state=run_id, response_mode="detached", code_challenge=challenge,
            )
            self.rt.write_run(run_id, run)
            return json_response({"runId": run_id, "action": {"type": "detached", "url": url}})

        if scenario_id == 5:  # OIDC login
            verifier, _challenge = pkce.generate()
            nonce = self.rt.new_run_id()
            run["verifier"] = verifier
            run["nonce"] = nonce
            oidc = self._oidc_client_for(scenario_id)
            url = oidc.authorization_url(state=run_id, nonce=nonce, code_verifier=verifier)
            run["calls"] = [CALL_OIDC_DISCOVERY, CALL_OIDC_AUTH_URL]
            self.rt.write_run(run_id, run)
            return json_response({"runId": run_id, "action": {"type": "redirect", "url": url}})

        if scenario_id == 8:  # standalone service-2FA — the challenge step
            meta = self.rt.read_config_meta(scenario_id)
            share_code = str(meta.get("share_code") or "")
            context = str(meta["context"]) if meta.get("context") else None
            idem_key = ("demo-" + run_id)[:64]  # backend-generated, per-run (SDK requires it)
            run["challengeIdemKey"] = idem_key
            run["wait"] = "challenge"
            run["calls"] = [CALL_SERVICE_BUILD, CALL_TWO_FACTOR, CALL_CHALLENGE]
            client = self._service_client_for(scenario_id)
            challenge = client.two_factor.challenge(share_code, idem_key, context)
            run["challengeId"] = challenge.challenge_id
            self.rt.write_run(run_id, run)
            return json_response({
                "runId": run_id,
                "action": {"type": "challenge", "matchingDigits": challenge.matching_digits},
            })

        return json_response({"error": "not_found"}, 404)  # unreachable

    # ── POST /api/scenarios/{id}/enroll (scenario 8) ──────────────────────────

    def enroll(self, scenario_id: int, body: bytes) -> Response:
        if scenario_id != 8:
            return json_response({"error": "not_found"}, 404)
        if not self.rt.has_config(scenario_id):
            return json_response({"error": "not_configured"}, 409)
        data = parse_body(body)
        response_mode = "detached" if data.get("responseMode") == "detached" else "redirect"
        run_id = self.rt.new_run_id()

        oauth = self._oauth_client_for(scenario_id)
        url = oauth.authorize_url("2fa_enroll", state=run_id, response_mode=response_mode)

        run = {
            "scenario": 8, "isEnroll": True, "status": "pending", "state": run_id,
            "calls": [
                self._idw_build_call(scenario_id),
                CALL_AUTH_ENROLL_DETACHED if response_mode == "detached" else CALL_AUTH_ENROLL,
            ],
            "wait": "detached_enroll" if response_mode == "detached" else "enroll_redirect",
        }
        self.rt.write_run(run_id, run)
        action = {"type": response_mode, "url": url}
        return json_response({"runId": run_id, "action": action})

    # ── GET /callback ─────────────────────────────────────────────────────────

    def callback(self, query: Dict[str, List[str]]) -> Response:
        state = query_one(query, "state")
        run = self.rt.read_run(state)
        if run is None:
            return redirect("/?error=unknown_run")
        scenario_id = int(run.get("scenario") or 0)

        try:
            if query_one(query, "enrolled") == "true":
                run["status"] = "done"
                run["result"] = {"enrolled": True}
                run["calls"] = add_call(run.get("calls"), CALL_ENROLLED_CALLBACK)
            elif query_one(query, "code"):
                code = query_one(query, "code")
                if scenario_id == 5:
                    run = self._complete_oidc(run, code)
                else:
                    run = self._complete_signin(run, code)
            else:
                run["status"] = "failed"
                run["error"] = "callback missing code / enrolled"
        except Exception as exc:  # noqa: BLE001
            run["status"] = "failed"
            run["error"] = str(exc)

        self.rt.write_run(state, run)
        return redirect(f"/?scenario={scenario_id}&run={state}")

    # ── GET /api/runs/{runId} ─────────────────────────────────────────────────

    def run(self, run_id: str, run: Dict[str, Any]) -> Response:
        if run.get("status", "pending") == "pending":
            run = self._advance(run)
            self.rt.write_run(run_id, run)

        out: Dict[str, Any] = {
            "status": run.get("status", "pending"),
            "calls": run.get("calls", []),
        }
        if "result" in run:
            out["result"] = run["result"]
        if "error" in run:
            out["error"] = run["error"]
        return json_response(out)

    def _advance(self, run: Dict[str, Any]) -> Dict[str, Any]:
        """Short-cycled advance for a pending detached / challenge run: ONE SDK wait
        with ``timeout=2``. An SDK logical timeout stays pending; a real transport
        failure fails the run. Clients are rebuilt from the scenario's config file."""
        wait = run.get("wait")
        scenario_id = int(run.get("scenario") or 0)
        try:
            if wait == "detached_signin":
                run["calls"] = add_call(run.get("calls"), CALL_POLL_SIGNIN)
                oauth = self._oauth_client_for(scenario_id, POLL_TIMEOUT_S)
                body = oauth.poll_result(str(run["state"]), timeout=2, interval=2)
                code = str(body.get("code") or "")
                if code:
                    run = self._complete_signin(run, code)
            elif wait == "detached_enroll":
                run["calls"] = add_call(run.get("calls"), CALL_POLL_ENROLL)
                oauth = self._oauth_client_for(scenario_id, POLL_TIMEOUT_S)
                body = oauth.poll_result(str(run["state"]), timeout=2, interval=2)
                if body.get("enrolled"):
                    run["status"] = "done"
                    run["result"] = {"enrolled": True}
            elif wait == "challenge":
                run["calls"] = add_call(run.get("calls"), CALL_WAIT_RESULT)
                client = self._service_client_for(scenario_id, POLL_TIMEOUT_S)
                res = client.two_factor.wait_for_result(str(run["challengeId"]), timeout=2, interval=2)
                run["status"] = "done"
                run["result"] = {"status": res.status, "completed_at": res.completed_at}
            # else (redirect / continue-on-phone): completion arrives via /callback — stay pending.
        except ApiError as exc:
            # The SDK poll helpers signal a LOGICAL "not completed within {n}s" timeout as
            # ApiError(0, ...) with that sentinel message. A real transport failure ALSO surfaces
            # as ApiError(0, ...), so match the SDK's sentinel: only the logical timeout is still
            # pending; a real network/transport failure fails the run.
            if exc.status == 0 and "not completed within" in (exc.message or str(exc)):
                return run
            run["status"] = "failed"
            run["error"] = str(exc)
        except Exception as exc:  # noqa: BLE001
            run["status"] = "failed"
            run["error"] = str(exc)
        return run

    # ── SDK / OIDC completion helpers ─────────────────────────────────────────

    def _complete_signin(self, run: Dict[str, Any], code: str) -> Dict[str, Any]:
        scenario_id = int(run.get("scenario") or 0)
        run["calls"] = add_call(run.get("calls"), {
            3: CALL_COMPLETE_ONE_TIME, 4: CALL_COMPLETE_CONNECT,
        }.get(scenario_id, CALL_COMPLETE_SIGNIN))
        oauth = self._oauth_client_for(scenario_id)
        out = oauth.complete_sign_in(code, run.get("verifier"))
        result: Dict[str, Any] = {
            "user": out.get("user"),
            "mode": out.get("mode"),
            "two_factor": bool(out.get("two_factor")),
            "values": out.get("values") or {},
            # The raw app-key ciphertext each decrypted value above came from — pairs with
            # "values" by claim name so the panel can show a decrypt actually ran on real bytes.
            "values_cipher": out.get("values_cipher") or {},
        }

        if scenario_id == 4:  # Connect: read the person's LIVE values via the service Client.
            share_code = str((out.get("user") or {}).get("share_code") or "")
            run["calls"] = add_call(run.get("calls"), CALL_SERVICE_BUILD)
            client = self._service_client_for(scenario_id)
            run["calls"] = add_call(run.get("calls"), CALL_CONNECTIONS_LIVE)
            live: Dict[str, Any] = {}
            for conn in client.connections():
                if share_code and conn.share_code == share_code:
                    live = {slug: jsonable(v.value) for slug, v in conn.values.items()}
                    break
            result["live_values"] = live

        run["status"] = "done"
        run["result"] = result
        return run

    def _complete_oidc(self, run: Dict[str, Any], code: str) -> Dict[str, Any]:
        scenario_id = int(run.get("scenario") or 0)
        oidc = self._oidc_client_for(scenario_id)
        for _name in (CALL_OIDC_DISCOVERY, CALL_OIDC_TOKEN, CALL_OIDC_VERIFY):
            run["calls"] = add_call(run.get("calls"), _name)
        claims = oidc.complete(
            code=code,
            state=str(run["state"]),
            code_verifier=str(run.get("verifier") or ""),
            nonce=str(run.get("nonce") or ""),
        )
        run["status"] = "done"
        run["result"] = {"claims": claims}
        return run

    # ── SDK / OIDC client builders — built from the persisted config FILE ─────

    def _oauth_client_for(self, scenario_id: int, poll_timeout: Optional[float] = None) -> OAuthClient:
        path = self.rt.config_path_for(scenario_id)
        kwargs: Dict[str, Any] = {}
        if poll_timeout is not None:
            kwargs["session"] = TimeoutSession(poll_timeout)
        if not self._uses_default_authorize_base(scenario_id):
            # Non-default authorize base (local-stack option): still load Config from the file, just
            # supply the alternate consent host the from_config wrapper cannot set.
            base = str(self.rt.read_config_meta(scenario_id).get("authorize_base") or "")
            return OAuthClient(Config.from_idw_file(path), authorize_url=base, **kwargs)
        return OAuthClient.from_config(path, **kwargs)

    def _uses_default_authorize_base(self, scenario_id: int) -> bool:
        """Whether ``_oauth_client_for`` takes the named-constructor branch. The SAME predicate
        decides the client AND the trace entry, so the panel can never name a constructor that did
        not run — the local-stack option really does build the client a different way."""
        base = str(self.rt.read_config_meta(scenario_id).get("authorize_base") or "")
        return not base or base == DEFAULT_AUTHORIZE_URL

    def _idw_build_call(self, scenario_id: int) -> str:
        """The trace entry for the OAuth client ``_oauth_client_for`` just built."""
        return CALL_IDW_BUILD if self._uses_default_authorize_base(scenario_id) else CALL_IDW_BUILD_LOCAL

    def _service_client_for(self, scenario_id: int, poll_timeout: Optional[float] = None) -> Client:
        path = self.rt.config_path_for(scenario_id)
        if poll_timeout is None:
            return Client.from_config(path)
        cfg = Config.from_file(path)
        return Client(cfg, http=HttpClient(cfg, session=TimeoutSession(poll_timeout)))

    def _oidc_client_for(self, scenario_id: int):
        from ..oidc import OidcClient

        cfg = self.rt.load_config(scenario_id)
        # The SAME value the authorize URL carried, so the two legs of the exchange cannot
        # diverge. An absent record is a loud failure, never a substituted host.
        redirect_uri = str(cfg.get("oauth_redirect_uri") or "")
        if not redirect_uri:
            raise ValueError(NO_STORED_ORIGIN)
        return OidcClient(
            issuer=str(cfg.get("api_url") or ""),
            client_id=str(cfg.get("oauth_client_id") or ""),
            client_secret=str(cfg.get("oauth_client_secret") or ""),
            redirect_uri=redirect_uri,
        )

    def _redirect_uri(self, headers: Optional[Dict[str, str]]) -> str:
        """The registered redirect URI: ``http://{host}/callback``, host = the origin the browser
        actually used. The server binds all interfaces, so a phone on the LAN saves ITS
        origin into the config file and the OAuth round-trip returns to the phone, not to the
        phone's own localhost. Never falls back to a hardcoded host — ``127.0.0.1`` and
        ``localhost`` are DIFFERENT origins for redirect matching and for browser storage alike,
        so a substituted default drops the developer on an origin whose localStorage never held
        the setup and whose URI the OAuth app never registered."""
        host = _request_host(headers)
        if not host:
            raise ValueError(NO_ORIGIN)
        return f"http://{host}/callback"


# ── module helpers ────────────────────────────────────────────────────────────


def _request_host(headers: Optional[Dict[str, str]]) -> str:
    """The origin THIS request arrived on — the only source the redirect URI is ever derived
    from. Header names are matched case-insensitively (the wire spelling is the client's)."""
    for name, value in (headers or {}).items():
        if name.lower() == "host":
            return str(value).strip()
    return ""


def _claims(data: Dict[str, Any]) -> List[str]:
    raw = data.get("claims")
    if isinstance(raw, list) and raw:
        return [str(x) for x in raw]
    return ["email", "phone"]  # a small default claim set


def _claim_objects(types: List[Any]) -> List[Claim]:
    # A claim carries a mandatory, unique `name` — the key `values` and `attestations` come
    # back under. The demo's config lists claim TYPES, so the type doubles as the name here; a real
    # integration usually names them for its own domain ("billing_email").
    return [Claim(name=str(t), type=str(t)) for t in types]
