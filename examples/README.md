# allus SDK examples — Python

A runnable **example test suite** for the `allus-company-data` **Python SDK**. One
local server serves a shared web frontend plus a small demo backend that shows which
SDK call implements each scenario, across **three families**:

| Family | Scenarios | What it demonstrates |
|---|---|---|
| **Identity** | *Sign in with allme* (redirect + detached), one-time claims, connect, OIDC login (via a real third-party OIDC client), 2FA guide, standalone service-2FA + enrollment | the OAuth / OIDC / 2FA surface a website uses to sign a person in |
| **Flow** | run a contract flow end-to-end | trigger a flow run, drive the company steps with type-checked filling, hand a turn to the person's phone, read the decrypted answers, download a generated contract |
| **Company-data** | connections, request-field definitions, change-feed pump, webhook receiver, create the six document types | the regular company-data surface a company uses to read connected people and receive updates |

~90 % of the logic is a shared frontend fetched from a pinned release; this directory
is the thin Python backend. Everything the handlers do goes through the SDK's
**intended top-level surface** — never internals, never raw platform HTTP. This is a
**demo**, not a production service: disposable local state under `.runtime/`, a
single-worker stdlib server, no hardening beyond ordinary localhost developer use.

---

## Prerequisites

- **Python ≥ 3.11** on your PATH (the SDK requires it; the venv inherits the
  interpreter you launch with).
- **Network access** — first run fetches the frontend bundle and installs deps.

No other tooling: the launcher creates the virtualenv and unpacks the bundle with
the standard library.

## Get the code

Clone the SDK repository and change into this examples directory:

```bash
git clone https://github.com/allus-fyi/company-data-python.git
cd company-data-python/examples
```

## Run it — one command

```bash
python bin/start.py            # first run creates .venv + installs deps
# or a different port:
PORT=9000 python bin/start.py
```

**`python bin/start.py` runs `allus_examples`, which fetches the pinned portal
bundle and serves the example test suite (all three scenario families) on
http://localhost:8091.** In detail, the launcher:

1. creates a local `.venv` and installs this suite's own `requirements.txt` (the
   local SDK, editable, via `-e ..`, plus Authlib for the OIDC scenarios),
2. wipes `.runtime/` (fresh state every boot),
3. downloads the **pinned** frontend release named in `frontend.lock`, **verifies its
   sha256**, and unpacks it to `.frontend/<tag>/` (a present, verified bundle is a
   cache hit — nothing is re-fetched),
4. checks the bundle's `contract.json` version against the backend's (**contract v3**;
   a mismatch is refused loudly),
5. refuses a busy port with a clear message, then
6. serves `http://localhost:8091` with a **single-worker** `http.server` — one request
   at a time (requests serialize, so there are no locks), including the public
   `POST /webhook`.

Open **http://localhost:8091** and pick a scenario.

**Port.** `8091` is the default, overridable with `PORT`. The default is deliberately
the **same across all allus SDK examples** (one browser origin ⇒ your localStorage
setup carries across SDKs) — the documented consequence is that only one example runs
at a time.

---

## The config-file model

Each scenario's setup panel has a **Save** button. It POSTs your settings to the
backend, which writes them to a canonical SDK **config file** under
`.runtime/config/` (any private-key PEM lands in `.runtime/config/keys/` at `0600`,
referenced by path) — the same shape a real integrator wires by hand. The panel shows
the written path so you can open and read the real config; **Run** / **Trigger** then
builds the SDK from that file (`Client.from_config` / `OAuthClient.from_config`) and
runs off it. You never hand-create or edit the file — it is there to be read.

## Where the SDK calls live

Open a family's handler file and you see the SDK calls directly:

| Scenario | Handler | SDK / library call(s) |
|---|---|---|
| Sign in — redirect (id 1) | `allus_examples/handlers/identity.py` | `OAuthClient.authorize_url('signin', …)` → `complete_sign_in` |
| Sign in — detached (id 2) | identity.py | `authorize_url(response_mode='detached')` → `poll_result` → `complete_sign_in` |
| One-time claims (id 3) | identity.py | `authorize_url('one_time', claims=…)` → `complete_sign_in` (decrypts with the app private key) |
| Connect (id 4) | identity.py | `authorize_url('connect', …)` → `complete_sign_in`, then `Client.connections` for live values |
| OIDC login / continue-on-phone (ids 5, 6) | identity.py + `allus_examples/oidc.py` | **Authlib** `OAuth2Session.create_authorization_url` → `fetch_token` → `jwt.decode` (id_token verify) |
| 2FA at consent — **guide** card (id 7) | — | no `/start`; a checklist linking to scenarios 1 & 5 |
| Standalone service-2FA + enrollment (id 8) | identity.py | `Client.two_factor.challenge` → `wait_for_result`; `/enroll` → `authorize_url('2fa_enroll', …)` |
| Run a contract flow (`flow:run`) | `allus_examples/handlers/flow.py` | `identity` / `trigger_flow_run` / `flow_run` / `process_flow_run` / `flow_run_answers` / `flow_run_document` |
| Read connected people (`companydata:read`) | `allus_examples/handlers/company_data.py` | `Client.connections()` |
| Request-field definitions (`companydata:definitions`) | company_data.py | `Client.request_fields()` |
| Change-feed pump (`companydata:changes`) | company_data.py | `Client.process_changes()` |
| Webhook receiver (`companydata:webhook`) | company_data.py | `Client.verify_webhook()` + `parse_webhook()` + a `drain_batch()` feed fallback |
| Create the six document types (`companydata:documents`) | company_data.py | `Client.create_document()` ×6 |

The scaffolding shared by all three families (runtime state, launcher, router, bundle
fetch+verify, contract guard, port guard, config-file writing, run store, clear) lives
at the package root: `allus_examples/{runtime,launcher,server,common,pkce,oidc}.py`.

---

## Portal setup

The scenario advanced inputs default to the deployed platform (API url
`https://api.allme.fyi`). You register the demo's **service + data client**, create
request fields, connect a test person, and import/publish flows in the **allus portal
at https://portal.allus.fyi**. Each scenario's setup checklist names the exact portal
steps. To run against a local stack instead, switch the advanced **API url** to your
local API in the browser — no file in this suite changes.

### Flow — the two fixtures

The flow scenario ships two fixtures you import into the portal (Flows → Import), then
publish:

| Fixture (`fixtures/`) | Shape |
|---|---|
| `fixtures/info-gathering.zip` | `data_only` — a few company steps (text, an **email** validation-demo step, an address composite), then one person turn. |
| `fixtures/contract.zip` | `document` — a company step, then a signature leaf that generates a document. |

The person's turn — and the contract fixture's signature — are completed on a **phone**
with the allme app, signed in as the connected demo person.

### Webhook — set up first, tunnel optional

The webhook scenario is **setup-first**: its run needs the **registered webhook id +
HMAC secret**, so register the webhook in the portal and copy both into the scenario's
inputs before running. Set **`encrypt_payload` OFF** (this example holds no account
private key, so an encrypted body cannot be decrypted here).

Inbound delivery of live webhooks needs the platform to reach your `localhost`, which
requires a **tunnel** — this is **optional**:

- **With a tunnel** (`cloudflared tunnel --url http://localhost:8091`), register the
  printed public URL with **`/webhook`** appended so real deliveries arrive.
- **Without a tunnel**, the same run **also polls the change feed** (`drain_batch()`,
  one fetch per `GET /api/runs` poll, deduped on `Change.id`) as an always-works
  fallback (labeled `feed` vs `webhook`), so events still appear.

The receiver returns **401** on a bad HMAC and **200** otherwise (only a 200 counts as
success to the platform worker).

---

## Bumping the frontend pin

The frontend ships as a checksummed release asset; the ONE pin for the whole examples
tree lives in `frontend.lock` (`{tag, sha256}`), and it pins the release carrying the
one-portal frontend (**contract v3**). To move to a newer release: note the release
**tag** and its `dist.tar.gz` checksum (`shasum -a 256 dist.tar.gz`) from
`github.com/allme-sdk/example-test-suite`, set `tag` + `sha256` in `frontend.lock`,
`rm -rf .frontend/`, then re-run — it re-fetches, verifies the checksum, and checks the
bundle's `contract.json` version against the backend (a mismatch refuses loudly). A
**contract-version change** means the backend must be updated in the same step.

## Using the published SDK package

By default this suite installs `allus-company-data` from a **local editable path**
(`-e ..` in `requirements.txt` — the SDK source tree in this repo). To point at the
**published** package instead, replace that line with a version spec (e.g.
`allus-company-data>=<version>`), then `rm -rf .venv` and re-run.

## Not a separately published package — but it ships with the SDK

Everything here is example-only: the suite is not a separately published package. Since
#493 the SDK root `pyproject.toml` maps this tree into the distribution as
`allus_company_data.examples`, so `examples/` ships **inside** the installed SDK. Its own
dependencies (such as Authlib) stay example-only and never become dependencies OF the SDK.
