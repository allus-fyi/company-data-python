# Company-data example — connections / request fields / change feed / webhooks / documents (Python SDK)

A runnable website that demonstrates the **regular company-data surface** a company
uses — reading connected people, request-field definitions, the change feed,
webhooks, and documents — through the `allus-company-data` **Python SDK**. Like the
[identity example](../identity), ~90 % of the logic is a shared frontend fetched
from a pinned release; this directory is the thin Python backend that implements the
[demo-backend contract](https://github.com/allme-sdk/example-test-suite) for the
five `companydata:*` scenarios.

Everything the handlers do goes through the SDK's **intended top-level functions**
— `Client.connections()`, `request_fields()`, `process_changes()` /
`drain_batch()`, `verify_webhook()` + `parse_webhook()`, `create_document()` —
never internals, never raw platform HTTP.

---

## Run it — one command

```bash
git clone https://github.com/allus-fyi/company-data-python
cd company-data-python/examples/company-data
python bin/start.py
```

`bin/start.py` is a stdlib-only bootstrapper: on first run it creates a local
`.venv` and installs this example's own `requirements.txt` (the local SDK, editable,
via `-e ../..`), then hands off to `python -m company_data_example` under that venv,
which:

1. wipes `.runtime/` (fresh state every boot),
2. on first run, downloads the **pinned** frontend release named in `frontend.lock`,
   **verifies its sha256**, and unpacks it to `.frontend/<tag>/` (a present, verified
   bundle is a cache hit — nothing is re-fetched),
3. checks the bundle's `contract.json` version against the backend's,
4. refuses a busy port with a clear message, then
5. serves `http://localhost:8091` with a **single-worker** `http.server` (one
   request at a time — requests serialize, so there are no locks).

Open **http://localhost:8091** and pick a scenario. Each scenario's setup panel has
a **Save** button: it POSTs your settings to the backend, which writes them to a
canonical SDK **config file** (`.runtime/config/{sid}.json`, the service PEM under
`.runtime/config/keys/`) — the same shape a real integrator wires by hand. The panel
shows the written path so you can open and read the real config; **Run** then builds
the SDK from that file (`Client.from_config`) and runs off it. You never hand-create
or edit the file — the backend writes it from your browser inputs; it is there to be
read.

**Port.** `8091` is the default, overridable with the `PORT` env var
(`PORT=8092 python bin/start.py`). The default is the **same across all six SDK
examples** (one browser origin ⇒ your localStorage setup carries across SDKs), so
only one runs at a time.

**Requirements:** Python ≥ 3.11 (the SDK requires it; the venv inherits the
interpreter you launch with) and network access to fetch the frontend bundle. No
other tooling — the launcher unpacks the bundle with the stdlib `tarfile`.

---

## The five scenarios

| Scenario | SDK call | What it shows |
|---|---|---|
| **Read connected people** (`companydata:read`) | `Client.connections()` | each connected person's decrypted values, grouped one card per person (two people who filled the same slug stay distinguishable) |
| **Request-field definitions** (`companydata:definitions`) | `Client.request_fields()` | your request slugs → label / type / the folded `mandatory` flag + `one_time` |
| **Change-feed pump** (`companydata:changes`) | `Client.process_changes()` | a crash-safe drain of the change feed (idempotent per event on `Change.id`), shown as a batch |
| **Webhook receiver** (`companydata:webhook`) | `Client.verify_webhook()` + `Client.parse_webhook()` | a public `POST /webhook` (401 on a bad HMAC, 200 otherwise) **plus** a `Client.drain_batch()` change-feed fallback so it works with no tunnel |
| **Create the six document types** (`companydata:documents`) | `Client.create_document()` ×6 | broadcast JSON / broadcast PDF / per-person file / private file / contract-requiring-signature / contract-requiring-acceptance |

Every scenario uses the **service role**, so the service PEM + passphrase are a
required input on all five (the SDK loads the key at `Client` construction).

The four data scenarios run synchronously on **Run**: the run is `done` with its
result read once via `GET /api/runs/{runId}`. The webhook scenario is
**accumulating** — its run stays `pending` while events arrive (via `POST /webhook`
and the per-poll feed fallback), and the frontend keeps polling and re-rendering
`run.result`.

---

## Default target — the deployed platform

The scenario **advanced inputs default to the deployed platform**: API url
`https://api.allme.fyi`. You register the demo's **service + data client** in the
**allus portal at https://portal.allus.fyi**; each scenario's setup checklist names
the exact portal steps (create the service + download its PEM, register a data client
on it, configure request fields, connect a test person). If you run the platform API
locally, switch the advanced **API url** to `http://localhost:8070` in the browser —
no file in this example changes.

---

## The webhook scenario — setup first; a tunnel stays optional

This scenario is **setup-first**: register a webhook on your service in the portal,
then paste its **webhook id** and one-time **HMAC secret** into the scenario before
starting it — **the run refuses to start without them** (`server.py` answers
`409 not_configured`). Set `encrypt_payload` OFF; this example holds no account
private key.

Once it is started you need **no tunnel** to see events: the same run **also polls
the change feed** (`Client.drain_batch()`, one fetch per `GET /api/runs` poll, deduped
on `Change.id`) as an **always-works fallback** (labeled `feed` vs `webhook`), so
events appear even when nothing can deliver to your machine.

**Optional / advanced — real inbound delivery.** To see the platform POST to your
`/webhook` endpoint for real, the platform must be able to reach your machine. Open one
tunnel (`cloudflared tunnel --url http://localhost:8091`) and register the printed
public URL with **`/webhook`** appended as the service webhook in the portal. Set
**`encrypt_payload` OFF** (this example holds no account private key; an encrypted body
cannot be decrypted here). Copy the **webhook id** and the one-time **HMAC secret**
shown at registration into the scenario's inputs. (If you run the platform API
locally, it can reach `localhost` directly — register `http://localhost:8091/webhook`
and skip the tunnel.)

The exact receiver sequence (never the combined `handle_webhook()`, which can't
split 401 from 200): read `X-Allus-Webhook-Id` → an unknown/stale id or no active run
is a **200** discard; `verify_webhook()` false → **401**; `parse_webhook()` ok →
append + **200**; a parse error on a *verified* delivery → **200** acknowledge (and
increment `unparseable`). Only a **200** counts as success to the platform worker.

---

## Bumping the frontend pin

The frontend ships as a checksummed release asset; the pin lives in `frontend.lock`
(`{"tag":"v0.3.0","sha256":"<sha256 of dist.tar.gz>"}`). To move to a newer release:
note the release **tag** and its `dist.tar.gz` checksum (`shasum -a 256
dist.tar.gz`), set `tag` + `sha256` in `frontend.lock`, `rm -rf .frontend/`, then
re-run. A **contract-version change** means the backend must be updated in the same
step; the startup guard refuses a mismatch loudly. A pin bump is a **per-example
commit**.

---

## Using the published SDK package

By default this example installs `allus-company-data` from a **local editable path**
(`-e ../..` in `requirements.txt` — the SDK source tree in this repo). To point at
the **published** package instead, replace that line with `allus-company-data`
(optionally pinned), then `rm -rf .venv` and re-run.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| **`port 8091 is busy`** at startup | Another example (or process) holds the port — one browser origin is shared across SDK examples, so only one runs at a time. Stop it, or run `PORT=<n> python bin/start.py`. |
| **`pip` refuses to install the SDK** (`requires-python`) | The SDK needs Python ≥ 3.11. Launch with a 3.11+ interpreter (e.g. `python3.13 bin/start.py`); the venv inherits it. Delete `.venv` after switching. |
| **Stale / wrong frontend** after a pin bump | The present bundle is a cache hit and is not re-fetched. `rm -rf .frontend/` and re-run to re-download the pinned release. |
| **`contract mismatch: bundle contractVersion=… backend implements …`** | The pinned bundle's `contract.json` version differs from what this backend implements. Bump `frontend.lock` to a release whose `contract.json` matches (and re-fetch), or update the backend. |
| **`frontend checksum MISMATCH`** | The downloaded `dist.tar.gz` doesn't match `frontend.lock`'s `sha256`. Fix the `sha256` or re-download; the example refuses to serve an unverified bundle. |
| **Webhook deliveries never arrive (deployed)** | The cluster cannot reach `localhost` — you need the `cloudflared` tunnel above, and the registered URL must end in `/webhook`. The change-feed fallback still shows events meanwhile. |
| **A per-person / contract document errors** | Those types target a connected person — set the **target person share code** in the documents scenario's setup, then re-run. Broadcast documents need no target. |

---

## What's in here

| Path | What it is |
|---|---|
| `bin/start.py` | The one-command launcher: creates `.venv`, installs `requirements.txt`, execs the server. |
| `requirements.txt` | This example's own deps (the SDK via `-e ../..`, `requests`). **Not part of the published SDK package** (the SDK's `pyproject.toml` packages only `src/`). |
| `company_data_example/launcher.py` | Boot steps: wipe `.runtime/`, fetch+verify the bundle, contract guard, single-worker `http.server`. |
| `company_data_example/server.py` | The backend: the five scenario handlers, the webhook receiver, the Change projection. |
| `company_data_example/runtime.py` | Cross-request state: config files + run store + the single webhook routing record + the pump cache dir. |
| `frontend.lock` | The pinned frontend release (`{tag, sha256}`). |
| `.frontend/` | The fetched, verified frontend bundle (git-ignored). |
| `.runtime/` | The written SDK config files, per-run state, webhook routing record, and pump cache — git-ignored, wiped every boot; `0700`. |

`.runtime/`, `.frontend/`, and `.venv/` are git-ignored — the fetched bundle and
installed deps never land in the repo.
