# allus-company-data (Python)

The Python SDK for the **allus company-data API**. Point it at a JSON
config file and it hands back typed, plaintext, **your-slug-keyed conclusions**:
for each connected person, a map of *your request-field slug → plaintext value*
(plus whether the value is live and when it last changed).

The SDK hides everything else — the OAuth token, the field catalog, the id
plumbing, the hybrid decryption, binary fetching, the changes-queue mechanics,
JSON-vs-XML. The platform is **zero-knowledge**: the API only ever holds
ciphertext, so all decryption happens inside the SDK with your service private
key. **The person's own field choices are never exposed** — you only ever see
the request slots you configured.

> This SDK is one of six language ports that share an identical API surface.
> This manual is the Python view of it.

**Contents:** [TL;DR — fetch new updates](#tldr--fetch-new-updates) ·
[Quickstart](#quickstart) · [Every call](#every-call) ·
[The typed value model](#the-typed-value-model) ·
[The changes pump](#the-changes-pump) · [Webhooks](#webhooks) ·
[Rate limits](#rate-limits) · [Errors](#errors) ·
[How it's wired](#how-its-wired)

Deeper reference pages live in [`docs/`](docs/):
[config](docs/config.md) · [model](docs/model.md) · [pump](docs/pump.md) ·
[webhooks](docs/webhooks.md) · [errors](docs/errors.md).

---

## TL;DR — fetch new updates

```bash
pip install allus-company-data
```

Point a config.json at your service keys:

```json
{
  "api_url": "https://api.allme.fyi",
  "client_id": "svc_xxx",
  "client_secret": "xxx",
  "service_private_key": "/path/to/service.pem",
  "key_passphrase": "xxx",
  "cache_dir": "./allus-cache"
}
```

Drain everything new, handled one update at a time:

```python
from allus_company_data import Client

client = Client.from_config("config.json")

def handle(change):
    # one update at a time: event, person, slug, value, live, at
    print(change.event, change.person_id, change.slug, change.value,
          "live" if change.live else "snapshot", change.at)

client.process_changes(handle)   # returns when the feed is empty
```

`process_changes` pulls every pending change, decrypts it, and hands them to your
callback ONE BY ONE, acking each only after your code returns. Crash mid-batch?
The next run replays exactly what wasn't acked — nothing is lost, and the API
keeps no backlog of its own. Run it on a schedule (cron / systemd timer); there
is no daemon/follow mode by design. Connections, binary values, and webhooks are
documented below.

---

## Quickstart

Requires **Python ≥ 3.11**.

```bash
pip install allus-company-data
# or, working from this repo:  pip install -e '.[dev]'      # from sdks/python/
python -c "import allus_company_data; print(allus_company_data.__version__)"
```

### 1. Write a config file

A single JSON file holds everything. Any field can be overridden by an `ALLUS_*`
env var, so secrets needn't live in the file. **No SDK method ever takes a key,
passphrase, or secret as an argument** — they all come from here.

`allus.json`:

```json
{
  "api_url": "https://api.allme.fyi",
  "client_id": "svc_1a2b3c…",
  "client_secret": "…",
  "service_private_key": "./service-CRM.pem",
  "key_passphrase": "…",

  "account_private_key": "./account.pem",
  "account_passphrase": "…",

  "webhooks": {
    "wh_abc123": "hmac_secret_for_that_webhook"
  },

  "cache_dir": "./allus-cache",
  "format": "json"
}
```

| Field | Required | Meaning |
|-------|----------|---------|
| `api_url` | yes | API base, e.g. `https://api.allme.fyi`. |
| `client_id` / `client_secret` | yes | The registered `client_credentials` credentials for **one** service. |
| `service_private_key` | yes | Path to the OpenSSL-encrypted PKCS#8 PEM you downloaded from the portal. |
| `key_passphrase` | yes | Decrypts that PEM in memory at startup. |
| `account_private_key` / `account_passphrase` | only for `encrypt_payload` webhooks | The company **account** key, used to unwrap an encrypted webhook envelope. |
| `webhooks` / `webhook_secret` | webhook auth — HMAC (default) | Per-webhook HMAC secrets keyed by webhook id (matched via the `X-Allus-Webhook-Id` header). A single-webhook service can use a flat `"webhook_secret": "…"` instead of the map. |
| `webhook_bearer_token` | webhook auth — bearer | Verify `Authorization: Bearer <token>` deliveries. |
| `webhook_basic` | webhook auth — basic | `{"username","password"}` — verify HTTP Basic deliveries. |
| `webhook_header` | webhook auth — header | `{"name","value"}` — verify a custom-header delivery. |
| `webhook_auth_none` | webhook auth — none | `true` — explicit opt-out; `verifyWebhook` always passes (use only behind your own gateway). **Configure at most one** webhook auth method (two+ → `ConfigError`). |
| `cache_dir` | no (default `./allus-cache`) | Durable local buffer for the changes pump. Must be writable + durable. |
| `format` | no (default `json`) | Wire format `json` or `xml`. Invisible in the output. |

Env overrides use the `ALLUS_` prefix of the field name, e.g.
`ALLUS_CLIENT_SECRET`, `ALLUS_KEY_PASSPHRASE`, `ALLUS_ACCOUNT_PASSPHRASE`,
`ALLUS_WEBHOOK_SECRET`. A missing/invalid config (or an unreadable PEM / wrong
passphrase) raises `ConfigError` at construction — fail fast.

### 2. First call — list a connection's values

```python
from allus_company_data import Client

client = Client.from_config("allus.json")

# Iterate every connected person (lazy, auto-paged).
for conn in client.connections():
    print(conn.display_name, conn.person_id)
    for slug, val in conn.values.items():
        print(f"  {slug} = {val.value!r}  (live={val.live}, updated={val.updated_at})")
    break  # just the first one for the demo
```

Or fetch one connection by id:

```python
conn = client.connection("019xxxxxxxxxxxxxxxxxxxxxxxxx")
email = conn.values["work_email"].value        # "alice@acme.com"  (a str)
```

`client = Client.from_env()` builds the same client entirely from `ALLUS_*`
env vars (no file).

---

## Every call

`Client` is the only object you construct. Build it from config, then:

```python
Client.from_config(path, **kwargs) -> Client     # from a JSON file (env overrides secrets)
Client.from_env(**kwargs)          -> Client      # entirely from ALLUS_* env vars
```

`kwargs` are advanced/optional: `http` (an injected `HttpClient`), `logger` (a
`logging.Logger`), `sleep` (a `Callable[[float], None]`, for tests).

### `request_fields()`

```python
request_fields() -> list[RequestField]
```

Your request-field **definitions** — fetched once from
`GET /api/company-data/request-fields` and cached for the life of the client (it
types every value). Returns *your* request config, never the person's fields.

* **Params:** none.
* **Returns:** `list[RequestField]` — each `RequestField(slug, label, type, one_time, mandatory, raw)`. `mandatory` is true when the field is mandatory-to-provide **or** mandatory-to-stay-connected.
* **Raises:** `AuthError`, `ApiError`, `RateLimitError`.

```python
for f in client.request_fields():
    flag = "mandatory" if f.mandatory else "optional"
    print(f"{f.slug:20} {f.type:10} {flag}{' (one-time)' if f.one_time else ''}")
```

### `connections(limit, offset)`

```python
connections(limit: int = 100, offset: int = 0) -> Iterator[Connection]
```

A **lazy generator** that auto-pages `GET /api/company-data/connections?limit&offset`
and yields one typed `Connection` at a time (bounded memory for a large book).
Each `conn.values[slug]` is already decrypted (or a lazy binary handle).

* **Params:** `limit` — page size (default 100); `offset` — starting offset.
* **Returns:** `Iterator[Connection]`.
* **Raises:** `AuthError`, `ApiError`, `DecryptError` (per value, at access), `RateLimitError` (after the iterator's bounded internal backoff — see [Rate limits](#rate-limits)).

> **Heavily rate-limited.** Use for the initial full sync + occasional
> reconciliation only — never as a poll substitute for the changes feed. The
> generator paces itself within the limit (backs off on `Retry-After`).

```python
# Initial full sync, streaming so a 100k-connection book never lands in memory.
for conn in client.connections(limit=200):
    upsert_local_record(conn)
```

### `connection(id)`

```python
connection(id: str) -> Connection
```

Fetch one connection by its connection id (`GET /api/company-data/connections/{id}`).

* **Params:** `id` — the connection id (`Connection.id`).
* **Returns:** one `Connection`. Note: this endpoint returns `{connection_id, user_id, values}` and **no** `display_name`/`connected_at`, so those identity fields are `None` here (the list endpoint carries them).
* **Raises:** `AuthError`, `ApiError` (404 if unknown), `DecryptError`, `RateLimitError`.

```python
conn = client.connection(conn_id)
phone = conn.values.get("mobile")
if phone:
    print(phone.value, "live" if phone.live else "snapshot")
```

### `logs(limit, offset)`

```python
logs(limit: int = 50, offset: int = 0) -> list[LogEntry]
```

The service's activity log (`GET /api/company-data/logs?limit&offset`) — **ops
events only** (email / purge / webhook), never person field data.

* **Params:** `limit` (default 50), `offset` (default 0).
* **Returns:** `list[LogEntry]` — each `LogEntry(type, message, metadata, at, raw)`.
* **Raises:** `AuthError`, `ApiError`, `RateLimitError`.

```python
for entry in client.logs(limit=20):
    print(entry.at, entry.type, entry.message)
```

### `process_changes(handler, **options)`

```python
process_changes(handler: Callable[[Change], None], **options) -> None
```

The crash-safe changes pump: drains the feed through `handler` **one `Change` at
a time**, durably buffering each batch before delivery, with per-item ack and
retry → dead-letter → continue. Runs **until the feed is empty, then returns** —
there is **no follow/daemon mode** (you schedule re-runs yourself). Delivery is
**at-least-once**, so your handler **must be idempotent** (dedup on `Change.id`).
See [The changes pump](#the-changes-pump) for the full model.

* **Params:** `handler` — your callback; called with one `Change`. A return is an ack; an exception triggers retry.
* **Options** (keyword-only): `batch_size` (clamped to ≤ 500, default 100), `max_retries` (default 3), `on_error` (`"deadletter"` — default — or `"halt"`), `backoff` (`Callable[[int], float]`, attempt → seconds).
* **Returns:** `None` (when the feed is empty + the buffer is drained).
* **Raises:** `AuthError`, `ApiError`, `RateLimitError` (during a drain); `ValueError` (bad `on_error`); whatever the handler raises if `on_error="halt"` and retries are exhausted.

```python
def handle(change):
    if already_processed(change.id):      # idempotency — dedup on the stable id
        return
    if change.event == "field_updated":
        store(change.person_id, change.slug, change.value)
    elif change.event in ("connection_deleted", "field_deleted"):
        remove(change.person_id, change.slug)
    mark_processed(change.id)

client.process_changes(handle)            # returns when the feed is empty
```

> `logger` is **not** a `process_changes` option in this SDK — pass it once to
> the `Client` constructor (`Client.from_config("allus.json", logger=my_logger)`).

### Advanced changes primitives

```python
drain_batch(max: int = 100)                      -> list[Change]   # raw, UNBUFFERED — you own durability
dead_letters()                                   -> list[dict]      # the local dead-letter store
retry_dead_letters(handler, **options)           -> int             # re-drive dead-lettered events; returns count re-driven
```

* `drain_batch(max)` — fetches one batch (clamped ≤ 500) and returns the decrypted `Change`s directly. It does **not** persist anything, so a crash loses what the API already deleted. Prefer `process_changes` for safe consumption.
* `dead_letters()` — each dict is the stored (ciphertext) event plus a flattened `error` and `attempts`.
* `retry_dead_letters(handler, **options)` — same `max_retries` / `on_error` / `backoff` options as `process_changes`; on success a record is removed, on repeated failure it stays dead-lettered (or re-raises under `"halt"`). Dead letters are never re-fetched from the API — the local store is their only home.

```python
for dl in client.dead_letters():
    print("stuck:", dl["id"], dl["error"], "after", dl["attempts"], "attempts")

n = client.retry_dead_letters(handle)     # after you've fixed the bug
print(f"re-drove {n} dead letters")
```

### Webhook helpers (on the client)

The webhook receiver helpers are also exposed as `Client` methods (they delegate
to the module functions, fully config-driven — no key/secret arguments):

```python
client.verify_webhook(raw_body: bytes, headers: dict) -> bool
client.parse_webhook(raw_body: bytes, headers: dict)  -> Change
client.handle_webhook(raw_body: bytes, headers: dict) -> Change   # verify + parse
```

* `verify_webhook` — recomputes `HMAC-SHA256(raw_body, secret)` and constant-time-compares it to `X-Allus-Signature`. Returns `True`/`False`; **never raises** for a bad signature.
* `parse_webhook` — body → a typed `Change`. Does **not** verify. Handles JSON, XML, and the `encrypt_payload` account-key envelope. Raises `WebhookError` on a malformed/unparseable body.
* `handle_webhook` — verify **then** parse; raises `WebhookError` on a bad/unknown signature, otherwise returns the `Change`. The typical one-liner inside a route.

The same three are importable as standalone functions
(`from allus_company_data import verify_webhook, parse_webhook, handle_webhook`),
which take the `config` and the decrypt/type closures explicitly — but inside an
app you'll almost always use the client methods. See [Webhooks](#webhooks).

---

## The typed value model

You work with these objects and nothing else (`from allus_company_data import …`):

```text
RequestField { slug, label, type, one_time, mandatory }     # YOUR request config
Connection   { id, person_id, display_name, connected_at, values: {<slug>: Value} }
Value        { value, live, updated_at }
Change       { id, event, person_id, slug?, value?, live?, at }
LogEntry     { type, message, metadata, at }
```

### Keyed by *your* slug

`conn.values["work_email"].value` → `"alice@acme.com"`. The key is the stable,
explicit slug you set per request field in the portal — rename the label freely,
the slug is the contract. **The person's source field is never exposed**: no
source slug, no `field_id`, not even via `.raw`.

### `Value(value, live, updated_at)`

| Attribute | Meaning |
|-----------|---------|
| `value` | The typed plaintext (see the table below). |
| `live` | `True` if the person chose "keep connected" (auto-updates); `False` for a one-time snapshot. |
| `updated_at` | `datetime` of when this answer last changed (per-answer, rides on the `Value`). |

### Value types (from the field's `type`)

| Field type | Python `value` |
|------------|----------------|
| `email`, `phone`, `url`, `text` | `str` |
| `address`, `bank`, `creditcard` | `dict` — the decrypted plaintext is a JSON object, parsed for you |
| `date`, `date_of_birth` | `datetime.date` (falls back to the raw string if it can't be parsed) |
| `photo`, `document`, `legal_document` | a lazy `BinaryHandle` — see below |

```python
addr = conn.values["home_address"].value     # dict, e.g. {"street": "...", "city": "...", ...}
dob  = conn.values["birthday"].value          # datetime.date(1990, 5, 17)
```

### Binary fields — the lazy `BinaryHandle`

A photo/document value is a `BinaryHandle`. Nothing is fetched or decrypted until
you call `.bytes()` or `.save()`:

```python
handle = conn.values["passport_scan"].value   # BinaryHandle (no network yet)

data = handle.bytes()                          # GET the slot file → decrypt → file bytes
n    = handle.save("/tmp/passport.jpg")        # same, written to disk; returns bytes written
print(handle.value_url)                         # the opaque slot-keyed URL it fetches from
```

`.bytes()` GETs the slot-keyed file endpoint, unwraps the API's
`{"encrypted": true, "value": <wrapper>}` envelope, decrypts with your service
key, parses the inner JSON envelope (`{"full": "data:…"}` for photos,
`{"file": "data:…"}` for documents) and base64-decodes the data URI into the
file bytes. The result is cached on the handle, so repeated calls don't re-fetch.

### `Change(id, event, person_id, slug?, value?, live?, at)`

A change-feed / webhook event.

| Attribute | Meaning |
|-----------|---------|
| `id` | **The stable server change-row id — your dedup key** (captured before the server delete). |
| `event` | `connection_created`, `connection_deleted`, `field_updated`, `field_deleted`, `consent_accepted`, `consent_declined`. |
| `person_id` | The person the change is about (may be `None`). |
| `slug`, `value`, `live` | Present only on `field_updated`; `value` is typed exactly like `Value.value` (incl. a lazy `BinaryHandle` for binaries). Connection/consent events carry no slot/value. |
| `at` | `datetime` of the change. (There is no separate `updated_at` on a change.) |

### `.raw`

Every model carries `.raw` — the underlying *hardened* API dict — for debugging
or an edge case the SDK didn't model. It still never contains the person's source
field.

See [`docs/model.md`](docs/model.md) for the full reference.

---

## The changes pump

The changes feed is a server-side **drain-on-fetch queue**:
`GET /api/company-data/changes?limit=N` returns up to N events (default 100, max
500) **and deletes exactly those rows in the same transaction** — no
offset/cursor, and the API keeps no copy afterward. So consumption can't be a
plain list: a consumer crash mid-batch would lose events the API already deleted,
and a huge backlog must not materialize in memory. `process_changes` solves both.

**Per run, repeating until the feed is empty then returning:**

1. **Replay first.** Deliver any un-acked events already in the local buffer (from a previous crashed run), oldest-first.
2. **Drain.** When the buffer is empty, fetch one batch and **persist it to the durable file buffer (fsync) BEFORE handing anything out.** This is the backup the API no longer has.
3. **Deliver one-by-one.** For each buffered event, oldest-first: decrypt its value *at delivery* (never on disk), build the typed `Change`, call `handler`.
4. **Ack / retry / dead-letter.** On success, remove the event from the buffer (ack). On a handler error, retry with backoff up to `max_retries`; then either move it to the dead-letter store and continue (`on_error="deadletter"`, default — one poison event never wedges the stream) or stop and re-raise (`on_error="halt"`). A `DecryptError` on a buffered event (corrupt/truncated ciphertext, rotated key) is **dead-lettered immediately** — re-decrypting can't fix it, so it does *not* burn retries (under `on_error="halt"` it re-raises). Either way it never propagates out and wedges replay.
5. Repeat until a drain returns empty **and** the buffer is drained → return.

### The durable buffer

* Plain files under `cache_dir` (zero extra dependencies): `pending/` for un-acked events, `deadletter/` for ones that exhausted retries.
* Stored events keep their **ciphertext** value — **no plaintext PII is ever written to disk**. Decryption happens only at delivery.
* Writes are crash-safe (temp file → fsync → atomic rename → dir fsync). Files are named with a monotonic, zero-padded sequence so they replay oldest-first.

### Crash safety, at-least-once, and idempotency

A batch is durably buffered *before* any delivery, and acked per-item only *after*
the handler succeeds. The ack can't be atomic with your side-effects — a crash
between your handler's success and its ack re-delivers that event on the next run.
That makes delivery **at-least-once**, so:

> **Your handler must be idempotent. Dedup on `Change.id`.**

`Change.id` is the stable server change-row id, captured before the server delete,
so it survives crash + replay unchanged.

### No follow mode

`process_changes` returns when the feed empties. **You** schedule re-runs — a
cron job, a `while True: client.process_changes(handle); time.sleep(5)` loop, a
worker queue, whatever fits. The feed is cheap to poll (see
[Rate limits](#rate-limits)).

### Worked example

```python
import time
from allus_company_data import Client

client = Client.from_config("allus.json")

def handle(change):
    # Idempotent: skip anything we've already applied.
    if seen(change.id):
        return
    match change.event:
        case "field_updated":
            store_value(change.person_id, change.slug, change.value, live=change.live)
        case "field_deleted":
            clear_value(change.person_id, change.slug)
        case "connection_deleted":
            drop_person(change.person_id)
        case "connection_created" | "consent_accepted" | "consent_declined":
            note_event(change.person_id, change.event, change.at)
    record_seen(change.id)

# Schedule your own re-runs; process_changes itself returns when empty.
while True:
    client.process_changes(handle, batch_size=200, max_retries=5)
    time.sleep(5)
```

If a handler keeps failing, the event lands in the dead-letter store instead of
blocking the stream; inspect with `client.dead_letters()` and re-drive with
`client.retry_dead_letters(handle)` after fixing the cause. See
[`docs/pump.md`](docs/pump.md).

---

## Webhooks

Webhooks are the lower-latency push alternative to polling the changes feed. The
platform POSTs each change event to your configured webhook URL with:

* `X-Allus-Webhook-Id` — which webhook this is (selects the HMAC secret from config).
* `X-Allus-Signature` — `HMAC-SHA256(rawBody, secret)` as lowercase hex.
* the body — the same slug-keyed `Change` shape as the pull feed (JSON or XML).

All secrets/keys come from config; the helpers take **no key or secret
arguments**. Use the raw request body bytes (do not re-serialize a parsed body —
the HMAC is over the exact bytes the platform sent).

### In a web route (Flask)

```python
from flask import Flask, request, abort
from allus_company_data import Client, WebhookError

app = Flask(__name__)
client = Client.from_config("allus.json")

@app.post("/allus/webhook")
def allus_webhook():
    try:
        change = client.handle_webhook(request.get_data(), dict(request.headers))
    except WebhookError:
        abort(401)              # bad / unknown signature, or unparseable envelope

    # Same idempotency rule as the pump: dedup on change.id.
    if not seen(change.id):
        apply_change(change)
        record_seen(change.id)
    return ("", 204)
```

`verify_webhook` / `parse_webhook` let you split the steps if you prefer:

```python
if not client.verify_webhook(raw_body, headers):
    abort(401)
change = client.parse_webhook(raw_body, headers)
```

### Config-driven secrets

Per-webhook HMAC secrets live in the config `webhooks` map, keyed by webhook id;
the SDK reads `X-Allus-Webhook-Id` off the request and looks up the matching
secret. A single-webhook service can use the flat `"webhook_secret": "…"`
shortcut (or `ALLUS_WEBHOOK_SECRET`). An unknown/unconfigured id ⇒ verification
returns `False` (and `handle_webhook` raises `WebhookError`).

### The `encrypt_payload` account-key envelope

If a webhook has `encrypt_payload` enabled, the body is **replaced** by a
`{"_enc":1,…}` envelope encrypted to your company **account** key (and the HMAC is
over that envelope — the final bytes sent). `parse_webhook`/`handle_webhook`
unwrap it transparently using the configured `account_private_key` +
`account_passphrase`, then decrypt the inner field value with the service key — so
an encrypted-payload `Change` is identical to a plain one. If you receive such a
webhook without an `account_private_key` configured, you get a `WebhookError`.

> The account-key envelope uses OAEP-**SHA1** (OpenSSL's default), distinct from
> the OAEP-SHA256 used for person field values — the SDK handles this difference
> internally; you only supply the account key in config.

See [`docs/webhooks.md`](docs/webhooks.md).

---

## Rate limits

| Endpoint | Limit | Use it for |
|----------|-------|-----------|
| `changes` (the pump) | **generous** | Poll **as often as you like** — it's a cheap drain-on-fetch queue. |
| `request-fields`, `logs` | moderate | Occasional reads. |
| `connections`, `connection(id)`, binary `/file` | **heavily limited** | Initial full sync + occasional reconciliation **only** — never as a poll substitute. |

A 429 carries `Retry-After`. The SDK backs off and retries automatically:

* The transport (`HttpClient`) retries a 429 a bounded number of times honoring `Retry-After`, then surfaces `RateLimitError`.
* The `connections(...)` generator additionally backs off per `Retry-After` on a surfaced `RateLimitError` and retries the page a bounded number of times before re-raising — so it paces itself within the limit instead of hammering.

If you catch a `RateLimitError`, its `.retry_after` is the seconds to wait
(or `None` when the header was absent).

---

## Errors

All from `allus_company_data`. Same taxonomy + names across all six SDKs.

| Error | When |
|-------|------|
| `ConfigError` | Missing/invalid config, unreadable key file, or wrong passphrase — at construction (fail fast). |
| `AuthError` | Token fetch/refresh failed (bad `client_id`/`secret`, revoked client); or a 401 survives the one automatic refresh-and-retry. |
| `ApiError(status, error_key, message)` | Any non-2xx from the API; carries the HTTP `status`, the platform `error_key` (when present), and `message`. |
| `DecryptError` | A ciphertext wrapper is malformed, the key is wrong, or the GCM tag mismatches. Surfaces when a value is accessed/decrypted. |
| `WebhookError` | Signature verification failed, or an envelope couldn't be unwrapped/parsed. |
| `RateLimitError(retry_after)` | A 429 from a rate-limited endpoint. Subclass of `ApiError` (status fixed at 429); carries `retry_after` (seconds, or `None`). |

```python
from allus_company_data import (
    Client, ConfigError, AuthError, ApiError,
    DecryptError, WebhookError, RateLimitError,
)

try:
    client = Client.from_config("allus.json")
    for conn in client.connections():
        ...
except ConfigError as e:
    ...   # fix the config / key file
except RateLimitError as e:
    wait(e.retry_after or 60)
except ApiError as e:
    log(e.status, e.error_key, e.message)
```

See [`docs/errors.md`](docs/errors.md).

---

## How it's wired

Everything below is what the SDK hides so your code only ever sees conclusions.

**Auth / token.** An `HttpClient` owns a `client_credentials`-only token. On the
first call (or when the cached token nears expiry) it POSTs
`client_id`/`client_secret` to `{api_url}/oauth2/token` and caches the bearer
token + its expiry; refresh is automatic. A mid-flight 401 triggers exactly one
refresh-and-retry, then `AuthError`. The token is scoped server-side to **one**
service, so every call is implicitly that service's data.

**Slug resolution.** `request_fields()` is fetched once and cached; its slug→type
map types every value (so `address` parses to a dict, `photo` becomes a lazy
binary handle, etc.). The connection/changes endpoints return values keyed by
**your** request slug — the person's source field is dropped server-side and
never reaches the SDK.

**Decryption (zero-knowledge).** The service private key is loaded **once** at
construction from the configured encrypted PEM + passphrase into an in-memory RSA
key. A `decrypt` closure over it is handed to every model factory and the pump —
the key never appears in a method signature. Each value is a hybrid wrapper
(`{"_enc":1,"k":rsa_oaep_sha256(aesKey),"iv":…,"d":aes256gcm(…)}`); the SDK
RSA-OAEP-SHA256 unwraps the AES key, then AES-256-GCM decrypts the payload. **The
platform only ever holds ciphertext — it never sees your plaintext.**

**Binary fetch.** A binary value is a lazy `BinaryHandle` over a slot-keyed
`value_url`. On `.bytes()`/`.save()` it GETs that file endpoint, unwraps the
`{"encrypted":true,"value":<wrapper>}` envelope, runs the same service-key
decrypt to a JSON file-envelope, and base64-decodes its data URI to the file
bytes. (Slot-keyed, never source-field-keyed.)

**The drain-on-fetch feed.** `process_changes` delegates to a `Pump` wired to a
`fetch_changes` closure (`GET /changes?limit=`, returning raw ciphertext events)
and a `decrypt` closure (builds a typed `Change`). Because the fetch deletes the
rows it returns, the pump persists each batch to the durable file buffer
(ciphertext at rest) before delivery, acks per-item after your handler succeeds,
and replays the buffer on restart — see [The changes pump](#the-changes-pump).
```
