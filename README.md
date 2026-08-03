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
[Company documents](#company-documents) ·
[Contract-flow runs](#contract-flow-runs-company-side) ·
[Rate limits](#rate-limits) · [Errors](#errors) · [How it's wired](#how-its-wired)

Deeper reference pages live in [`docs/`](docs/):
[config](docs/config.md) · [model](docs/model.md) · [pump](docs/pump.md) ·
[webhooks](docs/webhooks.md) · [errors](docs/errors.md).

---

## TL;DR — fetch new updates

A system/Homebrew Python refuses a bare `pip install` (PEP 668) — install into a
virtualenv:

```bash
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
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

Requires **Python ≥ 3.11**. A system/Homebrew Python refuses a bare `pip install`
(PEP 668) — install into a virtualenv:

```bash
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install allus-company-data
# or, working from a clone:    pip install -e '.[dev]'      # from the repo root
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

### Key rotation — `key_rotated` and the public-key cache

Every client caches the RSA public keys it fetches: a person's key is immutable — until they
**rotate** it. A person learns of a rotation from a silent push; your service gets no pushes, so the
`key_rotated` change is your **only** signal. Without it a long-running worker keeps encrypting to
the rotated-away key for its whole lifetime, and the person can never read those values.

**On the pump this is automatic** — the cached key is dropped as the change passes through, before
your handler sees it. **Over a webhook it is not:** the signature verifier is static and has no
client instance, so it cannot reach the cache. Call the invalidator yourself — noting that the two
clients key their caches **differently**: the service client by `share_code`, the customer client by
the person's **user id**. Passing a share code to the customer client removes nothing and leaves you
encrypting to the old key. Both identifiers ride every change, alongside `public_key_sha256` — the
fingerprint of the person's new key.

```python
if change.event == "key_rotated":
    client.invalidate_public_key(change.share_code)      # service Client — keyed by SHARE CODE
    customer.invalidate_public_key(change.person_id)     # CustomerClient — keyed by PERSON USER ID
    # change.public_key_sha256 = fingerprint of the NEW key, if you want to verify the refetch
```

This is **eventual, not fail-closed** — nothing rejects a document encrypted to a stale key, so a
window remains between the rotation and your next drain. Drain often if that window matters.

### `service_key_rotated` — the same thing, the other way round

The customer client also caches the **service's** public key, the one you encrypt your consent
answers and documents *to*, keyed `"companyCode/serviceCode"`. When that company replaces its
service keypair, the `service_key_rotated` change on your account feed is your only signal — you
receive no pushes. Same shape, same guarantees, same automatic handling on the pump:

```python
if change.event == "service_key_rotated":
    # Automatic on the pump. Over a webhook, from the raw event body:
    customer.invalidate_service_key(body["company_share_code"], body["service_share_code"])
    # body["service_public_key_sha256"] = fingerprint of the service's NEW key
```

Also **eventual, not fail-closed**. Note the identifiers are **share codes**, not the ids used by
`invalidate_public_key` — the two caches are keyed differently and the wrong call removes nothing.

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
Change       { id, event, person_id, slug?, value?, live?, document_id?, status?, at }
Document     { id, kind, name, description, status, payload_kind, is_private, value, metadata, created_at, updated_at }
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
| `email`, `phone`, `url`, `text` | `str` — `phone` is a single E.164-style string (`+` and digits) |
| `country`, `nationality` | `str` — an ISO 3166-1 alpha-2 code (e.g. `"US"`, `"NL"`); not a display name |
| `address`, `bank`, `creditcard` | `dict` — the decrypted plaintext is a JSON object, parsed for you |
| `date`, `date_of_birth` | `datetime.date` (falls back to the raw string if it can't be parsed) |
| `photo`, `document`, `legal_document` | a lazy `BinaryHandle` — see below |

`country`/`nationality` values are 2-letter ISO codes, and an `address`'s
`country`/`state` sub-fields are an ISO alpha-2 code / USPS 2-letter state code
respectively. `is_field_value_valid(type, value)` validates these against the
bundled country dataset; `is_valid_country_code(code)` / `dial_code_for(code)`
check a code or look up its E.164 dial code.

```python
addr = conn.values["home_address"].value     # dict, e.g. {"street": "...", "city": "...", ...}
dob  = conn.values["birthday"].value          # datetime.date(1990, 5, 17)
```

### Binary fields — the lazy `BinaryHandle`

A photo/document value is a `BinaryHandle`. Nothing is fetched or decrypted until
you call `.bytes()` or `.save()`:

```python
handle = conn.values["passport_scan"].value   # BinaryHandle (no network yet)

data = handle.bytes()                          # GET the slot file → the file bytes
n    = handle.save("/tmp/passport.jpg")        # same, written to disk; returns bytes written
print(handle.value_url)                         # the opaque slot-keyed URL it fetches from
print(handle.content_type)                      # what the bytes arrived as, once fetched
print(handle.content_sha256)                    # the platform's digest of exactly those bytes
```

`.bytes()` GETs the slot-keyed file endpoint and returns the file bytes — but that
endpoint has **two 200 shapes, and which one you get is the person's choice, not
yours**. It depends on whether their source field is private, they can change that
at any time, and nothing announces it in advance:

* **private source** → `application/json`, `{"encrypted": true, "value": <wrapper>}`.
  The handle decrypts the wrapper with your service key, parses the inner JSON
  envelope (`{"full": "data:…"}` for photos, `{"file": "data:…"}` for documents) and
  base64-decodes the data URI into the file bytes.
* **plaintext source** → the file's own `Content-Type` (`image/jpeg`,
  `application/pdf`, …) and the body IS the file. Nothing is decrypted and no service
  key is needed.

The handle hides the difference: `.bytes()`/`.save()` give you the file either way.
The shapes are told apart on the response `Content-Type`, never by looking at the
body — a PDF that happened to start with a brace must not be mistaken for a wrapper.
The result is cached on the handle, so repeated calls don't re-fetch.

Every 200 carries `X-Allus-Content-Sha256`, the sha256 of exactly the bytes returned;
`handle.content_sha256` is that header (and `handle.content_type` the Content-Type),
so you can record what you received and later show your archived copy has not
drifted. It is the platform's word, not a signature. There is no variant selection —
one slot has one byte sequence and therefore one digest.

A frozen (share-once) answer is retained for 90 days. After that the endpoint returns
**410 `company_data.file_expired`**, which surfaces as an `ApiError` whose `details`
carry the answer's `content_sha256` and `expired_at` — your archived copy is then the
only one, and you can still prove what it is:

```python
try:
    data = handle.bytes()
except ApiError as e:
    if e.error_key == "company_data.file_expired":
        log(e.details["content_sha256"], e.details["expired_at"])
```

### `Change(id, event, person_id, slug?, value?, live?, at)`

A change-feed / webhook event.

| Attribute | Meaning |
|-----------|---------|
| `id` | **The stable server change-row id — your dedup key** (captured before the server delete). |
| `event` | `connection_created`, `connection_deleted`, `field_updated`, `field_deleted`, `consent_accepted`, `consent_declined`, `document_status_changed`. |
| `person_id` | The person the change is about (may be `None`). |
| `slug`, `value`, `live` | Present only on `field_updated`; `value` is typed exactly like `Value.value` (incl. a lazy `BinaryHandle` for binaries). Connection/consent/document events carry no slot/value. |
| `document_id`, `status` | Present only on `document_status_changed` — which document moved lifecycle state and to what (no slug/value). See [Company documents](#company-documents). |
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

### Delivery contract — effectively unique, rarely replayed

Each queued event is POSTed **once**, and **only HTTP `200` counts as delivered** — a
`202`, a `204`, a 3xx redirect and every 4xx/5xx are all treated as a failure. On anything
other than `200` (or a timeout or connection error) the event is **not retried in place**:
it and the rest of the webhook's queue move to a durable server-side backlog and the
webhook is marked bad. The backlog is delivered later, either automatically when
the webhook next probes healthy, or when you drain it yourself with
`GET /api/company-data/changes?webhook_id=…` (delete-on-read).

So deliveries are **effectively unique** — with one rare exception. If your endpoint
processed an event but the platform never saw your `200` (your response timed out, or
you crashed after committing but before responding), the event is treated as failed
and replayed on recovery, so you receive it **again**. Nothing caps that at two: a
failed probe leaves its backlog row in place, so every later recovery attempt whose
`200` is likewise lost replays the same event once more. Inside that window the
contract is **at-least-once** — plan for one or more repeats, not for exactly one.

> **Do not use `change.id` as an idempotency key here.** On the webhook path the id is
> neither reliably stable nor reliably fresh, and a receiver cannot tell which one it is
> holding. A **live** delivery is built with no change row behind it, so its id is minted
> for that single POST — the later replay of the same event is rebuilt from a durable
> backlog row and therefore carries a **different** id. But a replayed delivery carries
> **that row's** id, and the row stays in place until it is delivered successfully, so a
> re-attempted replay arrives with the **same** id — which changes again if the event is
> re-backlogged after a further failure. An id check therefore misses the duplicate you
> are most likely to see and matches only a rarer one; it is not a contract. If you need
> strict idempotency, key on the **content** — event + person + slug/document + payload —
> never on the id.

**Webhooks and the pull feed are alternative integrations — consume one, never both.**
The id-dedup guidance in the changes-pump section above applies to the pump only, where
`change.id` is the real server change-row id.


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

    # Do NOT carry the pump's id-dedup over here: the webhook id is not an
    # idempotency key (see "Delivery contract" above). Key on content if you need one.
    apply_change(change)
    return ("", 200)   # 200 — the ONLY status allus counts as delivered
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

## Company documents

Documents are content **your service issues to people** (a quote, a contract, a
JSON payload, a PDF) — the mirror image of the request slots. They come in two
shapes:

* **Broadcast** — no target. Sent to **every** connection on the service.
  **Plaintext** — you can't single-key-encrypt one value to all your
  connections, so a broadcast value is stored as-is.
* **Per-person** — targeted at one connection (`connection_id=` /
  `person_user_id=` / `share_code=`). **Automatically end-to-end encrypted to
  that recipient's public key** before it leaves the process. The server only
  ever stores ciphertext.

> **The encryption rule, plainly:** every **per-person** document is
> automatically end-to-end encrypted to the recipient's public key — for **any**
> `is_private` value. **Broadcast** documents are plaintext. `is_private` is a
> **device-display-only** flag (it picks lock-screen vs decrypt-on-load on the
> recipient's device), *not* what decides encryption — so `is_private=True` with
> **no** per-person target raises `ConfigError`. As everywhere in this SDK, **no
> method ever takes a key or secret argument** — the recipient key is fetched for
> you, and your own service key comes from config.

### Creating documents

`payload_kind` picks the body:

* `payload_kind="json"` — pass `json_value=` (a JSON-serializable object).
* `payload_kind="file"` — pass `file_bytes=` (`+ file_mime=`); the bytes are
  uploaded. For a **per-person** file the bytes are encrypted automatically too.

```python
from allus_company_data import Client

client = Client.from_config("allus.json")

# 1. BROADCAST plaintext json doc — every connection sees it, no target.
notice = client.create_document(
    kind="document",
    name="2026 price list",
    payload_kind="json",
    json_value={"plan": "pro", "monthly": 49, "currency": "EUR"},
)

# 2. PER-PERSON doc — auto-encrypted to that recipient's public key.
#    Target it by ANY one of connection_id / person_user_id / share_code.
contract = client.create_document(
    kind="document",
    name="Service agreement",
    payload_kind="json",
    is_private=True,                       # display-only; needs a per-person target
    connection_id="019xxxxxxxxxxxxxxxxxxxxxxxxx",
    json_value={"tier": "enterprise", "term_months": 12},
)

# A per-person FILE — the bytes are encrypted for the recipient automatically.
with open("agreement.pdf", "rb") as fh:
    pdf = client.create_document(
        kind="legal_document",
        name="Signed agreement",
        payload_kind="file",
        person_user_id="019yyyyyyyyyyyyyyyyyyyyyyyyy",
        file_bytes=fh.read(),
        file_mime="application/pdf",
    )

# is_private without a target → ConfigError (a broadcast can't be locked).
```

### Listing, reading, updating, deleting

```python
list_documents(*, person_user_id=None, status=None, limit=100, offset=0) -> list[Document]
document(document_id)                                                     -> Document
document_file(document_id)                                                -> bytes    # #491: the file BYTES
flow_run_document(run_id)                                                 -> bytes    # #491: the run's OWN (service-key) copy
update_document_status(document_id, status)                              -> Document
update_document_metadata(document_id, *, metadata=None, name=None,
                         description=None)                               -> Document
delete_document(document_id)                                            -> None
```

```python
# All this service's documents (optionally filter by person and/or status).
for doc in client.list_documents(status="offering"):
    print(doc.id, doc.name, doc.status, doc.payload_kind, "private" if doc.is_private else "shared")

doc = client.document(contract.id)

# For a json doc, .json() returns the plaintext object — a per-person doc is
# decrypted with your service key on demand; a broadcast doc is already plaintext.
print(doc.json())

# #491: download a FILE document's bytes (metadata methods don't include them).
# A BROADCAST document is served plaintext and is returned as-is. A PER-PERSON /
# private document is encrypted to the RECIPIENT's key — the company cannot
# decrypt that, so this raises ApiError('documents.recipient_encrypted') instead
# of a doomed decrypt attempt.
try:
    pdf_bytes = client.document_file(contract.id)
except ApiError as e:
    if e.error_key == "documents.recipient_encrypted":
        # This is a per-person document; only the recipient can read it. For a
        # generated flow contract, download the company's OWN copy instead:
        pdf_bytes = client.flow_run_document(run.id)
    else:
        raise

# Move it through its lifecycle / edit its metadata.
client.update_document_status(contract.id, "active")
client.update_document_metadata(contract.id, name="Service agreement (v2)",
                                metadata={"renewal": "auto"})

client.delete_document(notice.id)
```

A `Document` carries `id, kind, name, description, status, payload_kind,
is_private, value, metadata, created_at, updated_at` (and `.raw`). Use `.json()`
on a `payload_kind="json"` document to get the decrypted plaintext object.

### Reacting to a status change in the feed

When someone advances one of your documents (e.g. signs it), the platform emits a
**`document_status_changed`** change. In a `process_changes` handler it carries
`.document_id` and `.status` (and **no** `slug`/`value` — it's a lifecycle event,
not a field value):

```python
def handle(change):
    if change.event == "document_status_changed":
        # the document moved lifecycle state (offering → ready_to_sign → active → …)
        on_document_status(change.document_id, change.status)
    elif change.event == "field_updated":
        store(change.person_id, change.slug, change.value)

client.process_changes(handle)
```

---

## Contract-flow runs (company side)

The company is one bound **party** of a contract flow — a multi-step, per-party
form the platform walks to gather (and end-to-end encrypt) answers, optionally
finishing at a document-generating leaf. These calls cover the company's turn:

```python
trigger_flow_run(flow_id, *, connection_id, bindings)      -> FlowRun
flow_runs(*, status="awaiting_company")                    -> list[FlowRun]
flow_run(run_id)                                            -> FlowRun
flow_run_answers(run)                                        -> dict[str, str]  # #491 gap 1
submit_flow_answers(run, fill, *, party_pubkeys=None)       -> FlowRun
generate_flow_document(run)                                  -> dict
process_flow_run(run_id, fill_node, *, party_pubkeys=None)  -> FlowRun
identity()                                                    -> dict           # #491 gap 3
```

* `trigger_flow_run(flow_id, connection_id=..., bindings={...})` starts a run bound to a connection and the flow's other parties, pinning the flow's latest **published** version.
* `flow_runs(status=...)` / `flow_run(run_id)` list / fetch runs. `status=None` returns everything; the default `"awaiting_company"` is the actionable queue.
* `flow_run_answers(run)` (#491 gap 1) — a run's **decrypted** answers as `{slug: plaintext}`, reading the company's service-key answer copies. Accepts a loaded `FlowRun` or a run id (fetched via `flow_run`).
* `submit_flow_answers` / `generate_flow_document` / `process_flow_run` fill the company's current node, advance the run (encrypting one answer copy per bound party), and — at a document-mode leaf — generate the contract. See the method docstrings for the full per-party encryption details.
* `identity()` (#491 gap 3) — this client's own `{"company_user_id": ..., "service_id": ...}` from `GET /api/company-data/whoami`. `trigger_flow_run`'s company-side binding must use `company_user_id` (the person party's user_id comes from the connection) — without this call it was unconstructible through the SDK.

```python
me = client.identity()
run = client.trigger_flow_run(
    flow_id, connection_id=conn.id,
    bindings={"company": me["company_user_id"], "person": conn.person_id},
)

# Later, once the run is complete:
answers = client.flow_run_answers(run.id)     # {slug: plaintext} — the company's copies

# If the flow's output_mode is "document", download the company's OWN generated
# copy (encrypted to the SERVICE key, unlike a per-person document_file()):
pdf_bytes = client.flow_run_document(run.id)  # see Company documents above
```

* **Raises:** `AuthError`, `ApiError` (404 on `flow_run`/`flow_run_document` for an unknown run, or one with no generated document yet), `DecryptError`, `RateLimitError`, `ValidationError` (from `submit_flow_answers` on a slug failing field-type validation).

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

Your `client_credentials` token requests (`/oauth2/token`) are on their own rate-limit bucket,
separate from person logins — but it is keyed by **source IP, not by your `client_id`**, so it is
shared with every other `client_credentials` caller reaching the API from the same address (another
service on your network, a second client on the same host). Caching the token, as described under
**How it's wired** below, is what keeps that shared window from being spent needlessly — by you or
anyone else behind the same IP. Every rate-limit refusal — this 429, and the platform's 503 when its
own limiter store is unreadable — now carries a populated `.error_key`, readable off the same
`RateLimitError`/`ApiError`.

---

## Errors

All from `allus_company_data`. Same taxonomy + names across all six SDKs.

| Error | When |
|-------|------|
| `ConfigError` | Missing/invalid config, unreadable key file, or wrong passphrase — at construction (fail fast). |
| `AuthError` | Token fetch/refresh failed (bad `client_id`/`secret`, revoked client); or a 401 survives the one automatic refresh-and-retry. |
| `ApiError(status, error_key, message, details)` | Any non-2xx from the API; carries the HTTP `status`, the platform `error_key` (when present), `message`, and `details` — the error body's remaining fields (e.g. a 410 `company_data.file_expired`'s `content_sha256` + `expired_at`). |
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
`value_url`. On `.bytes()`/`.save()` it GETs that file endpoint and classifies the
response on its `Content-Type`: an encrypted answer (`{"encrypted":true,"value":…}`)
runs the same service-key decrypt to a JSON file-envelope and base64-decodes its data
URI, while a plaintext answer's body already IS the file. Either way you get the file
bytes, plus the response's `X-Allus-Content-Sha256` on `.content_sha256`.
(Slot-keyed, never source-field-keyed.)

**The drain-on-fetch feed.** `process_changes` delegates to a `Pump` wired to a
`fetch_changes` closure (`GET /changes?limit=`, returning raw ciphertext events)
and a `decrypt` closure (builds a typed `Change`). Because the fetch deletes the
rows it returns, the pump persists each batch to the durable file buffer
(ciphertext at rest) before delivery, acks per-item after your handler succeeds,
and replays the buffer on restart — see [The changes pump](#the-changes-pump).

## Sign in with allme (OAuth, #195)

Relying-party helper for the "Sign in with allme" identity flow. Config-only keys (the idw role):

```python
from allus_company_data import OAuthClient, Claim

oauth = OAuthClient.from_config("idw-config.json")  # {api_url, oauth_client_id, oauth_redirect_uri, oauth_client_secret?, oauth_private_key?, oauth_key_passphrase?}
url = oauth.authorize_url("signin", state="xyz", code_challenge=challenge)   # the button target
# ...user approves; your redirect_uri receives ?code=...
info = oauth.complete_sign_in(code, code_verifier=verifier)  # {user, mode, values(plaintext), values_cipher}
```

Modes: `signin` (identity), `one_time` (frozen claim values, decrypted for you), `connect` (a lasting connection),
`2fa_enroll` (opt a person into 2FA — see below).
`authorize_url(mode, claims=[Claim("email", "email", suggest="email_personal")])`; `poll_result(state)` for the detached response mode.

**#498 — a claim IS a request field.** You describe what you need and the **person** picks which of their
own fields answers it; you never name a field. A claim carries a mandatory unique `name` (everything
that comes back is keyed by it — `values`, `values_cipher`, `attestations`, and their stored choice for a
repeat login), a field `type`, an optional `suggest`ed slug, `required`, and `verified` ("only a
#311-verified answer will do"). A nameless or duplicate claim raises `ConfigError` at the call rather than
failing at the API. `verified` is accepted only on the OIDC flow and only for a type allme can verify
(today `email`); elsewhere it is refused with `invalid_request` rather than quietly dropped.

`complete_sign_in` returns `{user, mode, two_factor, values, values_cipher, attestations}`.
* `user.sub` **is** the person's share code and equals `share_code` — byte-identical to the id_token's
  `sub`. `display_name` is gone: ask for a `name` claim and read `values["name"]`.
* `values_cipher` is an additive sibling of `values`, keyed the same way: the raw app-key ciphertext
  wrapper each plaintext value was decrypted from, exactly as `userinfo` delivered it. Lets you show that
  a value really came from encrypted delivery rather than trusting it verbatim. Empty for a mode/claim
  that carries no ciphertext (`signin`, or `plaintext` delivery) — that emptiness is the honest answer.
* `attestations` is an additive sibling map keyed by the same claim name, present only for a `verified`
  claim under encrypted delivery. Each entry carries a `verified` boolean **the SDK computes itself**,
  in constant time, over the plaintext it just decrypted — plus the raw `hash`/`salt`/`verifiedAt`.
  **A slug ABSENT from the map is "not attested", never "wrong"** (treat that value as unverified);
  **an entry present with `verified` false is a MISMATCH and you must reject the value.** `verifiedAt`
  attests the value as verified *at that moment*, not verified today.


## 2FA by allme (#436, #481)

Ask a connected person to approve a login inside the allme app. On the same service data client (no new
config), via the `two_factor` sub-client:

```python
from allus_company_data import Client

client = Client.from_config("allus.json")

# Raise a challenge. idempotency_key is REQUIRED — a repeat within the TTL returns the SAME challenge and
# sends no second push. `context` is plain text shown on the person's card.
ch = client.two_factor.challenge("2I6UF3", idempotency_key="login-8f3c1a", context="Sign-in from Chrome")
if ch.matching_digits:                        # number matching is on for this service
    show_on_login_page(ch.matching_digits)    # the person types these back into the app; the server checks them

# Wait for the terminal outcome — polls result() for you, raises ApiError on timeout.
res = client.two_factor.wait_for_result(ch.challenge_id)   # or result(ch.challenge_id) to poll once yourself
if res.status == "approved":
    grant_login()
```

- **Burn-on-read.** The first read of a terminal state (`approved` | `denied` | `expired` | `revoked`)
  delivers it and burns it — a later read is `gone`. Read it once and persist your own outcome;
  `wait_for_result` returns that first terminal read and never re-reads a consumed challenge.
- **Webhook variant.** The `2fa_challenge_completed` change/webhook carries the same terminal `status`, so a
  webhook consumer need not poll. **Expiry fires no webhook/Change** — only `approved`/`denied`/`revoked`
  reach the feed, so a lapsed challenge is observable only by polling.
- **Enrollment.** Only an enrolled person can be challenged (an un-enrolled `share_code` is `404`).
  Enrollment is a one-time consent on the `web.allme.fyi/auth` surface via the OAuth helper's `2fa_enroll`
  mode — a redirect button (`oauth.authorize_url("2fa_enroll", state=...)`), or server-to-server with
  `response_mode="detached"` + `poll_result(state)`, which returns `{"enrolled": true, "state": ...}` once
  the person confirms.
- **Errors.** `404` (unknown / not-enrolled share code). A `429` is either the plain rate limit (retried with
  backoff → `RateLimitError`) or `twofa.pending_cap` (too many challenges already open for this person) — the
  latter surfaces immediately as `ApiError` and is never retried, since a retry cannot clear it.
