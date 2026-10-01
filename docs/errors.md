# Error model

Same taxonomy + names across all six SDKs. All importable from
`allus_company_data`.

```python
from allus_company_data import (
    ConfigError, AuthError, ApiError, DecryptError, WebhookError, RateLimitError,
)
```

| Error | Raised when |
|-------|-------------|
| `ConfigError` | Missing/invalid config, an unreadable key file, or a wrong passphrase — at construction (fail fast). |
| `AuthError` | The `client_credentials` token fetch/refresh failed (bad `client_id`/`secret`, revoked client); or a mid-flight 401 survived the one automatic refresh-and-retry. |
| `ApiError(status, error_key, message, details)` | Any non-2xx from the API. |
| `DecryptError` | A ciphertext wrapper is malformed, the key is wrong, or the GCM tag mismatches. |
| `WebhookError` | Signature verification failed, or a webhook envelope couldn't be unwrapped/parsed. |
| `RateLimitError(retry_after)` | A 429 from a rate-limited endpoint. Subclass of `ApiError`. |

## `ApiError`

```python
class ApiError(Exception):
    status: int                # the HTTP status
    error_key: Optional[str]   # the platform error_key, when the body provided one
    message: Optional[str]     # a human-readable message
    details: dict              # the error body's remaining fields, verbatim
```

`str(err)` is `"HTTP <status> (<error_key>): <message>"`. A transport failure
(no HTTP response — e.g. a connection error) surfaces as `ApiError(0, None, …)`.

`details` carries whatever the body sent beside the key and the message — no
error needs its own exception type to be readable. The one that uses it today is
the binary file endpoint's **410 `company_data.file_expired`** (a frozen answer's
90-day retention has elapsed), which sends the answer's `content_sha256` and
`expired_at`:

```python
except ApiError as e:
    if e.error_key == "company_data.file_expired":
        archive_note(e.details["content_sha256"], e.details["expired_at"])
```

A **421 `region.rebase_required`** never reaches you when the platform is reachable: it is the global front door telling the SDK to send the call to the caller's home region, which the SDK does automatically (README, **How it's wired** → Regions). It surfaces as `ApiError` only when the base the refusal names is absent or empty — in which case no base was stored and no retry was made.

## 503 `db.writes_paused` — saving is paused, retry

While the platform cannot complete a save in every region, a call can answer
**503** with `error_key` **`db.writes_paused`** (`"Saving data is not possible
right now"`) and the header `Retry-After: 30`. **Nothing was written**, so the call
is safe to repeat exactly as it was. Reads keep working.

It surfaces as a plain `ApiError` (`status == 503`, `error_key ==
"db.writes_paused"`); the SDK does not retry it. `ApiError` does not carry the
`Retry-After` header: wait 30 seconds, then repeat the same call.

Where it can come from:

* every company-data and customer call that is not a GET — creating, updating or
  deleting documents, flow-run starts, answers, uploads and generation, consent
  answers, connect requests, messages, 2FA challenges, `/api/keys/batch`;
* the change-feed drains `GET /api/company-data/changes` and
  `GET /api/customer/changes` (`process_changes`, `drain_batch`): nothing was
  drained, the events stay queued on the server and arrive on a later run, and the
  local buffer is untouched;
* `OAuthClient.poll_result` (`POST /oauth2/result`): the result is not consumed;
  poll again.

The token request (`POST /oauth2/token`) does not answer it: token grants keep
working while saving is paused.

```python
except ApiError as e:
    if e.status == 503 and e.error_key == "db.writes_paused":
        time.sleep(30)
        ...  # repeat the same call
```

## 503 `platform.out_of_order` — the platform is out of order, retry

While the region serving a call is being rebuilt, the call answers **503** with
`error_key` **`platform.out_of_order`** (`"allme is temporarily out of order.
Please try again later."`) and the header `Retry-After: 300`. **The request was
not processed**, so the call is safe to repeat exactly as it was. The platform
answers normally again once the region is back in service.

It surfaces as a plain `ApiError` (`status == 503`, `error_key ==
"platform.out_of_order"`); the SDK does not retry it. `ApiError` does not carry the
`Retry-After` header: wait 300 seconds, then repeat the same call.

Where it can come from:

* every company-data and customer call, reads included — connections, request
  fields, binary fetches, documents, flow runs, consent answers, connect requests,
  messages, 2FA challenges and results, `/api/keys`;
* the change-feed drains `GET /api/company-data/changes` and
  `GET /api/customer/changes` (`process_changes`, `drain_batch`): nothing was
  drained, the events stay queued on the server and arrive on a later run, and the
  local buffer is untouched;
* every `OAuthClient` call — `exchange_code`, `userinfo`, `poll_result` (the
  result is not consumed; poll again).

The `client_credentials` token request (`POST /oauth2/token`) the service and
customer clients make does not answer it, so the SDK still holds a token and the
503 arrives on the call itself. Every other grant at `POST /oauth2/token` — the
`OAuthClient` code exchange, a refresh-token grant — answers it.

```python
except ApiError as e:
    if e.status == 503 and e.error_key == "platform.out_of_order":
        time.sleep(300)
        ...  # repeat the same call
```

## `RateLimitError`

```python
class RateLimitError(ApiError):   # status is always 429
    retry_after: Optional[float]  # seconds from the Retry-After header, or None
```

The SDK already retries a 429 with backoff before surfacing this:

* the transport (`HttpClient`) retries a bounded number of times honoring `Retry-After`;
* the `connections(...)` generator additionally backs off + retries a page a bounded number of times.

For the heavily-limited connections endpoints it surfaces after that backoff so
you don't accidentally hammer them; on the changes feed it auto-backs-off within
reason. If you catch it, wait `err.retry_after` (or a default) before retrying.

## Where each surfaces

| Layer | Common errors |
|-------|---------------|
| `Client.from_config` / `from_env` | `ConfigError` |
| Token / any call (auth) | `AuthError` |
| `connections`, `connection`, `request_fields`, `logs`, pump drains | `ApiError`, `RateLimitError` |
| Value access / `BinaryHandle.bytes()` / pump delivery | `DecryptError` |
| `verify_webhook` / `parse_webhook` / `handle_webhook` | `WebhookError` (`verify_webhook` returns `False` rather than raising on a bad signature) |

## Example

```python
from allus_company_data import (
    Client, ConfigError, AuthError, ApiError,
    DecryptError, WebhookError, RateLimitError,
)

try:
    client = Client.from_config("allus.json")
    for conn in client.connections():
        process(conn)
except ConfigError:
    ...            # fix the config / key file
except AuthError:
    ...            # bad/revoked credentials
except RateLimitError as e:
    sleep(e.retry_after or 60)
except DecryptError:
    ...            # wrong service key or corrupt data
except ApiError as e:
    log(e.status, e.error_key, e.message)
```
