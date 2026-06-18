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
| `ApiError(status, error_key, message)` | Any non-2xx from the API. |
| `DecryptError` | A ciphertext wrapper is malformed, the key is wrong, or the GCM tag mismatches. |
| `WebhookError` | Signature verification failed, or a webhook envelope couldn't be unwrapped/parsed. |
| `RateLimitError(retry_after)` | A 429 from a rate-limited endpoint. Subclass of `ApiError`. |

## `ApiError`

```python
class ApiError(Exception):
    status: int                # the HTTP status
    error_key: Optional[str]   # the platform error_key, when the body provided one
    message: Optional[str]     # a human-readable message
```

`str(err)` is `"HTTP <status> (<error_key>): <message>"`. A transport failure
(no HTTP response — e.g. a connection error) surfaces as `ApiError(0, None, …)`.

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
