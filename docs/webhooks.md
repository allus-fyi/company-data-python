# Webhook receiver helpers

The lower-latency push alternative to polling the changes feed. The platform POSTs
each change event to your configured webhook URL with:

* `X-Allus-Webhook-Id` — which webhook this is (selects the HMAC secret from config).
* `X-Allus-Signature` — `HMAC-SHA256(rawBody, secret)` as lowercase hex.
* the body — the same slug-keyed `Change` shape as the pull feed (JSON or XML). If `encrypt_payload` is on, the body is replaced by a `{"_enc":1,…}` envelope encrypted to the company **account** key (and the HMAC is over that envelope).

**All secrets/keys come from config — these helpers take NO key or secret
arguments.** Always pass the **raw request body bytes** (don't re-serialize a
parsed body; the HMAC is over the exact bytes sent).

## Client methods (the usual form)

```python
client.verify_webhook(raw_body: bytes, headers: dict) -> bool
client.parse_webhook(raw_body: bytes, headers: dict)  -> Change
client.handle_webhook(raw_body: bytes, headers: dict) -> Change   # verify + parse
```

| Method | Returns | Errors |
|--------|---------|--------|
| `verify_webhook` | `bool` — recomputes `HMAC-SHA256(raw_body, secret)` and constant-time-compares to `X-Allus-Signature`. `False` on missing signature / unknown id / mismatch. | **Never raises** for a bad signature. |
| `parse_webhook` | a typed `Change`. Does **not** verify. Handles JSON, XML, and the `encrypt_payload` account-key envelope. | `WebhookError` on a malformed/unparseable body or envelope. |
| `handle_webhook` | a typed `Change` — verify **then** parse. | `WebhookError` on a bad/unknown signature, or any `parse_webhook` error. |

## Standalone functions

The same three are importable as module functions. They take the `config` and the
decrypt/type closures explicitly — used by `Client` internally; you'll normally
use the client methods inside an app.

```python
from allus_company_data import verify_webhook, parse_webhook, handle_webhook

verify_webhook(raw_body, headers, config) -> bool
parse_webhook(raw_body, headers, config, *, type_for_slug, decrypt_value, binary_fetch=None) -> Change
handle_webhook(raw_body, headers, config, *, type_for_slug, decrypt_value, binary_fetch=None) -> Change
```

## In a web route

### Flask

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
        abort(401)
    if not seen(change.id):          # idempotency — same rule as the pump
        apply_change(change)
        record_seen(change.id)
    return ("", 204)
```

### FastAPI

```python
from fastapi import FastAPI, Request, Response, HTTPException
from allus_company_data import Client, WebhookError

app = FastAPI()
client = Client.from_config("allus.json")

@app.post("/allus/webhook")
async def allus_webhook(request: Request):
    raw = await request.body()
    try:
        change = client.handle_webhook(raw, dict(request.headers))
    except WebhookError:
        raise HTTPException(status_code=401)
    if not seen(change.id):
        apply_change(change)
        record_seen(change.id)
    return Response(status_code=204)
```

Split the steps if you prefer:

```python
if not client.verify_webhook(raw_body, headers):
    abort(401)
change = client.parse_webhook(raw_body, headers)
```

## Config-driven secrets

Per-webhook HMAC secrets live in the config `webhooks` map, keyed by webhook id;
the SDK reads `X-Allus-Webhook-Id` and looks up the matching secret. A
single-webhook service can use the flat `"webhook_secret": "…"` shortcut (or
`ALLUS_WEBHOOK_SECRET`). An unknown/unconfigured id ⇒ `verify_webhook` returns
`False` (and `handle_webhook` raises `WebhookError`).

## The `encrypt_payload` account-key envelope

If a webhook has `encrypt_payload` enabled, the whole body is a `{"_enc":1,…}`
envelope encrypted to your company **account** key, and the HMAC is over that
envelope. `parse_webhook`/`handle_webhook`:

1. Unwrap the envelope with the configured `account_private_key` + `account_passphrase`.
2. Parse the inner payload (JSON or XML per `format`).
3. Decrypt the inner field `value` (a service-key wrapper) with the service key.

So an `encrypt_payload` `Change` is identical to a plain one. Receiving such a
webhook without an `account_private_key` configured raises `WebhookError`.

> The envelope uses RSA-OAEP-**SHA1** (OpenSSL's default), distinct from the
> OAEP-SHA256 used for person field values. The SDK handles this difference
> internally — you only supply the account key in config.
