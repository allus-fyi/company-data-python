# Output model reference

The conclusions — the only objects you work with. Importable from
`allus_company_data`. Each carries `.raw` (the underlying hardened API dict; never
contains the person's source field).

## `RequestField`

Your request-field **definition** — your config, never the person's fields.
Returned by `client.request_fields()`.

```python
@dataclass
class RequestField:
    slug: str          # the stable, company-set key — the contract for value access
    label: str         # the human label (rename freely; the slug stays)
    type: str          # email|phone|url|text|address|bank|creditcard|date|date_of_birth|photo|document|legal_document|passport|photo_id|drivers_license
    one_time: bool     # a one-time snapshot vs a live (auto-updating) answer
    mandatory: bool    # mandatory-to-provide OR mandatory-to-stay-connected (the API's two flags, folded)
    verified: bool     # this row DEMANDS a verified answer (mutually exclusive with one_time)
    verified_max_age_days: Optional[int]  # oldest verification accepted; None = no age limit
    raw: dict
```

## `Connection`

A connected person — identity + the slug-keyed value map. No source field
anywhere; `values` is keyed by **your** request slug.

```python
@dataclass
class Connection:
    id: str
    person_id: str
    display_name: Optional[str]      # None on connection(id) (the list endpoint carries it)
    connected_at: Optional[datetime] # likewise None on connection(id)
    values: Dict[str, Value]         # {<your_slug>: Value}
    raw: dict
```

```python
conn.values["work_email"].value        # "alice@acme.com"
conn.values.get("mobile")               # None if the person didn't answer that slot
```

## `Value`

One answer for one of your request slots.

```python
@dataclass
class Value:
    value: Any                        # typed plaintext (see below)
    live: bool                        # True = "keep connected" (auto-updates); False = one-time snapshot
    updated_at: Optional[datetime]    # when this answer last changed
    verified: bool                    # the hash recomputes over the plaintext AND the verification has not lapsed
    verified_at: Optional[datetime]        # when the answering field was verified
    verified_expires_at: Optional[datetime]  # when that verification lapses; None = it does not
    raw: dict
```

### `value` types (resolved from the field's `type`)

| Field type | Python `value` | Notes |
|------------|----------------|-------|
| `email`, `phone`, `url`, `text` | `str` | The decrypted plaintext. |
| `address`, `bank`, `creditcard` | `dict` | The decrypted plaintext is a JSON object → parsed. A non-JSON structured value raises `DecryptError`. |
| `date`, `date_of_birth` | `datetime.date` | Parsed from ISO `YYYY-MM-DD` (the leading 10 chars); falls back to the raw string if unparseable. |
| `photo`, `document`, `legal_document`, `passport`, `photo_id`, `drivers_license` | `BinaryHandle` | Lazy — nothing fetched/decrypted until `.bytes()`/`.save()`. The last three are ID-document subtypes of `legal_document` and share its envelope. |
| unanswered / no value | `None` | The slot has no answer. |

## `BinaryHandle`

A lazy handle for a binary value. No network or decryption happens at construction.

```python
class BinaryHandle:
    value_url: str | None             # the opaque slot-keyed file URL (read-only)
    content_type: str | None          # the Content-Type the bytes arrived with (after a fetch)
    content_sha256: str | None        # the platform's X-Allus-Content-Sha256 for those bytes
    def bytes(self) -> bytes          # fetch (if needed) → the primary file bytes
    def save(self, path: str) -> int  # write bytes() to path; returns bytes written
```

On first `.bytes()`/`.save()` the handle GETs the slot-keyed file endpoint and
classifies the response on its `Content-Type` (never by sniffing the body). Which of
the two 200 shapes arrives depends on whether the person's source field is private —
their choice, changeable at any time, not announced in advance:

* **encrypted** (private source) — `application/json`, `{"encrypted": true, "value": <wrapper>}`:
  1. Decrypt the inner `{"_enc":1,…}` wrapper with the service key → a JSON file-envelope string (`{"full": "data:…", "thumb": …}` for photos, `{"file": "data:…", …}` for documents).
  2. Base64-decode the primary data URI (`full` for photos, `file` for documents) → the file bytes.
* **plaintext** (non-private source) — the file's own `Content-Type` and the body IS
  the file: returned as-is, no decrypt, no service key needed.

Either shape is cached on the handle (repeated calls don't re-fetch) and both carry
`X-Allus-Content-Sha256` → `content_sha256`, the sha256 of exactly the bytes
`.bytes()` returns. There is no variant selection: one slot has one byte sequence.

An unanswered binary slot yields an empty handle; calling `.bytes()` on it raises
`DecryptError`. A frozen answer whose 90-day retention has elapsed raises `ApiError`
(410 `company_data.file_expired`) with `content_sha256`/`expired_at` in `.details`.

## `Change`

A change-feed / webhook event. Returned by the pump (`process_changes`,
`drain_batch`) and the webhook helpers.

```python
@dataclass
class Change:
    id: str                  # the pull feed's server change-row id — your dedup key THERE only
    event: str               # see the event table
    person_id: Optional[str]
    slug: Optional[str]      # field_updated/field_deleted/consent_* only
    value: Any = None        # field_updated only; typed exactly like Value.value
    live: Optional[bool] = None  # field_updated only
    connection_id: Optional[str] = None       # message_received only
    message_id: Optional[str] = None          # message_received only — the ack boundary
    person_public_key: Optional[str] = None   # message_received only — base64 SPKI for the reply
    message_body: Optional[str] = None        # message_received only — the DECRYPTED text
    verified: bool = False       # field_updated only; hash recomputes AND the verification has not lapsed
    verified_at: Optional[datetime] = None         # when the answering field was verified
    verified_expires_at: Optional[datetime] = None  # when that verification lapses; None = it does not
    at: Optional[datetime] = None  # the change time (no separate updated_at on a change)
    raw: dict
```

### Events

| `event` | Carries |
|---------|---------|
| `connection_created` | identity only (no slot/value) |
| `connection_deleted` | identity only (no slot/value) |
| `field_updated` | `slug` + decrypted `value` (+ `live`); binary → a lazy `BinaryHandle` |
| `field_deleted` | `slug`, no value |
| `consent_accepted` / `consent_declined` | `slug` |
| `message_received` | `connection_id`, `message_id`, `person_public_key` + `message_body` (the DECRYPTED message text); no slot. Person→company only — a broadcast raises no event |

The event's ciphertext is carried under `body`. It is never `value`: on every other
event `value` means field ciphertext, and a message body is not one.

**Answering one.** `send_message` answers **201** with the created message carrying
`message_id`, which is what it returns — hand that id, or the inbound event's `message_id`,
to `mark_messages_read` as the acknowledgement boundary.

`Change.id` is captured before the server's drain-delete, so it survives a
crash + replay unchanged — dedup on it.

> **On the webhook path this id is NOT a dedup key.** A live webhook delivery has no change row behind it, so its id is minted for that single POST; a delivery replayed from the server-side backlog is rebuilt from a durable row and carries that row's id instead — the same id on every re-attempt of that row. The id is therefore sometimes stable across a duplicate and sometimes not, with no way for the receiver to tell, which is what makes it unusable as an idempotency key. Webhooks and the pull feed are alternative integrations; see `webhooks.md` for the webhook delivery contract and what to key on instead (change.id is not it).

## `LogEntry`

A service activity-log entry — ops events only (email / purge / webhook), never
person field data.

```python
@dataclass
class LogEntry:
    type: str
    message: Optional[str]
    metadata: Any
    at: Optional[datetime]
    raw: dict
```

## `.raw`

Every model has a `.raw` attribute: the underlying (hardened) API dict, for
debugging or an edge case the SDK didn't model. It never contains the person's
source field — the hardened API doesn't return it.

## Share codes — what you may send, what you always receive

A profile can carry a second, human-readable **custom share code** assigned by an
allme operator, beside the generated code the person's app displays. Both resolve
to the same person.

- **Both places this SDK takes a share code as input accept either**:
  `client.send_connect_request(share_code)` (`POST /api/company-data/connect-requests`)
  and `client.two_factor.challenge(share_code, idempotency_key, context)`
  (`POST /api/service-2fa/challenges`). Same parameter, same type, same shape —
  nothing in the SDK changes, and a customer who gives you `ACME` instead of
  `2I6UF3` simply works.
- **Every `share_code` the API emits is the GENERATED code** — `Connection.share_code`,
  `Change.share_code` and every webhook body. So a code handed to you by a customer
  may differ from the one you read back for that same person, and anything you key
  on the emitted value (a public-key cache, your own customer record) stays
  internally consistent.
