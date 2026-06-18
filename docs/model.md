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
    type: str          # email|phone|url|text|address|bank|creditcard|date|date_of_birth|photo|document|legal_document
    one_time: bool     # a one-time snapshot vs a live (auto-updating) answer
    mandatory: bool    # mandatory-to-provide OR mandatory-to-stay-connected (the API's two flags, folded)
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
    raw: dict
```

### `value` types (resolved from the field's `type`)

| Field type | Python `value` | Notes |
|------------|----------------|-------|
| `email`, `phone`, `url`, `text` | `str` | The decrypted plaintext. |
| `address`, `bank`, `creditcard` | `dict` | The decrypted plaintext is a JSON object → parsed. A non-JSON structured value raises `DecryptError`. |
| `date`, `date_of_birth` | `datetime.date` | Parsed from ISO `YYYY-MM-DD` (the leading 10 chars); falls back to the raw string if unparseable. |
| `photo`, `document`, `legal_document` | `BinaryHandle` | Lazy — nothing fetched/decrypted until `.bytes()`/`.save()`. |
| unanswered / no value | `None` | The slot has no answer. |

## `BinaryHandle`

A lazy handle for a binary value. No network or decryption happens at construction.

```python
class BinaryHandle:
    value_url: str | None             # the opaque slot-keyed file URL (read-only)
    def bytes(self) -> bytes          # fetch (if needed) → decrypt → decoded primary file bytes
    def save(self, path: str) -> int  # write bytes() to path; returns bytes written
```

On first `.bytes()`/`.save()`:

1. GET the slot-keyed file endpoint → the API serves `{"encrypted": true, "value": <wrapper>}`.
2. Decrypt the inner `{"_enc":1,…}` wrapper with the service key → a JSON file-envelope string (`{"full": "data:…", "thumb": …}` for photos, `{"file": "data:…", …}` for documents).
3. Base64-decode the primary data URI (`full` for photos, `file` for documents) → the file bytes. Cached on the handle (repeated calls don't re-fetch).

An unanswered binary slot yields an empty handle; calling `.bytes()` on it raises
`DecryptError`.

## `Change`

A change-feed / webhook event. Returned by the pump (`process_changes`,
`drain_batch`) and the webhook helpers.

```python
@dataclass
class Change:
    id: str                  # the stable server change-row id — YOUR dedup key
    event: str               # see the event table
    person_id: Optional[str]
    slug: Optional[str]      # field_updated/field_deleted/consent_* only
    value: Any = None        # field_updated only; typed exactly like Value.value
    live: Optional[bool] = None  # field_updated only
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

`Change.id` is captured before the server's drain-delete, so it survives a
crash + replay unchanged — dedup on it.

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
