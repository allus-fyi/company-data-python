# The changes pump

The changes feed is a server-side **drain-on-fetch queue**:
`GET /api/company-data/changes?limit=N` returns up to N events (default 100, max
500) **and deletes exactly those rows in the same transaction**. There is no
offset/cursor/page, and the API keeps no copy after a fetch. So a consumer must:

* not lose a drained batch if it crashes mid-batch (the API already deleted it), and
* not materialize a huge backlog in memory.

`client.process_changes(handler)` (delegating to `allus_company_data.pump.Pump`)
does both.

## `process_changes(handler, **options)`

```python
process_changes(
    handler: Callable[[Change], None],
    *,
    batch_size: int = 100,                      # clamped to [1, 500]
    max_retries: int = 3,
    on_error: str = "deadletter",               # "deadletter" | "halt"
    backoff: Callable[[int], float] = <exp>,    # attempt(1-based) -> seconds
) -> None
```

Drains the feed through `handler` one `Change` at a time, **until the feed is
empty, then returns**. No follow/daemon mode — schedule re-runs yourself.

## The cycle

1. **Replay first** — deliver any un-acked events already in the local buffer (a previous crashed run), oldest-first.
2. **Drain** — when the buffer is empty, fetch one batch (≤ `batch_size`, ≤ 500) and **persist it to the durable buffer (fsync) BEFORE handing anything out**.
3. **Deliver one-by-one** — for each buffered event, oldest-first: decrypt its value *at delivery* (never on disk), build the typed `Change`, call `handler(change)`.
4. **Ack / retry / dead-letter** — on handler success, remove the event from the buffer (ack). On a handler error, retry with `backoff` up to `max_retries`; then:
   * `on_error="deadletter"` (default) → move it to the dead-letter store, log it, and continue (one poison event never wedges the stream);
   * `on_error="halt"` → re-raise the handler's exception (the event stays un-acked in the buffer for the next run).
   A **`DecryptError`** (corrupt/truncated ciphertext, rotated key) is special: the decrypt runs *inside* the delivery attempt, and an undecryptable event is **dead-lettered immediately** — re-decrypting can't fix it, so it does **not** burn `max_retries`. Under `on_error="halt"` it re-raises like a handler error. Either way it never propagates out of `process_changes` and wedges step-1 replay.
5. Repeat until a drain returns empty **and** the buffer is drained → return.

## Crash safety · at-least-once · idempotency

A batch is durably buffered *before* any delivery, and acked per-item only *after*
the handler succeeds. A crash between a handler's success and its ack re-delivers
that event on the next run. Delivery is therefore **at-least-once**:

> **Your handler must be idempotent. Dedup on `Change.id`** (the stable server
> change-row id, captured before the server delete).

## The durable buffer (on disk)

Under `cache_dir`:

```
<cache_dir>/pending/<seq>_<change_id>.json      # un-acked events, oldest-first
<cache_dir>/deadletter/<seq>_<change_id>.json   # events that exhausted retries
```

* Stored events keep their **ciphertext** `value`/`value_url` — **no plaintext PII is ever written to disk**. Decryption happens only at delivery.
* `<seq>` is a zero-padded, monotonically increasing sequence, so lexicographic filename order == oldest-first (stable even if `at` timestamps are equal/missing).
* Writes are crash-safe: temp file → fsync → atomic rename → dir fsync. A crash never leaves a half-written file.
* Re-instantiating the buffer on the same `cache_dir` recovers whatever is on disk — that recovery **is** the replay-on-restart.

## Options

| Option | Default | Meaning |
|--------|---------|---------|
| `batch_size` | 100 | Events per drain; clamped to `[1, 500]`. |
| `max_retries` | 3 | Handler retries before dead-letter/halt. |
| `on_error` | `"deadletter"` | `"deadletter"` (continue) or `"halt"` (re-raise). Any other value raises `ValueError`. |
| `backoff` | exponential, capped 30s | `attempt -> seconds` between retries. |

> `logger` is **not** a `process_changes` option in this SDK — pass it to the
> `Client` constructor (`Client.from_config("allus.json", logger=my_logger)`).
> Every drain, deliver, ack, retry, dead-letter, and replay is logged.

## No follow mode — schedule re-runs

```python
import time
while True:
    client.process_changes(handle)   # returns when the feed empties
    time.sleep(5)                     # the feed is cheap to poll (see rate limits)
```

A cron job, a worker loop, or any scheduler works equally well.

## Dead-letter inspect / re-drive

```python
client.dead_letters() -> list[dict]
client.retry_dead_letters(handler, *, max_retries=3, on_error="deadletter", backoff=<exp>) -> int
```

* `dead_letters()` — each dict is the stored (ciphertext) event with a flattened `error` and `attempts`, plus its `id`.
* `retry_dead_letters(handler)` — re-drives every dead-lettered event through `handler`. On success the record is removed. On repeated failure (or a `DecryptError`) the dead-letter record is **updated in place** with the new error + attempt count and stays in `deadletter/` (`"deadletter"`), or the error re-raises (`"halt"`). Returns the count successfully re-driven.

A re-failing dead-letter never re-enters `pending/` — it is rewritten in place
within `deadletter/`, so a crash mid-re-drive can't resurrect it as a live event
on the next run. Dead letters are **never silently dropped** and **never
re-fetched from the API** (it already deleted them) — the local store is their
only home, which is exactly why it's durable.

```python
for dl in client.dead_letters():
    print(dl["id"], dl["error"], dl["attempts"])

fixed = client.retry_dead_letters(handle)   # after fixing the handler bug
```

## Advanced: `drain_batch(max)`

```python
client.drain_batch(max: int = 100) -> list[Change]
```

A raw, **UNBUFFERED** drain: fetches one batch (clamped ≤ 500) and returns the
decrypted `Change`s directly — it does **not** persist anything to the buffer, so
**you own durability** if you use it (a crash loses what the API already deleted).
Prefer `process_changes` for safe consumption.
