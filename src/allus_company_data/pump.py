"""Crash-safe streaming changes pump.

The changes feed is a server-side **drain-on-fetch queue**: a fetch returns up to
N events (default 100, max 500) and deletes those rows in the same transaction —
the API keeps no copy. So consumption cannot be a plain list: a consumer crash
mid-batch would lose events the API already deleted, and a huge backlog must not
materialize in memory. The pump solves both:

    process_changes(handler) — one Change at a time, until the feed is empty,
                               then RETURNS. No follow/daemon mode (you schedule
                               re-runs yourself).

Per cycle:

1. **Replay first** — deliver any un-acked events already in the local buffer
   (from a previous crashed run), oldest-first.
2. **Drain** — when the buffer is empty, fetch ONE batch (≤ ``batch_size``, ≤500)
   and **persist it to the durable buffer (fsync) BEFORE handing anything out**.
   This is the backup the API no longer holds.
3. **Deliver one-by-one** — for each buffered event oldest-first: decrypt its
   value (at delivery — never on disk), build the typed ``Change``, call the
   handler.
4. **Ack / retry / dead-letter** — on success remove the event from the buffer;
   on error retry with backoff up to ``max_retries``, then (``on_error``
   ``deadletter``) move it to the dead-letter store and continue (one poison
   event never wedges the stream), or (``halt``) stop and re-raise.
5. Repeat until a drain returns empty AND the buffer is drained → return.

Crash safety + at-least-once + idempotency: a batch is durably buffered before
any delivery, and acked per-item only after the handler succeeds. A crash between
a handler's success and its ack re-delivers that event on restart, so the
handler MUST be idempotent — every :class:`Change` carries a stable ``id``
(captured before the server delete) for dedup.

Injection (so tests + the real Client share one pump): the pump takes a
``fetch_changes(limit) -> list[dict]`` source (the raw drain-on-fetch call,
returning ciphertext event dicts) and a ``decrypt(event) -> Change`` callable
(closes over the loaded service private key — config-only key handling).
No key/secret is ever a method argument.
"""

from __future__ import annotations

import logging
import time
from typing import Callable, List, Optional

from .buffer import FileBuffer
from .config import Config
from .crypto import DecryptError
from .models import Change

# The drain-on-fetch queue caps a fetch at 500. The pump
# clamps any requested batch size to this.
MAX_BATCH = 500
_DEFAULT_BATCH = 100

# Default retry/backoff for a failing handler.
_DEFAULT_MAX_RETRIES = 3
_DEFAULT_BACKOFF_S = 0.5
_MAX_BACKOFF_S = 30.0

# A fetch source: given a limit, drain-and-return up to that many raw event dicts.
FetchChanges = Callable[[int], List[dict]]
# A decrypt callable: raw event dict -> typed Change (value decrypted at delivery).
DecryptChange = Callable[[dict], Change]
# The consumer handler: it does the side-effect; success acks, an exception retries.
Handler = Callable[[Change], None]


def _default_backoff(attempt: int) -> float:
    """Exponential backoff (capped) for the ``attempt``-th retry (1-based)."""
    return min(_DEFAULT_BACKOFF_S * (2 ** (attempt - 1)), _MAX_BACKOFF_S)


class Pump:
    """The crash-safe changes pump.

    Wires a durable :class:`~allus_company_data.buffer.FileBuffer` (under
    ``config.cache_dir``) to an injected drain source + decrypt callable.
    """

    def __init__(
        self,
        config: Config,
        *,
        fetch_changes: FetchChanges,
        decrypt: DecryptChange,
        logger: Optional[logging.Logger] = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._config = config
        self._fetch_changes = fetch_changes
        self._decrypt = decrypt
        self._sleep = sleep
        self._log = logger or logging.getLogger("allus_company_data.pump")
        # The buffer recovers whatever is already on disk — that recovery IS the
        # replay-on-restart in step 1.
        self._buffer = FileBuffer(config.cache_dir)

    @property
    def buffer(self) -> FileBuffer:
        return self._buffer

    # ── the pump ──────────────────────────────────────────────────────────────

    def process_changes(
        self,
        handler: Handler,
        *,
        batch_size: int = _DEFAULT_BATCH,
        max_retries: int = _DEFAULT_MAX_RETRIES,
        on_error: str = "deadletter",
        backoff: Callable[[int], float] = _default_backoff,
    ) -> None:
        """Stream events through ``handler`` until the feed is empty, then return.

        ``handler`` is called with one typed :class:`Change` at a time and must be
        idempotent (at-least-once delivery; dedup on ``Change.id``).

        Options: ``batch_size`` (clamped ≤500), ``max_retries``,
        ``on_error`` (``"deadletter"`` — default — or ``"halt"``), ``backoff``
        (attempt → seconds).
        """
        if on_error not in ("deadletter", "halt"):
            raise ValueError("on_error must be 'deadletter' or 'halt'")
        size = _clamp_batch(batch_size)

        while True:
            # 1. Replay anything already buffered (a previous crashed run), then
            #    deliver it. If the buffer is empty, drain ONE batch first.
            pending = self._buffer.pending()
            if pending:
                self._log.info("pump replay: %d buffered event(s)", len(pending))
            else:
                drained = self._drain_into_buffer(size)
                if drained == 0:
                    # A drain returned empty AND the buffer is drained → done.
                    return
                pending = self._buffer.pending()

            # 3+4. Deliver each buffered event oldest-first; ack/retry/dead-letter.
            for event in pending:
                self._deliver_one(
                    event,
                    handler,
                    max_retries=max_retries,
                    on_error=on_error,
                    backoff=backoff,
                )
            # Loop: re-check the buffer (now drained) and try another drain.

    def _drain_into_buffer(self, size: int) -> int:
        """Fetch one batch and PERSIST it to the buffer before any delivery.

        Returns the number of events drained (0 means the feed is empty).
        """
        batch = self._fetch_changes(size) or []
        self._log.info("pump drain: fetched %d event(s) (limit=%d)", len(batch), size)
        if not batch:
            return 0
        # Persist-before-deliver: the durable backup the API no longer has.
        self._buffer.append(batch)
        return len(batch)

    def _deliver_one(
        self,
        event: dict,
        handler: Handler,
        *,
        max_retries: int,
        on_error: str,
        backoff: Callable[[int], float],
    ) -> None:
        """Decrypt at delivery, call the handler, then ack / retry / dead-letter.

        The decrypt happens INSIDE the delivery attempt (not before the loop) so a
        :class:`DecryptError` on a persisted poison event (corrupt / truncated
        ciphertext, rotated key) is handled like a failure instead of propagating
        out of ``process_changes`` and wedging the stream on replay ("one poison
        event never wedges the stream"). Re-decrypting can't fix such
        an event, so a ``DecryptError`` is dead-lettered IMMEDIATELY — it does not
        burn ``max_retries`` retries (with ``on_error='halt'`` it re-raises, as a
        handler error would).
        """
        change_id = event.get("id")
        attempts = 0
        last_error: Optional[BaseException] = None

        while True:
            attempts += 1
            try:
                # Decrypt only now — never on disk (ciphertext at rest).
                # Inside the try so a poison-ciphertext DecryptError is contained.
                change = self._decrypt(event)
                self._log.debug("pump deliver: id=%s attempt=%d", change_id, attempts)
                handler(change)
            except DecryptError as exc:
                # A poison event: re-decrypting won't help, so don't burn retries.
                if on_error == "halt":
                    self._log.error(
                        "pump halt: id=%s undecryptable (%s)", change_id, exc
                    )
                    raise
                self._buffer.dead_letter(change_id, f"DecryptError: {exc}", attempts)
                self._log.error(
                    "pump dead-letter (undecryptable): id=%s: %s", change_id, exc
                )
                return
            except Exception as exc:  # noqa: BLE001 - the handler is user code
                last_error = exc
                if attempts <= max_retries:
                    delay = max(0.0, backoff(attempts))
                    self._log.warning(
                        "pump retry: id=%s attempt=%d failed (%s); backoff %.3fs",
                        change_id,
                        attempts,
                        exc,
                        delay,
                    )
                    if delay:
                        self._sleep(delay)
                    continue
                # Retries exhausted.
                if on_error == "halt":
                    self._log.error(
                        "pump halt: id=%s failed after %d attempt(s)",
                        change_id,
                        attempts,
                    )
                    raise
                self._buffer.dead_letter(change_id, str(exc), attempts)
                self._log.error(
                    "pump dead-letter: id=%s after %d attempt(s): %s",
                    change_id,
                    attempts,
                    exc,
                )
                return
            else:
                # Success → per-item ack (remove from the buffer).
                self._buffer.ack(change_id)
                self._log.debug("pump ack: id=%s", change_id)
                return

        # Unreachable, but keep the type checker happy about last_error use.
        assert last_error is None  # pragma: no cover

    # ── advanced primitive ─────────────────────────────────────────────────────

    def drain_batch(self, max: int = _DEFAULT_BATCH) -> List[Change]:
        """Raw, UNBUFFERED drain → a list of typed Changes (advanced).

        Fetches one batch (clamped ≤500) and returns the decrypted Changes
        directly — it does NOT persist anything to the buffer, so **you own
        durability** if you use it. Prefer :meth:`process_changes` for safe
        consumption.
        """
        size = _clamp_batch(max)
        batch = self._fetch_changes(size) or []
        self._log.info("drain_batch: fetched %d event(s) (limit=%d)", len(batch), size)
        return [self._decrypt(event) for event in batch]

    # ── dead-letter inspect / re-drive ─────────────────────────────────────────

    def dead_letters(self) -> List[dict]:
        """The local dead-letter store (ciphertext + error + attempt count)."""
        return self._buffer.dead_letters()

    def retry_dead_letters(
        self,
        handler: Handler,
        *,
        max_retries: int = _DEFAULT_MAX_RETRIES,
        on_error: str = "deadletter",
        backoff: Callable[[int], float] = _default_backoff,
    ) -> int:
        """Re-drive every dead-lettered event through ``handler``.

        On success the dead-letter record is removed; on repeated failure it is
        re-dead-lettered (``deadletter``) or the error is re-raised (``halt``).
        They are never re-fetched from the API (it already deleted them) — the
        local store is their only home. Returns the count successfully re-driven.
        """
        if on_error not in ("deadletter", "halt"):
            raise ValueError("on_error must be 'deadletter' or 'halt'")

        redriven = 0
        for record in self._buffer.dead_letters():
            change_id = record.get("id")
            # Strip the reserved failure block before re-decrypting the event.
            event = {k: v for k, v in record.items() if k not in ("_deadletter", "error", "attempts")}
            attempts = 0
            while True:
                attempts += 1
                try:
                    # Decrypt inside the loop so an undecryptable dead-letter
                    # (the poison-ciphertext case) is contained here too — it updates
                    # its own record in place instead of crashing the re-drive.
                    change = self._decrypt(event)
                    handler(change)
                except DecryptError as exc:
                    if on_error == "halt":
                        self._log.error(
                            "retry_dead_letters halt: id=%s undecryptable (%s)",
                            change_id,
                            exc,
                        )
                        raise
                    self._buffer.update_dead_letter(
                        change_id, f"DecryptError: {exc}", attempts
                    )
                    self._log.warning(
                        "retry_dead_letters: id=%s still undecryptable (%s)",
                        change_id,
                        exc,
                    )
                    break
                except Exception as exc:  # noqa: BLE001
                    if attempts <= max_retries:
                        delay = max(0.0, backoff(attempts))
                        if delay:
                            self._sleep(delay)
                        continue
                    if on_error == "halt":
                        self._log.error(
                            "retry_dead_letters halt: id=%s failed again", change_id
                        )
                        raise
                    # Refresh the stored attempt count + error IN PLACE — the record
                    # stays in deadletter/ and never re-enters pending/, so there is
                    # no crash window (between an append and a re-dead-letter) where it
                    # could resurrect as a live pending event.
                    self._buffer.update_dead_letter(change_id, str(exc), attempts)
                    self._log.warning(
                        "retry_dead_letters: id=%s still failing (%s)", change_id, exc
                    )
                    break
                else:
                    self._buffer.remove_dead_letter(change_id)
                    self._log.info("retry_dead_letters: id=%s re-driven OK", change_id)
                    redriven += 1
                    break
        return redriven


def _clamp_batch(value: int) -> int:
    """Clamp a requested batch size into [1, MAX_BATCH]."""
    try:
        v = int(value)
    except (TypeError, ValueError):
        v = _DEFAULT_BATCH
    if v < 1:
        v = 1
    if v > MAX_BATCH:
        v = MAX_BATCH
    return v


__all__ = ["Pump", "MAX_BATCH"]
