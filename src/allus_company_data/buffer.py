"""Durable plain-file buffer for the crash-safe changes pump.

The changes feed is a server-side **drain-on-fetch queue**: a fetch returns up to
N events and deletes those rows in the same transaction — the API keeps no copy.
So a drained batch MUST be persisted locally BEFORE any delivery, or a consumer
crash mid-batch loses events the API already deleted. This module is that
persistence: a zero-dependency, plain-file buffer under ``cache_dir``.

Layout::

    <cache_dir>/pending/<seq>_<change_id>.json     # one un-acked event, oldest-first
    <cache_dir>/deadletter/<seq>_<change_id>.json   # events that exhausted retries

* The stored event is the **raw hardened API event dict** — its ``value`` /
  ``value_url`` is **CIPHERTEXT**, never the decrypted plaintext. No PII is ever
  written to disk ("ciphertext at rest").
* ``<seq>`` is a zero-padded, monotonically increasing sequence number persisted
  in ``<cache_dir>/.seq``. Because :meth:`append` is called in drain order
  (oldest-first), sorting filenames lexicographically yields oldest-first — a
  stable order even if event ``at`` timestamps are missing or equal.
* Writes are **crash-safe**: each file is written to a temp name, ``fsync``-ed,
  atomically ``rename``-d into place, and the containing directory is ``fsync``-ed
  — so a crash never leaves a half-written pending file.
* ``ack(id)`` deletes the pending file; ``dead_letter(id, error)`` moves it to
  ``deadletter/`` with the error + attempt count appended. Neither re-fetches
  from the API (it already deleted the row) — the buffer is the only home.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from typing import List, Optional

_PENDING_DIR = "pending"
_DEADLETTER_DIR = "deadletter"
_SEQ_FILE = ".seq"

# Width of the zero-padded sequence prefix. 16 digits keeps filenames sorting
# lexicographically up to ~10^16 appends — vastly beyond any real backlog.
_SEQ_WIDTH = 16


def _sanitize_id(change_id: object) -> str:
    """Make a change id safe for a filename (the seq prefix guarantees order)."""
    s = str(change_id) if change_id is not None else "noid"
    return "".join(c if (c.isalnum() or c in ("-", "_")) else "_" for c in s) or "noid"


def _fsync_dir(path: str) -> None:
    """fsync a directory so a create/rename within it is durably recorded."""
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:  # pragma: no cover - platform without dir fds (e.g. some Windows)
        return
    try:
        os.fsync(fd)
    except OSError:  # pragma: no cover - fs without dir fsync
        pass
    finally:
        os.close(fd)


def _atomic_write_json(path: str, obj: dict) -> None:
    """Write ``obj`` as JSON to ``path`` crash-safely (temp + fsync + rename)."""
    directory = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp_", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, ensure_ascii=False)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)  # atomic rename over any existing file
    except BaseException:
        # Clean up the temp file on any failure so we never leak partials.
        try:
            os.unlink(tmp)
        except OSError:  # pragma: no cover
            pass
        raise
    # Durably record the rename in the directory entry.
    _fsync_dir(directory)


class FileBuffer:
    """A durable, ordered, ciphertext-at-rest event buffer under ``cache_dir``.

    Re-instantiating a ``FileBuffer`` on the same ``cache_dir`` recovers whatever
    is on disk — that recovery is exactly the pump's replay-on-restart.
    """

    def __init__(self, cache_dir: str) -> None:
        self._dir = cache_dir
        self._pending_dir = os.path.join(cache_dir, _PENDING_DIR)
        self._deadletter_dir = os.path.join(cache_dir, _DEADLETTER_DIR)
        self._seq_path = os.path.join(cache_dir, _SEQ_FILE)
        # Guard the seq counter against concurrent appends within one process.
        self._lock = threading.Lock()
        os.makedirs(self._pending_dir, exist_ok=True)
        os.makedirs(self._deadletter_dir, exist_ok=True)

    # ── sequence ─────────────────────────────────────────────────────────────

    def _next_seq(self) -> int:
        """Monotonic sequence, recovered from disk so it survives a restart.

        On a fresh process we seed from the highest seq already present in either
        directory, so replayed-then-newly-appended events keep ordering globally.
        """
        with self._lock:
            current = self._read_seq()
            if current is None:
                current = self._max_on_disk_seq()
            nxt = current + 1
            self._write_seq(nxt)
            return nxt

    def _read_seq(self) -> Optional[int]:
        try:
            with open(self._seq_path, "r", encoding="utf-8") as fh:
                return int(fh.read().strip())
        except (FileNotFoundError, ValueError):
            return None

    def _write_seq(self, value: int) -> None:
        _atomic_write_int(self._seq_path, value)

    def _max_on_disk_seq(self) -> int:
        best = 0
        for d in (self._pending_dir, self._deadletter_dir):
            for name in os.listdir(d):
                seq = _seq_of(name)
                if seq is not None and seq > best:
                    best = seq
        return best

    # ── append / list / ack ──────────────────────────────────────────────────

    def append(self, events: List[dict]) -> List[str]:
        """Persist a drained batch (oldest-first), each in its own fsync'd file.

        Each event is stored verbatim (ciphertext value intact). Returns the
        list of pending filenames written. This is the backup the API no longer
        holds — it MUST complete before the pump delivers anything.
        """
        written: List[str] = []
        for event in events:
            seq = self._next_seq()
            change_id = event.get("id") if isinstance(event, dict) else None
            name = f"{seq:0{_SEQ_WIDTH}d}_{_sanitize_id(change_id)}.json"
            path = os.path.join(self._pending_dir, name)
            _atomic_write_json(path, event)
            written.append(name)
        return written

    def pending(self) -> List[dict]:
        """All un-acked events, oldest-first (by the sortable filename)."""
        return [self._read_event(self._pending_dir, n) for n in self._pending_files()]

    def _pending_files(self) -> List[str]:
        names = [
            n
            for n in os.listdir(self._pending_dir)
            if n.endswith(".json") and not n.startswith(".tmp_")
        ]
        names.sort()  # zero-padded seq prefix → lexicographic == oldest-first
        return names

    def _read_event(self, directory: str, name: str) -> dict:
        with open(os.path.join(directory, name), "r", encoding="utf-8") as fh:
            return json.load(fh)

    def _find_pending_file(self, change_id: str) -> Optional[str]:
        target = _sanitize_id(change_id)
        for name in self._pending_files():
            if name.split("_", 1)[1] == f"{target}.json":
                return name
        return None

    def ack(self, change_id: str) -> bool:
        """Delete the pending file for ``change_id`` (the per-item ack). Idempotent."""
        name = self._find_pending_file(change_id)
        if name is None:
            return False
        try:
            os.unlink(os.path.join(self._pending_dir, name))
        except FileNotFoundError:  # pragma: no cover - already gone (idempotent)
            return False
        _fsync_dir(self._pending_dir)
        return True

    # ── dead-letter ────────────────────────────────────────────────────────────

    def dead_letter(self, change_id: str, error: str, attempts: int) -> bool:
        """Move a poison event from pending → deadletter with error + attempts.

        The event keeps its ciphertext value; the failure context is appended
        under reserved keys so it is never silently dropped.
        """
        name = self._find_pending_file(change_id)
        if name is None:
            return False
        event = self._read_event(self._pending_dir, name)
        record = dict(event)
        record["_deadletter"] = {"error": str(error), "attempts": int(attempts)}
        dest = os.path.join(self._deadletter_dir, name)
        _atomic_write_json(dest, record)
        try:
            os.unlink(os.path.join(self._pending_dir, name))
        except FileNotFoundError:  # pragma: no cover
            pass
        _fsync_dir(self._pending_dir)
        return True

    def _deadletter_files(self) -> List[str]:
        names = [
            n
            for n in os.listdir(self._deadletter_dir)
            if n.endswith(".json") and not n.startswith(".tmp_")
        ]
        names.sort()
        return names

    def dead_letters(self) -> List[dict]:
        """All dead-lettered events, oldest-first.

        Each item is the stored (ciphertext) event with a flattened ``error`` and
        ``attempts`` lifted out of the reserved ``_deadletter`` block, plus the
        event's own ``id`` for convenience.
        """
        out: List[dict] = []
        for name in self._deadletter_files():
            event = self._read_event(self._deadletter_dir, name)
            meta = event.get("_deadletter") or {}
            item = dict(event)
            item["error"] = meta.get("error")
            item["attempts"] = meta.get("attempts")
            out.append(item)
        return out

    def _find_deadletter_file(self, change_id: str) -> Optional[str]:
        target = _sanitize_id(change_id)
        for name in self._deadletter_files():
            if name.split("_", 1)[1] == f"{target}.json":
                return name
        return None

    def update_dead_letter(self, change_id: str, error: str, attempts: int) -> bool:
        """Rewrite a dead-letter record IN PLACE with a refreshed error + attempts.

        Used by a still-failing re-drive (``retry_dead_letters``): the record
        stays in ``deadletter/`` and its failure context is updated atomically
        (temp file inside ``deadletter/`` → fsync → ``os.replace`` over the same
        path). It is NEVER routed back through ``pending/``, so a crash anywhere
        in this method leaves the record either as the old dead-letter or the new
        one — it can never resurrect as a live pending event. Idempotent (returns
        ``False`` if the record is gone). Preserves the file's seq prefix so its
        oldest-first ordering in ``deadletter/`` is unchanged.
        """
        name = self._find_deadletter_file(change_id)
        if name is None:
            return False
        path = os.path.join(self._deadletter_dir, name)
        try:
            event = self._read_event(self._deadletter_dir, name)
        except FileNotFoundError:  # pragma: no cover - already gone (idempotent)
            return False
        # Rebuild the stored record: keep the ciphertext event, drop any prior
        # flattened error/attempts, and set the fresh reserved failure block.
        # The stored attempt count is monotonic across separate re-drive runs —
        # a later run with a smaller ``max_retries`` must never lower the recorded
        # total — so we clamp to max(existing, new).
        prior = (event.get("_deadletter") or {}).get("attempts")
        try:
            prior_attempts = int(prior) if prior is not None else 0
        except (TypeError, ValueError):  # pragma: no cover - defensive
            prior_attempts = 0
        record = {k: v for k, v in event.items() if k not in ("_deadletter", "error", "attempts")}
        record["_deadletter"] = {"error": str(error), "attempts": max(prior_attempts, int(attempts))}
        _atomic_write_json(path, record)  # temp+fsync+replace, all within deadletter/
        return True

    def remove_dead_letter(self, change_id: str) -> bool:
        """Delete a dead-letter record (after a successful re-drive). Idempotent."""
        name = self._find_deadletter_file(change_id)
        if name is None:
            return False
        try:
            os.unlink(os.path.join(self._deadletter_dir, name))
        except FileNotFoundError:  # pragma: no cover
            return False
        _fsync_dir(self._deadletter_dir)
        return True


def _atomic_write_int(path: str, value: int) -> None:
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp_seq_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(str(value))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:  # pragma: no cover
            pass
        raise
    _fsync_dir(directory)


def _seq_of(name: str) -> Optional[int]:
    """Extract the leading sequence number from a buffer filename."""
    head = name.split("_", 1)[0]
    try:
        return int(head)
    except ValueError:
        return None


__all__ = ["FileBuffer"]
