"""Crash-safe changes-pump tests.

The pump is the highest-risk component, so it is built full-TDD. These tests
drive it with a **fake in-memory changes source** that returns canned
CIPHERTEXT events (reusing the shared decryption vector's real ``{_enc:1,...}``
wrapper as a value) and a ``decrypt`` callable that runs the real crypto core.
Nothing here touches the live API.

Covered (the §6 contract):

* (a) a drained batch is persisted to the durable buffer BEFORE any handler call;
* (b) a handler success acks (the pending file is removed);
* (c) a handler that always raises on one event is retried then dead-lettered
      after ``max_retries`` — the other events still process;
* (d) **crash test**: deliver 1 of 3, simulate a crash (raise after acking #1,
      before #2/#3), re-instantiate the pump on the same ``cache_dir`` → it
      REPLAYS the un-acked events (idempotent — handler may see one twice) before
      draining more; nothing is lost;
* (e) buffer files store CIPHERTEXT (the on-disk value is the ``{_enc...}``
      wrapper, never the plaintext);
* (f) ``process_changes`` returns when the source is drained;
* (g) ``Change.id`` is stable across replay.
"""

import json
import os

import pytest

from allus_company_data.crypto import DecryptError, decrypt, load_private_key
from allus_company_data.config import Config
from allus_company_data.models import Change
from allus_company_data.buffer import FileBuffer
from allus_company_data.pump import Pump

VECTOR_PATH = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__), "..", "testdata", "decryption-vector.json"
    )
)


# ── fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def vector():
    with open(VECTOR_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def private_key(vector):
    pem = vector["encrypted_private_key_pem"].encode("ascii")
    return load_private_key(pem, vector["passphrase"])


@pytest.fixture(scope="module")
def cipher_wrapper(vector):
    """The shared vector's real ciphertext wrapper — used AS the on-disk value."""
    return vector["text"]["wrapper"]


@pytest.fixture(scope="module")
def expected_plaintext(vector):
    return vector["text"]["plaintext"]


@pytest.fixture
def config(tmp_path, vector):
    """A minimal Config whose cache_dir is an isolated temp dir per test."""
    return Config(
        api_url="https://api.example.test",
        client_id="svc_test",
        client_secret="secret",
        service_private_key="unused.pem",
        key_passphrase=vector["passphrase"],
        cache_dir=str(tmp_path / "allus-cache"),
    )


@pytest.fixture
def decrypt_change(private_key):
    """Build a typed Change from a raw ciphertext event, decrypting at delivery.

    This is the ``decrypt`` callable injected into the pump: it is the ONLY place
    the plaintext is produced, mirroring the real Client closure over the loaded
    service private key.
    """

    def _decrypt(event: dict) -> Change:
        return Change.from_api(
            event,
            type_for_slug=lambda slug: "text",
            decrypt_value=lambda wrapper: decrypt(wrapper, private_key),
        )

    return _decrypt


def make_events(cipher_wrapper, count, *, start=1):
    """N canned ``field_updated`` events with CIPHERTEXT values (oldest-first)."""
    events = []
    for i in range(start, start + count):
        events.append(
            {
                "id": f"chg-{i:04d}",
                "event": "field_updated",
                "person_user_id": f"person-{i}",
                "slug": "work_email",
                "value": cipher_wrapper,  # ciphertext, exactly as the API serves it
                "live": True,
                "at": f"2026-06-17T10:0{i}:00Z",
            }
        )
    return events


class FakeSource:
    """In-memory drain-on-fetch queue: fetch deletes exactly what it returns."""

    def __init__(self, events):
        self.queue = list(events)
        self.fetch_calls = []  # records each requested limit, for assertions

    def fetch(self, limit):
        self.fetch_calls.append(limit)
        batch = self.queue[:limit]
        del self.queue[: len(batch)]
        return batch


# ── (a) persist-before-deliver ────────────────────────────────────────────────


def test_batch_persisted_before_any_handler_call(config, cipher_wrapper, decrypt_change):
    """A drained batch is written to the buffer BEFORE the handler sees anything."""
    source = FakeSource(make_events(cipher_wrapper, 3))

    pending_at_first_call = {}

    def handler(change):
        # On the very first delivery, the buffer must already hold the WHOLE
        # batch (all 3 files), proving persist happened before any delivery.
        if not pending_at_first_call:
            buf = FileBuffer(config.cache_dir)
            pending_at_first_call["count"] = len(buf.pending())

    pump = Pump(config, fetch_changes=source.fetch, decrypt=decrypt_change)
    pump.process_changes(handler)

    assert pending_at_first_call["count"] == 3


# ── (b) ack on success ─────────────────────────────────────────────────────────


def test_handler_success_acks_pending_file(config, cipher_wrapper, decrypt_change):
    source = FakeSource(make_events(cipher_wrapper, 3))
    seen = []

    pump = Pump(config, fetch_changes=source.fetch, decrypt=decrypt_change)
    pump.process_changes(lambda c: seen.append(c.id))

    assert seen == ["chg-0001", "chg-0002", "chg-0003"]
    # Every pending file removed (acked) once delivered successfully.
    buf = FileBuffer(config.cache_dir)
    assert buf.pending() == []
    assert buf.dead_letters() == []


def test_delivered_change_is_decrypted_plaintext(
    config, cipher_wrapper, decrypt_change, expected_plaintext
):
    """The handler receives a typed Change whose value is the DECRYPTED plaintext."""
    source = FakeSource(make_events(cipher_wrapper, 1))
    delivered = []

    pump = Pump(config, fetch_changes=source.fetch, decrypt=decrypt_change)
    pump.process_changes(lambda c: delivered.append(c))

    assert len(delivered) == 1
    assert delivered[0].value == expected_plaintext  # not the wrapper


# ── (c) retry → dead-letter → continue ────────────────────────────────────────


def test_poison_event_dead_lettered_others_processed(
    config, cipher_wrapper, decrypt_change
):
    source = FakeSource(make_events(cipher_wrapper, 3))
    attempts = {"chg-0002": 0}
    delivered_ok = []

    def handler(change):
        if change.id == "chg-0002":
            attempts["chg-0002"] += 1
            raise RuntimeError("poison")
        delivered_ok.append(change.id)

    pump = Pump(
        config,
        fetch_changes=source.fetch,
        decrypt=decrypt_change,
        sleep=lambda _s: None,  # no real backoff sleeps in the test
    )
    pump.process_changes(handler, max_retries=3)

    # The poison event was attempted 1 + max_retries times, then dead-lettered.
    assert attempts["chg-0002"] == 4
    # The other two still processed; one poison never wedges the stream.
    assert delivered_ok == ["chg-0001", "chg-0003"]

    buf = FileBuffer(config.cache_dir)
    assert buf.pending() == []  # nothing left pending
    dl = buf.dead_letters()
    dl_ids = [d["id"] for d in dl]
    assert dl_ids == ["chg-0002"]
    # The dead-letter record carries the error + attempt count.
    assert "poison" in dl[0]["error"]
    assert dl[0]["attempts"] == 4


def test_on_error_halt_raises_and_leaves_pending(
    config, cipher_wrapper, decrypt_change
):
    """on_error='halt' stops the pump and re-raises; the event stays pending."""
    source = FakeSource(make_events(cipher_wrapper, 3))

    def handler(change):
        if change.id == "chg-0002":
            raise RuntimeError("halt-me")

    pump = Pump(
        config,
        fetch_changes=source.fetch,
        decrypt=decrypt_change,
        sleep=lambda _s: None,
    )
    with pytest.raises(RuntimeError, match="halt-me"):
        pump.process_changes(handler, max_retries=1, on_error="halt")

    buf = FileBuffer(config.cache_dir)
    pending_ids = [e["id"] for e in buf.pending()]
    # chg-0001 acked; chg-0002 (failed) + chg-0003 (never reached) still pending.
    assert pending_ids == ["chg-0002", "chg-0003"]


# ── (d) crash test ─────────────────────────────────────────────────────────────


def test_crash_after_one_then_replay_on_restart(
    config, cipher_wrapper, decrypt_change
):
    """Crash after delivering+acking #1; a fresh pump replays #2 and #3.

    Step 1: a pump that delivers exactly one event then aborts the process
    (raises a sentinel AFTER #1 is acked, before #2/#3). The un-acked #2,#3 must
    survive in the buffer.
    Step 2: re-instantiate the pump on the SAME cache_dir with an EMPTY source —
    it must replay #2,#3 (from the buffer) before draining anything new. Nothing
    is lost.
    """
    source = FakeSource(make_events(cipher_wrapper, 3))

    class Crash(Exception):
        pass

    delivered_run1 = []

    def crashing_handler(change):
        delivered_run1.append(change.id)
        if len(delivered_run1) == 1:
            return  # #1 succeeds → gets acked
        # Simulate the process dying right after #1's ack, before #2/#3 ack.
        raise Crash()

    pump1 = Pump(config, fetch_changes=source.fetch, decrypt=decrypt_change)
    with pytest.raises(Crash):
        pump1.process_changes(crashing_handler, max_retries=0, on_error="halt")

    # #1 was delivered (and acked); #2 was delivered but its handler crashed
    # (not acked); #3 never reached. So #2 and #3 remain in the buffer.
    assert delivered_run1 == ["chg-0001", "chg-0002"]
    buf_mid = FileBuffer(config.cache_dir)
    survivor_ids = [e["id"] for e in buf_mid.pending()]
    assert survivor_ids == ["chg-0002", "chg-0003"]

    # Restart: a brand-new pump on the SAME cache_dir, with NO new events in the
    # source. It must REPLAY the survivors (idempotent re-delivery) first.
    empty_source = FakeSource([])
    delivered_run2 = []
    pump2 = Pump(config, fetch_changes=empty_source.fetch, decrypt=decrypt_change)
    pump2.process_changes(lambda c: delivered_run2.append(c.id))

    # #2 and #3 are replayed after restart — nothing lost. (#1 was already acked
    # and is NOT replayed.)
    assert delivered_run2 == ["chg-0002", "chg-0003"]
    # The source was NOT consulted before the replay drained the buffer; once the
    # buffer was empty it drained once (and got nothing) → returns.
    assert empty_source.fetch_calls and empty_source.fetch_calls[0] >= 1

    buf_end = FileBuffer(config.cache_dir)
    assert buf_end.pending() == []


def test_idempotent_change_id_stable_across_replay(
    config, cipher_wrapper, decrypt_change
):
    """Change.id is identical for the same event whether first-seen or replayed."""
    source = FakeSource(make_events(cipher_wrapper, 2))

    class Crash(Exception):
        pass

    run1 = []

    def crash_after_none(change):
        run1.append((change.id, change.value))
        raise Crash()  # crash immediately → both stay pending

    pump1 = Pump(config, fetch_changes=source.fetch, decrypt=decrypt_change)
    with pytest.raises(Crash):
        pump1.process_changes(crash_after_none, max_retries=0, on_error="halt")

    run2 = []
    empty = FakeSource([])
    pump2 = Pump(config, fetch_changes=empty.fetch, decrypt=decrypt_change)
    pump2.process_changes(lambda c: run2.append((c.id, c.value)))

    # The first event's id seen on the crashed run equals its id on replay.
    assert run1[0][0] == "chg-0001"
    assert run2[0] == ("chg-0001", run1[0][1])  # same id AND same decrypted value


# ── (e) ciphertext at rest ─────────────────────────────────────────────────────


def test_buffer_files_store_ciphertext_not_plaintext(
    config, cipher_wrapper, expected_plaintext, decrypt_change
):
    """On-disk pending JSON holds the {_enc...} wrapper, never the plaintext."""
    source = FakeSource(make_events(cipher_wrapper, 2))

    # A handler that crashes immediately so the files stay on disk to inspect.
    class Stop(Exception):
        pass

    pump = Pump(config, fetch_changes=source.fetch, decrypt=decrypt_change)
    with pytest.raises(Stop):
        def boom(_c):
            raise Stop()

        pump.process_changes(boom, max_retries=0, on_error="halt")

    pending_dir = os.path.join(config.cache_dir, "pending")
    files = sorted(os.listdir(pending_dir))
    assert files, "expected pending files on disk"

    for name in files:
        with open(os.path.join(pending_dir, name), "r", encoding="utf-8") as fh:
            raw_text = fh.read()
        # The plaintext must NOT appear anywhere in the on-disk bytes.
        assert expected_plaintext not in raw_text
        # The stored value is the ciphertext wrapper.
        stored = json.loads(raw_text)
        assert stored["value"]["_enc"] == 1
        assert stored["value"]["k"] == cipher_wrapper["k"]


# ── (f) returns when drained ───────────────────────────────────────────────────


def test_process_changes_returns_when_source_drained(
    config, cipher_wrapper, decrypt_change
):
    source = FakeSource(make_events(cipher_wrapper, 5))
    delivered = []

    pump = Pump(config, fetch_changes=source.fetch, decrypt=decrypt_change)
    # Small batch_size forces multiple drain cycles; it must still terminate.
    pump.process_changes(lambda c: delivered.append(c.id), batch_size=2)

    assert [c for c in delivered] == [
        "chg-0001",
        "chg-0002",
        "chg-0003",
        "chg-0004",
        "chg-0005",
    ]
    assert source.queue == []  # fully drained
    # The last fetch returned empty, which is what makes the pump return.
    assert source.fetch_calls[-1] == 2


def test_empty_source_returns_immediately(config, decrypt_change):
    source = FakeSource([])
    delivered = []
    pump = Pump(config, fetch_changes=source.fetch, decrypt=decrypt_change)
    pump.process_changes(lambda c: delivered.append(c))
    assert delivered == []
    assert source.fetch_calls == [100]  # one drain, default batch_size, got nothing


def test_batch_size_clamped_to_500(config, cipher_wrapper, decrypt_change):
    source = FakeSource(make_events(cipher_wrapper, 1))
    pump = Pump(config, fetch_changes=source.fetch, decrypt=decrypt_change)
    pump.process_changes(lambda c: None, batch_size=9999)
    assert max(source.fetch_calls) == 500  # never request more than the API max


# ── drain_batch primitive + dead-letter retry ─────────────────────────────────


def test_drain_batch_is_raw_unbuffered(config, cipher_wrapper, decrypt_change):
    """drain_batch returns typed Changes directly, writing NOTHING to the buffer."""
    source = FakeSource(make_events(cipher_wrapper, 3))
    pump = Pump(config, fetch_changes=source.fetch, decrypt=decrypt_change)

    batch = pump.drain_batch(max=2)
    assert [c.id for c in batch] == ["chg-0001", "chg-0002"]
    # Nothing buffered — the caller owns durability for this advanced primitive.
    buf = FileBuffer(config.cache_dir)
    assert buf.pending() == []
    assert source.fetch_calls == [2]


def test_drain_batch_clamped_to_500(config, decrypt_change):
    source = FakeSource([])
    pump = Pump(config, fetch_changes=source.fetch, decrypt=decrypt_change)
    pump.drain_batch(max=10_000)
    assert source.fetch_calls == [500]


def test_retry_dead_letters_redrives(config, cipher_wrapper, decrypt_change):
    """A dead-lettered event can be re-driven and removed on success."""
    source = FakeSource(make_events(cipher_wrapper, 2))

    def always_fail_2(change):
        if change.id == "chg-0002":
            raise RuntimeError("boom")

    pump = Pump(
        config,
        fetch_changes=source.fetch,
        decrypt=decrypt_change,
        sleep=lambda _s: None,
    )
    pump.process_changes(always_fail_2, max_retries=1)

    buf = FileBuffer(config.cache_dir)
    assert [d["id"] for d in buf.dead_letters()] == ["chg-0002"]

    # Now re-drive the dead-letters with a handler that succeeds.
    redriven = []
    pump.retry_dead_letters(lambda c: redriven.append(c.id))
    assert redriven == ["chg-0002"]
    assert FileBuffer(config.cache_dir).dead_letters() == []


def test_retry_dead_letters_still_failing_stays_deadlettered_never_pending(
    config, cipher_wrapper, decrypt_change
):
    """A still-failing re-drive bumps attempts IN deadletter/ and NEVER touches pending/.

    Fix 2 (the remove→append→dead_letter crash window): re-driving a dead-letter
    that fails again must leave it in ``deadletter/`` with a refreshed attempt
    count, and must never route it back through ``pending/`` (where a crash
    between the old append + re-dead-letter would resurrect it as a live pending
    event). We assert the record stays dead-lettered, the attempt count is bumped,
    and ``pending/`` is empty at every observable point.
    """
    source = FakeSource(make_events(cipher_wrapper, 2))

    def fail_2(change):
        if change.id == "chg-0002":
            raise RuntimeError("boom")

    pump = Pump(
        config, fetch_changes=source.fetch, decrypt=decrypt_change, sleep=lambda _s: None
    )
    pump.process_changes(fail_2, max_retries=1)

    buf = FileBuffer(config.cache_dir)
    dl0 = buf.dead_letters()
    assert [d["id"] for d in dl0] == ["chg-0002"]
    assert dl0[0]["attempts"] == 2  # 1 + max_retries
    pending_dir = os.path.join(config.cache_dir, "pending")
    deadletter_dir = os.path.join(config.cache_dir, "deadletter")

    # Re-drive with a handler that STILL fails. on_error='deadletter' (default).
    redriven = pump.retry_dead_letters(fail_2, max_retries=2)
    assert redriven == 0

    # It is STILL dead-lettered (not removed), with a bumped attempt count …
    buf2 = FileBuffer(config.cache_dir)
    dl1 = buf2.dead_letters()
    assert [d["id"] for d in dl1] == ["chg-0002"]
    assert dl1[0]["attempts"] == 3  # 1 + the 2 re-drive attempts
    assert "boom" in dl1[0]["error"]
    # … and it NEVER appeared in pending/ (no remove→append→dead_letter dance).
    assert buf2.pending() == []
    assert os.listdir(pending_dir) == []  # not even a temp/leftover file
    # The deadletter file is rewritten in place — exactly one record on disk.
    dl_files = [n for n in os.listdir(deadletter_dir) if n.endswith(".json")]
    assert len(dl_files) == 1

    # A final successful re-drive removes it cleanly.
    ok = []
    again = pump.retry_dead_letters(lambda c: ok.append(c.id))
    assert again == 1 and ok == ["chg-0002"]
    assert FileBuffer(config.cache_dir).dead_letters() == []
    assert FileBuffer(config.cache_dir).pending() == []


def test_retry_dead_letters_attempts_monotonic_across_runs(
    config, cipher_wrapper, decrypt_change
):
    """The stored attempt count never DECREASES across separate re-drive runs.

    A later ``retry_dead_letters`` run with a smaller ``max_retries`` produces a
    lower run-local attempt count; ``update_dead_letter`` clamps to
    ``max(existing, new)`` so the recorded total stays monotonic. (The five ports
    copy this — a non-monotonic counter would understate how many times an event
    has failed in operators' dashboards.)
    """
    source = FakeSource(make_events(cipher_wrapper, 2))

    def fail_2(change):
        if change.id == "chg-0002":
            raise RuntimeError("boom")

    pump = Pump(
        config, fetch_changes=source.fetch, decrypt=decrypt_change, sleep=lambda _s: None
    )
    pump.process_changes(fail_2, max_retries=3)
    dl0 = FileBuffer(config.cache_dir).dead_letters()
    assert [d["id"] for d in dl0] == ["chg-0002"]
    assert dl0[0]["attempts"] == 4  # 1 initial + 3 retries

    # Re-drive with a SMALLER budget (run-local attempts = 1). The stored count
    # must not drop to 1 — it stays clamped at the prior high-water mark of 4.
    assert pump.retry_dead_letters(fail_2, max_retries=0) == 0
    dl1 = FileBuffer(config.cache_dir).dead_letters()
    assert [d["id"] for d in dl1] == ["chg-0002"]
    assert dl1[0]["attempts"] == 4  # monotonic — NOT 1


def test_retry_dead_letters_crash_window_never_resurrects_to_pending(
    config, cipher_wrapper, decrypt_change
):
    """The Fix-2 crash window: a crash DURING a still-failing re-drive's rewrite
    must never leave the event live in pending/.

    The old code did remove_dead_letter → append([event]) (→ pending/) →
    dead_letter; a crash between the append and the re-dead-letter would resurrect
    the dead-letter as a LIVE pending event on the next replay (escaping the
    dead-letter store + re-running the side-effect). We simulate the crash by
    making the buffer raise right after it persists the re-drive's failure record;
    a fresh pump on the same cache_dir must NOT replay it as pending. With the fix
    (a single in-place ``update_dead_letter``), the record never enters pending/
    regardless of where the crash lands.
    """
    source = FakeSource(make_events(cipher_wrapper, 1, start=2))  # one event: chg-0002

    def always_fail(change):
        raise RuntimeError("boom")

    pump = Pump(
        config, fetch_changes=source.fetch, decrypt=decrypt_change, sleep=lambda _s: None
    )
    pump.process_changes(always_fail, max_retries=0)  # → chg-0002 dead-lettered
    assert [d["id"] for d in FileBuffer(config.cache_dir).dead_letters()] == ["chg-0002"]

    class Crash(Exception):
        pass

    # Crash in the buggy path's final step: the old code did
    # remove_dead_letter → append([event]) (→ pending/) → dead_letter; crashing at
    # `dead_letter` is exactly the window that left the just-appended event LIVE in
    # pending/. We make `dead_letter` crash. The FIXED code never calls
    # `dead_letter` on a re-fail (it uses an in-place `update_dead_letter`), so this
    # patch is inert for the fix — but lethal for the bug, which is the point.
    pump.buffer.dead_letter = lambda *a, **k: (_ for _ in ()).throw(Crash())  # type: ignore[assignment]
    try:
        pump.retry_dead_letters(always_fail, max_retries=0)
    except Crash:
        pass  # buggy code would crash here mid-rewrite; fixed code never gets here

    # A brand-new pump on the SAME cache_dir, empty source: REPLAY must find
    # nothing pending (the dead-letter never escaped to pending/), so the
    # side-effect is NOT re-run as a live event.
    replayed = []
    pump2 = Pump(
        config, fetch_changes=FakeSource([]).fetch, decrypt=decrypt_change,
        sleep=lambda _s: None,
    )
    pump2.process_changes(lambda c: replayed.append(c.id))
    assert replayed == []  # nothing resurrected into the live stream
    assert FileBuffer(config.cache_dir).pending() == []
    # Still safely dead-lettered (its only home).
    assert [d["id"] for d in FileBuffer(config.cache_dir).dead_letters()] == ["chg-0002"]


# ── Fix 1: a poison-decrypt event must not wedge the stream ─────────────────────


def make_poison_event(start_id):
    """A field_updated event whose stored ciphertext value is corrupt/undecryptable."""
    return {
        "id": start_id,
        "event": "field_updated",
        "person_user_id": "person-x",
        "slug": "work_email",
        # A structurally-bogus wrapper → DecryptError at delivery (never on disk).
        "value": {"_enc": 1, "k": "@@notbase64@@", "iv": "AAAA", "d": "AAAA"},
        "live": True,
        "at": "2026-06-17T10:09:00Z",
    }


def test_poison_decrypt_dead_letters_without_wedging(config, cipher_wrapper, private_key):
    """A DecryptError on a buffered event dead-letters it; the rest still process.

    The decrypt runs INSIDE the delivery attempt (Fix 1), so a poison-ciphertext
    event is contained instead of propagating out of process_changes and wedging
    the stream forever on replay. A DecryptError is dead-lettered IMMEDIATELY
    (not after burning max_retries), the good events around it still deliver, and
    a fresh pump on the SAME cache_dir does NOT re-deliver the poison event (it
    lives in deadletter/, never pending/).
    """
    decrypt_calls = {"chg-0002": 0}

    def decrypt_change(event: dict) -> Change:
        cid = event.get("id")
        if cid == "chg-0002":
            decrypt_calls["chg-0002"] += 1
            raise DecryptError("corrupt ciphertext for chg-0002")
        return Change.from_api(
            event,
            type_for_slug=lambda slug: "text",
            decrypt_value=lambda wrapper: decrypt(wrapper, private_key),
        )

    # 3 events; the middle one (chg-0002) is the poison one.
    events = make_events(cipher_wrapper, 1, start=1)
    events.append(make_poison_event("chg-0002"))
    events += make_events(cipher_wrapper, 1, start=3)
    source = FakeSource(events)

    delivered = []
    pump = Pump(
        config, fetch_changes=source.fetch, decrypt=decrypt_change, sleep=lambda _s: None
    )
    pump.process_changes(lambda c: delivered.append(c.id), max_retries=3)

    # The good events processed; the poison one did NOT wedge the stream.
    assert delivered == ["chg-0001", "chg-0003"]
    # Dead-lettered IMMEDIATELY — decrypt was attempted exactly once (no retries).
    assert decrypt_calls["chg-0002"] == 1

    buf = FileBuffer(config.cache_dir)
    assert buf.pending() == []  # nothing wedged in pending/
    dl = buf.dead_letters()
    assert [d["id"] for d in dl] == ["chg-0002"]
    assert "DecryptError" in dl[0]["error"]
    assert dl[0]["attempts"] == 1  # did not burn max_retries

    # The poison record is in deadletter/, not pending/.
    assert os.listdir(os.path.join(config.cache_dir, "pending")) == []
    dl_files = [
        n for n in os.listdir(os.path.join(config.cache_dir, "deadletter"))
        if n.endswith(".json")
    ]
    assert len(dl_files) == 1

    # A fresh pump on the SAME cache_dir, empty source: it must NOT re-deliver the
    # poison event (replay only drains pending/, which is empty).
    delivered2 = []
    pump2 = Pump(
        config, fetch_changes=FakeSource([]).fetch, decrypt=decrypt_change,
        sleep=lambda _s: None,
    )
    pump2.process_changes(lambda c: delivered2.append(c.id))
    assert delivered2 == []  # poison stays dead-lettered, not replayed
    assert [d["id"] for d in FileBuffer(config.cache_dir).dead_letters()] == ["chg-0002"]


def test_poison_decrypt_with_halt_reraises(config, cipher_wrapper, private_key):
    """on_error='halt' re-raises a DecryptError just like a handler error."""

    def decrypt_change(event: dict) -> Change:
        if event.get("id") == "chg-0001":
            raise DecryptError("undecryptable")
        return Change.from_api(
            event, type_for_slug=lambda s: "text",
            decrypt_value=lambda w: decrypt(w, private_key),
        )

    source = FakeSource([make_poison_event("chg-0001")])
    pump = Pump(
        config, fetch_changes=source.fetch, decrypt=decrypt_change, sleep=lambda _s: None
    )
    with pytest.raises(DecryptError, match="undecryptable"):
        pump.process_changes(lambda c: None, on_error="halt")
    # The un-acked poison event survives in pending/ (halt left it for inspection).
    buf = FileBuffer(config.cache_dir)
    assert [e["id"] for e in buf.pending()] == ["chg-0001"]
