"""Additions to the 2FA client: wait_for_result (built over the base challenge/result client)."""

import pytest

from allus_company_data.errors import ApiError
from allus_company_data.two_factor import TwoFactorClient


class FakeHttp:
    """Minimal stand-in for HttpClient — queues the dict bodies get()/post() return."""

    def __init__(self):
        self._get_q = []
        self.gets = []

    def queue_get(self, *bodies):
        self._get_q.extend(bodies)

    def get(self, path):
        self.gets.append(path)
        return self._get_q.pop(0)

    def post(self, path, json_body=None):  # unused here
        raise AssertionError("post not expected")


def _client():
    return TwoFactorClient(FakeHttp(), sleep=lambda _s: None)


def test_wait_for_result_returns_first_terminal():
    c = _client()
    c._http.queue_get(
        {"status": "pending"},
        {"status": "pending"},
        {"status": "approved", "completed_at": "2026-07-24T10:00:00Z"},
    )
    res = c.wait_for_result("chal_1", timeout=600, interval=0)
    assert res.status == "approved"
    assert res.completed_at == "2026-07-24T10:00:00Z"
    # Stopped at the first terminal read — never re-read a burned challenge.
    assert len(c._http.gets) == 3


@pytest.mark.parametrize("terminal", ["approved", "denied", "expired", "revoked", "gone"])
def test_wait_for_result_each_terminal_status(terminal):
    c = _client()
    c._http.queue_get({"status": "pending"}, {"status": terminal})
    assert c.wait_for_result("chal_1", timeout=600, interval=0).status == terminal


def test_wait_for_result_timeout_raises_apierror():
    c = _client()
    # timeout=0 → after the first pending poll the deadline has passed.
    c._http.queue_get({"status": "pending"}, {"status": "pending"})
    with pytest.raises(ApiError) as ei:
        c.wait_for_result("chal_late", timeout=0, interval=0)
    assert "not completed within" in str(ei.value)
