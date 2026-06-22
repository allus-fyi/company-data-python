"""HTTP/auth layer tests.

All mocked — no live API. A fake session records requests and replays scripted
responses so we can exercise: the client_credentials token fetch + caching,
401 → one refresh-and-retry → AuthError, 429 → Retry-After backoff → retry /
RateLimitError, ApiError mapping (carrying the body error_key), and the
JSON/XML accept + parse paths.
"""

import json

import pytest

from allus_company_data.config import Config
from allus_company_data.errors import ApiError, AuthError, RateLimitError
from allus_company_data.http import HttpClient


# ── test doubles ─────────────────────────────────────────────────────────────


class FakeResponse:
    def __init__(self, status_code, *, json_body=None, text=None, headers=None):
        self.status_code = status_code
        self._json_body = json_body
        if text is not None:
            self.text = text
        elif json_body is not None:
            self.text = json.dumps(json_body)
        else:
            self.text = ""
        self.headers = headers or {}

    def json(self):
        if self._json_body is None:
            raise ValueError("no json body")
        return self._json_body


class FakeSession:
    """Records calls and replays queued responses (FIFO) per HTTP method."""

    def __init__(self):
        self.post_responses = []
        self.get_responses = []
        self.request_responses = []
        self.posts = []
        self.gets = []
        self.requests = []

    def post(self, url, data=None, headers=None):
        self.posts.append({"url": url, "data": data, "headers": headers})
        return self.post_responses.pop(0)

    def get(self, url, params=None, headers=None):
        self.gets.append({"url": url, "params": params, "headers": headers})
        return self.get_responses.pop(0)

    def request(self, method, url, params=None, headers=None, json=None, data=None):
        # GET goes through the existing get() recorder (keeps the get-based tests intact);
        # write verbs (POST/PUT/DELETE) record + replay from request_responses.
        if method.upper() == "GET":
            return self.get(url, params=params, headers=headers)
        self.requests.append(
            {"method": method.upper(), "url": url, "params": params,
             "headers": headers, "json": json, "data": data}
        )
        return self.request_responses.pop(0)


def _config(tmp_path, fmt="json"):
    # service_private_key path need not exist — HttpClient never loads it.
    return Config(
        api_url="https://api.allme.fyi",
        client_id="svc_abc",
        client_secret="topsecret",
        service_private_key=str(tmp_path / "k.pem"),
        key_passphrase="pp",
        format=fmt,
    )


def _token_ok():
    return FakeResponse(
        200, json_body={"access_token": "tok-123", "token_type": "Bearer", "expires_in": 3600}
    )


def _make_client(tmp_path, session, fmt="json", sleeps=None):
    if sleeps is None:
        sleeps = []
    return HttpClient(
        _config(tmp_path, fmt),
        session=session,
        sleep=lambda s: sleeps.append(s),
    )


# ── token fetch + caching ───────────────────────────────────────────────────


def test_token_is_fetched_with_client_credentials_and_attached(tmp_path):
    s = FakeSession()
    s.post_responses = [_token_ok()]
    s.get_responses = [FakeResponse(200, json_body={"ok": True})]
    c = _make_client(tmp_path, s)

    body = c.get("/api/company-data/request-fields")
    assert body == {"ok": True}

    # The token was POSTed with the client_credentials grant + creds.
    assert s.posts[0]["url"] == "https://api.allme.fyi/oauth2/token"
    assert s.posts[0]["data"] == {
        "grant_type": "client_credentials",
        "client_id": "svc_abc",
        "client_secret": "topsecret",
    }
    # And the bearer was attached to the GET.
    assert s.gets[0]["headers"]["Authorization"] == "Bearer tok-123"
    assert s.gets[0]["headers"]["Accept"] == "application/json"


def test_token_is_cached_across_calls(tmp_path):
    s = FakeSession()
    s.post_responses = [_token_ok()]  # only one token fetch expected
    s.get_responses = [
        FakeResponse(200, json_body={"n": 1}),
        FakeResponse(200, json_body={"n": 2}),
    ]
    c = _make_client(tmp_path, s)

    c.get("/api/company-data/changes")
    c.get("/api/company-data/changes")
    assert len(s.posts) == 1  # token fetched once and reused


def test_token_refetched_when_expired(tmp_path):
    s = FakeSession()
    s.post_responses = [
        FakeResponse(200, json_body={"access_token": "first", "expires_in": 0}),
        FakeResponse(200, json_body={"access_token": "second", "expires_in": 3600}),
    ]
    s.get_responses = [
        FakeResponse(200, json_body={}),
        FakeResponse(200, json_body={}),
    ]
    # A monotonic clock that advances so the 0-expiry token is stale by the 2nd call.
    ticks = iter([0.0, 0.0, 100.0, 100.0, 100.0, 100.0])
    c = HttpClient(_config(tmp_path), session=s, clock=lambda: next(ticks))

    c.get("/api/company-data/changes")  # fetches "first" (expires_in=0 → already stale)
    c.get("/api/company-data/changes")  # must refetch → "second"
    assert len(s.posts) == 2
    assert s.gets[1]["headers"]["Authorization"] == "Bearer second"


def test_token_fetch_failure_raises_auth_error(tmp_path):
    s = FakeSession()
    s.post_responses = [FakeResponse(401, json_body={"error_key": "oauth.bad_client"})]
    c = _make_client(tmp_path, s)
    with pytest.raises(AuthError):
        c.get("/api/company-data/changes")


# ── 401 refresh-and-retry ───────────────────────────────────────────────────


def test_401_triggers_one_refresh_and_retry_then_succeeds(tmp_path):
    s = FakeSession()
    s.post_responses = [_token_ok(), _token_ok()]  # initial + one refresh
    s.get_responses = [
        FakeResponse(401, json_body={"error_key": "auth.expired"}),
        FakeResponse(200, json_body={"recovered": True}),
    ]
    c = _make_client(tmp_path, s)

    body = c.get("/api/company-data/connections")
    assert body == {"recovered": True}
    assert len(s.posts) == 2  # token refreshed exactly once
    assert len(s.gets) == 2   # original + retry


def test_401_after_refresh_raises_auth_error(tmp_path):
    s = FakeSession()
    s.post_responses = [_token_ok(), _token_ok()]
    s.get_responses = [
        FakeResponse(401, json_body={"error_key": "auth.expired"}),
        FakeResponse(401, json_body={"error_key": "auth.expired"}),  # still 401 after refresh
    ]
    c = _make_client(tmp_path, s)
    with pytest.raises(AuthError):
        c.get("/api/company-data/connections")
    assert len(s.posts) == 2  # only ONE refresh, then gives up


# ── 429 backoff ─────────────────────────────────────────────────────────────


def test_429_with_retry_after_backs_off_then_succeeds(tmp_path):
    s = FakeSession()
    s.post_responses = [_token_ok()]
    s.get_responses = [
        FakeResponse(429, headers={"Retry-After": "2"}, json_body={"error_key": "rate.limited"}),
        FakeResponse(200, json_body={"done": True}),
    ]
    sleeps = []
    c = _make_client(tmp_path, s, sleeps=sleeps)

    body = c.get("/api/company-data/changes")
    assert body == {"done": True}
    assert sleeps == [2.0]  # honored Retry-After


def test_429_exhausts_retries_then_raises_rate_limit_error(tmp_path):
    s = FakeSession()
    s.post_responses = [_token_ok()]
    s.get_responses = [
        FakeResponse(429, headers={"Retry-After": "1"}, json_body={"error_key": "rate.limited"})
        for _ in range(10)
    ]
    sleeps = []
    c = HttpClient(
        _config(tmp_path),
        session=s,
        sleep=lambda x: sleeps.append(x),
        max_retries_429=3,
    )
    with pytest.raises(RateLimitError) as exc:
        c.get("/api/company-data/connections")
    assert exc.value.retry_after == 1.0
    assert exc.value.status == 429
    assert exc.value.error_key == "rate.limited"
    # 3 bounded retries → 3 sleeps, then surfaces (4 GET attempts total).
    assert len(sleeps) == 3
    assert len(s.gets) == 4


def test_429_default_backoff_when_no_retry_after(tmp_path):
    s = FakeSession()
    s.post_responses = [_token_ok()]
    s.get_responses = [
        FakeResponse(429, json_body={"error_key": "rate.limited"}),  # no Retry-After header
        FakeResponse(200, json_body={"ok": 1}),
    ]
    sleeps = []
    c = _make_client(tmp_path, s, sleeps=sleeps)
    assert c.get("/api/company-data/changes") == {"ok": 1}
    assert len(sleeps) == 1 and sleeps[0] > 0  # exponential default kicked in


# ── ApiError mapping ────────────────────────────────────────────────────────


def test_non_2xx_maps_to_api_error_with_error_key(tmp_path):
    s = FakeSession()
    s.post_responses = [_token_ok()]
    s.get_responses = [
        FakeResponse(
            403,
            json_body={"error": "Not a registered service client", "error_key": "company_data.no_client"},
        )
    ]
    c = _make_client(tmp_path, s)
    with pytest.raises(ApiError) as exc:
        c.get("/api/company-data/connections")
    assert exc.value.status == 403
    assert exc.value.error_key == "company_data.no_client"
    assert exc.value.message == "Not a registered service client"
    # RateLimitError is a subclass of ApiError but this is not a 429.
    assert not isinstance(exc.value, RateLimitError)


def test_404_maps_to_api_error(tmp_path):
    s = FakeSession()
    s.post_responses = [_token_ok()]
    s.get_responses = [
        FakeResponse(404, json_body={"error_key": "company_data.connection_not_found"})
    ]
    c = _make_client(tmp_path, s)
    with pytest.raises(ApiError) as exc:
        c.get("/api/company-data/connections/zzz")
    assert exc.value.status == 404
    assert exc.value.error_key == "company_data.connection_not_found"


# ── XML format ──────────────────────────────────────────────────────────────


def test_xml_accept_header_and_parsing(tmp_path):
    # Mirrors the API's XML serialization: <response> root, <item> for lists, bool as text.
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<response>"
        "<request_fields>"
        "<item><slug>work_email</slug><label>Work email</label><type>email</type>"
        "<one_time>false</one_time><mandatory_provide>true</mandatory_provide>"
        "<mandatory_connected>false</mandatory_connected></item>"
        "<item><slug>logo</slug><label>Logo</label><type>photo</type>"
        "<one_time>false</one_time><mandatory_provide>false</mandatory_provide>"
        "<mandatory_connected>false</mandatory_connected></item>"
        "</request_fields>"
        "</response>"
    )
    s = FakeSession()
    s.post_responses = [_token_ok()]
    s.get_responses = [FakeResponse(200, text=xml)]
    c = _make_client(tmp_path, s, fmt="xml")

    body = c.get("/api/company-data/request-fields")
    assert s.gets[0]["headers"]["Accept"] == "application/xml"
    assert isinstance(body, dict)
    fields = body["request_fields"]
    assert isinstance(fields, list) and len(fields) == 2
    assert fields[0]["slug"] == "work_email"
    assert fields[0]["type"] == "email"
    # Booleans come back as the "true"/"false" strings the API wrote;
    # the model layer coerces them (see test_models).
    assert fields[0]["one_time"] == "false"
    assert fields[0]["mandatory_provide"] == "true"


def test_xml_error_body_carries_error_key(tmp_path):
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<response><error>nope</error><error_key>company_data.no_client</error_key></response>"
    )
    s = FakeSession()
    s.post_responses = [_token_ok()]
    s.get_responses = [FakeResponse(403, text=xml)]
    c = _make_client(tmp_path, s, fmt="xml")
    with pytest.raises(ApiError) as exc:
        c.get("/api/company-data/connections")
    assert exc.value.error_key == "company_data.no_client"


# ── single-element XML list edge case ────────────────────────────────────────


def test_xml_single_item_list_is_still_a_list(tmp_path):
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<response><changes><item><id>c1</id><event>connection_created</event>"
        "<person_user_id>u1</person_user_id></item></changes></response>"
    )
    s = FakeSession()
    s.post_responses = [_token_ok()]
    s.get_responses = [FakeResponse(200, text=xml)]
    c = _make_client(tmp_path, s, fmt="xml")
    body = c.get("/api/company-data/changes")
    assert isinstance(body["changes"], list)
    assert body["changes"][0]["event"] == "connection_created"
