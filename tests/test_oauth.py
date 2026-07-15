"""``Sign in with allme`` RP OAuth client tests (#195)."""

import json
import os
import urllib.parse

import pytest

from allus_company_data.config import Config, ConfigError
from allus_company_data.errors import ApiError, ConfigError
from allus_company_data.oauth import Claim, OAuthClient


VECTOR_PATH = os.path.join(os.path.dirname(__file__), "..", "testdata", "decryption-vector.json")


def _cfg(tmp_path=None, **overrides):
    data = {
        "api_url": "https://api.allme.fyi",
        "oauth_client_id": "idw_abc123",
        "oauth_redirect_uri": "https://shop.example/cb",
    }
    data.update(overrides)
    return Config(**{k: v for k, v in data.items()})


class FakeResp:
    def __init__(self, status, body=None):
        self.status_code = status
        self._body = body

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


class FakeSession:
    def __init__(self):
        self.posts = []
        self.gets = []
        self._post_q = []
        self._get_q = []

    def queue_post(self, *resps):
        self._post_q.extend(resps)

    def queue_get(self, *resps):
        self._get_q.extend(resps)

    def post(self, url, data=None, headers=None):
        self.posts.append({"url": url, "data": data})
        return self._post_q.pop(0)

    def get(self, url, params=None, headers=None):
        self.gets.append({"url": url, "headers": headers})
        return self._get_q.pop(0)


# ── config ───────────────────────────────────────────────────────────────

def test_idw_config_requires_client_and_redirect(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"api_url": "https://api.allme.fyi"}), encoding="utf-8")
    with pytest.raises(ConfigError):
        Config.from_idw_file(str(p))


def test_idw_config_from_env(monkeypatch):
    monkeypatch.setenv("ALLUS_API_URL", "https://api.allme.fyi")
    monkeypatch.setenv("ALLUS_OAUTH_CLIENT_ID", "idw_env")
    monkeypatch.setenv("ALLUS_OAUTH_REDIRECT_URI", "https://x/cb")
    cfg = Config.from_idw_env()
    assert cfg.oauth_client_id == "idw_env"
    assert cfg.oauth_redirect_uri == "https://x/cb"


# ── authorize_url ────────────────────────────────────────────────────────

def _parse_url(url):
    u = urllib.parse.urlparse(url)
    return u.scheme + "://" + u.netloc + u.path, dict(urllib.parse.parse_qsl(u.query))


def test_authorize_url_signin_golden():
    c = OAuthClient(_cfg())
    base, q = _parse_url(c.authorize_url("signin", state="st1"))
    assert base == "https://web.allme.fyi/auth"
    assert q["client_id"] == "idw_abc123"
    assert q["redirect_uri"] == "https://shop.example/cb"
    assert q["mode"] == "signin"
    assert q["response_mode"] == "redirect"
    assert q["state"] == "st1"
    assert "claims" not in q


def test_authorize_url_pkce_and_detached():
    c = OAuthClient(_cfg())
    _, q = _parse_url(c.authorize_url("signin", response_mode="detached", code_challenge="CH"))
    assert q["response_mode"] == "detached"
    assert q["code_challenge"] == "CH"
    assert q["code_challenge_method"] == "S256"


def test_authorize_url_claims_validation():
    c = OAuthClient(_cfg())
    claims = [
        Claim("email", suggest="email_personal"),
        Claim("photo"),          # binary → dropped
        Claim("phone", required=True),
        Claim(""),               # empty → dropped
    ]
    _, q = _parse_url(c.authorize_url("one_time", claims=claims))
    parsed = json.loads(q["claims"])
    assert [x["type"] for x in parsed] == ["email", "phone"]
    assert parsed[0]["suggest"] == "email_personal"
    assert parsed[1]["required"] is True


def test_authorize_url_caps_15_claims():
    c = OAuthClient(_cfg())
    _, q = _parse_url(c.authorize_url("one_time", claims=[Claim("text") for _ in range(30)]))
    assert len(json.loads(q["claims"])) == 15


def test_authorize_url_invalid_mode():
    c = OAuthClient(_cfg())
    with pytest.raises(ConfigError):
        c.authorize_url("bogus")


# ── exchange / userinfo / complete ───────────────────────────────────────

def test_exchange_and_userinfo():
    s = FakeSession()
    s.queue_post(FakeResp(200, {"access_token": "AT", "mode": "signin"}))
    s.queue_get(FakeResp(200, {"sub": "u1", "share_code": "AB12CD", "display_name": "Alice", "mode": "signin", "two_factor": False}))
    c = OAuthClient(_cfg(), session=s)
    tok = c.exchange_code("CODE", code_verifier="V")
    assert tok["access_token"] == "AT" and tok["mode"] == "signin"
    assert s.posts[0]["data"]["grant_type"] == "authorization_code"
    assert s.posts[0]["data"]["code_verifier"] == "V"
    info = c.userinfo("AT")
    assert info["display_name"] == "Alice"


def test_complete_sign_in_decrypts_values(tmp_path):
    with open(VECTOR_PATH) as f:
        vec = json.load(f)
    pem_path = tmp_path / "app.pem"
    pem_path.write_text(vec["encrypted_private_key_pem"], encoding="utf-8")
    cfg = _cfg(oauth_private_key=str(pem_path), oauth_key_passphrase=vec["passphrase"])
    s = FakeSession()
    s.queue_post(FakeResp(200, {"access_token": "AT", "mode": "one_time"}))
    s.queue_get(FakeResp(200, {
        "sub": "u1", "share_code": "AB12CD", "display_name": "Alice",
        "mode": "one_time", "two_factor": True,
        "values": {"email_personal": vec["text"]["wrapper"]},
    }))
    c = OAuthClient(cfg, session=s)
    out = c.complete_sign_in("CODE", code_verifier="V")
    assert out["mode"] == "one_time"
    assert out["two_factor"] is True
    assert out["user"]["display_name"] == "Alice"
    assert out["values"]["email_personal"] == vec["text"]["plaintext"]


# ── detached poll ────────────────────────────────────────────────────────

def test_poll_result_pending_then_code():
    s = FakeSession()
    s.queue_post(FakeResp(202), FakeResp(202), FakeResp(200, {"code": "AUTHCODE", "state": "DET1"}))
    c = OAuthClient(_cfg(), session=s, sleep=lambda _s: None)
    res = c.poll_result("DET1", interval=0.01, timeout=5)
    assert res["code"] == "AUTHCODE" and res["state"] == "DET1"
    assert len(s.posts) == 3


def test_poll_result_expired_raises():
    s = FakeSession()
    s.queue_post(FakeResp(410, {"error_key": "oauth.result_expired"}))
    c = OAuthClient(_cfg(), session=s, sleep=lambda _s: None)
    with pytest.raises(ApiError) as ei:
        c.poll_result("DET1", interval=0.01, timeout=5)
    assert ei.value.status == 410
