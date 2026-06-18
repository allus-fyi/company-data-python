"""Webhook receiver-helper tests.

No live API. We build fixture webhook requests exactly the way the platform's
webhook delivery does:

* the body = the slug-keyed Change shape (JSON or XML);
* ``X-Allus-Signature`` = lowercase-hex ``HMAC-SHA256(body, secret)`` (PHP
  ``hash_hmac('sha256', body, secret)``);
* ``X-Allus-Webhook-Id`` selects the secret from config;
* for an ``encrypt_payload`` webhook the body is REPLACED by a ``{"_enc":1,...}``
  envelope encrypted to the company ACCOUNT public key with OpenSSL's default
  OAEP (MGF1-**SHA1**) + AES-256-GCM, and the HMAC is then over that envelope.

Field ``value`` inside the change is a service-key wrapper (SHA-256), reusing the
shared decryption vector — so a parsed webhook Change decrypts identically to a
feed Change.

Covered: verify true / tampered false / unknown id false; parse a plain JSON
body → Change; parse an account-key-enveloped body → Change (with a generated
account key in config); an XML body variant; handle = verify+parse / WebhookError.
"""

import base64
import hmac
import json
import os
from hashlib import sha256

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from allus_company_data.config import Config
from allus_company_data.errors import ConfigError, WebhookError
from allus_company_data.webhooks import handle_webhook, parse_webhook, verify_webhook

VECTOR_PATH = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__), "..", "testdata", "decryption-vector.json"
    )
)

_SECRET = "wh_secret_abc123"
_WEBHOOK_ID = "wh-1"


# ── fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def vector():
    with open(VECTOR_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture
def config(vector, tmp_path):
    pem = tmp_path / "service-key.pem"
    pem.write_text(vector["encrypted_private_key_pem"], encoding="ascii")
    return Config(
        api_url="https://api.allme.fyi",
        client_id="svc",
        client_secret="s",
        service_private_key=str(pem),
        key_passphrase=vector["passphrase"],
        cache_dir=str(tmp_path / "cache"),
        webhooks={_WEBHOOK_ID: _SECRET},
    )


@pytest.fixture
def decrypt_value(vector):
    """The service-key decrypt closure the Client would supply (config-only keys)."""
    from allus_company_data.crypto import decrypt, load_private_key

    priv = load_private_key(vector["encrypted_private_key_pem"].encode("ascii"), vector["passphrase"])
    return lambda wrapper: decrypt(wrapper, priv)


def _type_for_slug(slug):
    return {"work_email": "email", "logo": "photo"}.get(slug)


def _sign(body: bytes, secret: str = _SECRET) -> str:
    return hmac.new(secret.encode("utf-8"), body, sha256).hexdigest()


def _headers(body: bytes, *, secret=_SECRET, webhook_id=_WEBHOOK_ID, sign=True):
    h = {"X-Allus-Webhook-Id": webhook_id, "X-Allus-Event": "field_updated"}
    if sign:
        h["X-Allus-Signature"] = _sign(body, secret)
    return h


def _change_body(vector) -> bytes:
    """A plain JSON field_updated change body (slug-keyed Change shape)."""
    payload = {
        "id": "chg-1",
        "event": "field_updated",
        "person_user_id": "person-1",
        "slug": "work_email",
        "at": "2026-06-17T12:00:00Z",
        "live": True,
        "value": vector["text"]["wrapper"],
    }
    # JSON_UNESCAPED_SLASHES on the PHP side; not material to HMAC since we sign
    # the exact bytes we also pass to the verifier.
    return json.dumps(payload).encode("utf-8")


# ── verify ─────────────────────────────────────────────────────────────────────


def test_verify_true_with_known_secret(config, vector):
    body = _change_body(vector)
    assert verify_webhook(body, _headers(body), config) is True


def test_verify_false_on_tampered_body(config, vector):
    body = _change_body(vector)
    headers = _headers(body)  # signature for the ORIGINAL body
    tampered = body + b" "
    assert verify_webhook(tampered, headers, config) is False


def test_verify_false_on_unknown_webhook_id(config, vector):
    body = _change_body(vector)
    headers = _headers(body, webhook_id="wh-UNKNOWN")
    assert verify_webhook(body, headers, config) is False


def test_verify_false_on_missing_signature(config, vector):
    body = _change_body(vector)
    headers = _headers(body, sign=False)
    assert verify_webhook(body, headers, config) is False


def test_verify_accepts_uppercase_hex(config, vector):
    """The platform sends lowercase hex; be tolerant of an uppercased signature."""
    body = _change_body(vector)
    headers = {"X-Allus-Webhook-Id": _WEBHOOK_ID, "X-Allus-Signature": _sign(body).upper()}
    assert verify_webhook(body, headers, config) is True


def test_verify_single_webhook_shortcut(vector, tmp_path):
    pem = tmp_path / "k.pem"
    pem.write_text(vector["encrypted_private_key_pem"], encoding="ascii")
    cfg = Config(
        api_url="https://api.allme.fyi", client_id="svc", client_secret="s",
        service_private_key=str(pem), key_passphrase=vector["passphrase"],
        cache_dir=str(tmp_path / "c"),
        webhooks={Config.SINGLE_WEBHOOK_KEY: _SECRET},  # flat "webhook_secret"
    )
    body = _change_body(vector)
    # Header carries an id, but config has only the flat secret → falls back to it.
    assert verify_webhook(body, _headers(body), cfg) is True


# ── parse (plain JSON) ──────────────────────────────────────────────────────────


def test_parse_plain_json_body(config, vector, decrypt_value):
    body = _change_body(vector)
    change = parse_webhook(
        body, _headers(body), config,
        type_for_slug=_type_for_slug, decrypt_value=decrypt_value,
    )
    assert change.id == "chg-1"
    assert change.event == "field_updated"
    assert change.person_id == "person-1"
    assert change.slug == "work_email"
    assert change.value == vector["text"]["plaintext"]  # decrypted via the service key
    assert change.live is True


def test_parse_xml_body(config, vector, decrypt_value):
    """An XML body (the platform's <response> serialization) parses to the same Change."""
    w = vector["text"]["wrapper"]
    xml = (
        "<response>"
        "<id>chg-7</id>"
        "<event>field_updated</event>"
        "<person_user_id>person-1</person_user_id>"
        "<slug>work_email</slug>"
        "<at>2026-06-17T12:00:00Z</at>"
        "<live>true</live>"
        "<value>"
        f"<_enc>1</_enc><k>{w['k']}</k><iv>{w['iv']}</iv><d>{w['d']}</d>"
        "</value>"
        "</response>"
    ).encode("utf-8")
    headers = _headers(xml)
    headers["X-Allus-Event"] = "field_updated"

    change = parse_webhook(
        xml, headers, config,
        type_for_slug=_type_for_slug, decrypt_value=decrypt_value,
    )
    assert change.id == "chg-7"
    assert change.event == "field_updated"
    assert change.slug == "work_email"
    # The XML-reconstructed wrapper decrypts to the vector plaintext.
    assert change.value == vector["text"]["plaintext"]


# ── parse (account-key encrypt_payload envelope) ────────────────────────────────


def _make_account_key(tmp_path, passphrase: str):
    """Generate an account RSA keypair; write the encrypted private PEM + return the public key."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
    )
    path = tmp_path / "account.pem"
    path.write_bytes(pem)
    return str(path), key.public_key()


def _wrap_to_account_key(public_key, plaintext: bytes) -> bytes:
    """Mimic the account-key envelope — OAEP-SHA1 + AES-256-GCM."""
    aes_key = os.urandom(32)
    iv = os.urandom(12)
    ct = AESGCM(aes_key).encrypt(iv, plaintext, None)  # tag appended
    k = public_key.encrypt(
        aes_key,
        # OpenSSL's default OAEP padding is MGF1-SHA1 — the webhook envelope path.
        padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None),
    )
    envelope = {
        "_enc": 1,
        "k": base64.b64encode(k).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
        "d": base64.b64encode(ct).decode("ascii"),
    }
    return json.dumps(envelope).encode("utf-8")


def test_parse_account_key_envelope(vector, tmp_path, decrypt_value):
    account_pem, account_pub = _make_account_key(tmp_path, "acctpp")

    service_pem = tmp_path / "service-key.pem"
    service_pem.write_text(vector["encrypted_private_key_pem"], encoding="ascii")
    config = Config(
        api_url="https://api.allme.fyi", client_id="svc", client_secret="s",
        service_private_key=str(service_pem), key_passphrase=vector["passphrase"],
        account_private_key=account_pem, account_passphrase="acctpp",
        cache_dir=str(tmp_path / "c"), webhooks={_WEBHOOK_ID: _SECRET},
    )

    inner = _change_body(vector)  # the serialized change (JSON)
    body = _wrap_to_account_key(account_pub, inner)  # the envelope IS the sent body
    headers = _headers(body)  # HMAC is over the envelope (the final body)

    # Verify first (HMAC over the envelope), then parse (unwrap → inner → Change).
    assert verify_webhook(body, headers, config) is True
    change = parse_webhook(
        body, headers, config,
        type_for_slug=_type_for_slug, decrypt_value=decrypt_value,
    )
    assert change.id == "chg-1"
    assert change.event == "field_updated"
    assert change.slug == "work_email"
    # The OUTER envelope is account-key (SHA-1); the INNER value is service-key
    # (SHA-256) → still decrypts to the vector plaintext.
    assert change.value == vector["text"]["plaintext"]


def test_parse_account_envelope_without_account_key_raises(config, vector, decrypt_value, tmp_path):
    """An encrypt_payload body but no account_private_key in config → WebhookError."""
    # Build an envelope with some throwaway account key, but DON'T configure it.
    _, account_pub = _make_account_key(tmp_path, "x")
    body = _wrap_to_account_key(account_pub, _change_body(vector))
    with pytest.raises(WebhookError):
        parse_webhook(
            body, _headers(body), config,  # config has no account_private_key
            type_for_slug=_type_for_slug, decrypt_value=decrypt_value,
        )


# ── handle = verify + parse ─────────────────────────────────────────────────────


def test_handle_verify_then_parse(config, vector, decrypt_value):
    body = _change_body(vector)
    change = handle_webhook(
        body, _headers(body), config,
        type_for_slug=_type_for_slug, decrypt_value=decrypt_value,
    )
    assert change.id == "chg-1"


def test_handle_bad_signature_raises(config, vector, decrypt_value):
    body = _change_body(vector)
    headers = _headers(body)
    headers["X-Allus-Signature"] = "deadbeef"  # wrong
    with pytest.raises(WebhookError):
        handle_webhook(
            body, headers, config,
            type_for_slug=_type_for_slug, decrypt_value=decrypt_value,
        )


# ── Client method delegation ────────────────────────────────────────────────────


def test_client_methods_delegate(config, vector):
    """Client.verify/parse/handle_webhook use the loaded service key + config secrets.

    verify_webhook is purely config+HMAC (no HTTP). parse/handle type the value
    via the cached request-fields catalog (one lazy fetch, then cached) — so the
    fake session need only answer the catalog call; no per-webhook HTTP.
    """
    from allus_company_data.client import Client
    from allus_company_data.http import HttpClient

    catalog_calls = {"n": 0}

    class CatalogOnlySession:
        def post(self, *a, **k):
            return _TokenResp()

        def get(self, url, params=None, headers=None):
            assert url.endswith("/request-fields"), f"unexpected GET {url}"
            catalog_calls["n"] += 1
            return _RFResp()

    client = Client(config, http=HttpClient(config, session=CatalogOnlySession()))
    body = _change_body(vector)
    headers = _headers(body)

    # verify makes NO HTTP at all.
    assert client.verify_webhook(body, headers) is True
    assert catalog_calls["n"] == 0

    change = client.handle_webhook(body, headers)
    assert change.id == "chg-1"
    assert change.value == vector["text"]["plaintext"]
    # The catalog was fetched at most once (cached for subsequent webhooks).
    assert catalog_calls["n"] == 1
    client.handle_webhook(body, headers)
    assert catalog_calls["n"] == 1


# ── Fix 4: the account key is loaded ONCE and reused per webhook ────────────────


def test_account_key_loaded_once_and_reused(vector, tmp_path, monkeypatch):
    """The Client loads the account key ONCE at construction; no per-webhook PBKDF2.

    encrypt_payload webhooks must not re-read the account PEM + re-run PBKDF2
    (~100k iters) on every request. We spy on ``webhooks.load_private_key`` and
    assert: it is called exactly once for the account key (at client build), the
    closure-cached key decrypts every subsequent enveloped webhook, and a second /
    third webhook trigger NO further account-key loads.
    """
    from allus_company_data import webhooks as whmod
    from allus_company_data.client import Client
    from allus_company_data.http import HttpClient

    account_pem, account_pub = _make_account_key(tmp_path, "acctpp")
    service_pem = tmp_path / "service-key.pem"
    service_pem.write_text(vector["encrypted_private_key_pem"], encoding="ascii")
    cfg = Config(
        api_url="https://api.allme.fyi", client_id="svc", client_secret="s",
        service_private_key=str(service_pem), key_passphrase=vector["passphrase"],
        account_private_key=account_pem, account_passphrase="acctpp",
        cache_dir=str(tmp_path / "c"), webhooks={_WEBHOOK_ID: _SECRET},
    )

    # Spy on the account-key load (used only inside webhooks.load_account_key).
    real_load = whmod.load_private_key
    calls = {"n": 0}

    def counting_load(pem_bytes, passphrase):
        calls["n"] += 1
        return real_load(pem_bytes, passphrase)

    monkeypatch.setattr(whmod, "load_private_key", counting_load)

    class CatalogOnlySession:
        def post(self, *a, **k):
            return _TokenResp()

        def get(self, url, params=None, headers=None):
            assert url.endswith("/request-fields")
            return _RFResp()

    client = Client(cfg, http=HttpClient(cfg, session=CatalogOnlySession()))
    # The account key was loaded exactly once, at construction (not per webhook).
    assert calls["n"] == 1

    inner = _change_body(vector)
    body = _wrap_to_account_key(account_pub, inner)
    headers = _headers(body)

    for _ in range(3):
        change = client.handle_webhook(body, headers)
        assert change.id == "chg-1"
        assert change.value == vector["text"]["plaintext"]
    # Three enveloped webhooks → STILL only the one construction-time load.
    assert calls["n"] == 1


def test_parse_webhook_loads_account_key_when_not_supplied(config, vector, decrypt_value, tmp_path):
    """Standalone parse_webhook (no cached key) still works — loads on demand.

    The account_key kwarg is optional; the module-level helper falls back to
    loading from config when the Client isn't supplying a cached key, so the
    config-only contract holds either way.
    """
    account_pem, account_pub = _make_account_key(tmp_path, "acctpp")
    service_pem = tmp_path / "service-key.pem"
    service_pem.write_text(vector["encrypted_private_key_pem"], encoding="ascii")
    cfg = Config(
        api_url="https://api.allme.fyi", client_id="svc", client_secret="s",
        service_private_key=str(service_pem), key_passphrase=vector["passphrase"],
        account_private_key=account_pem, account_passphrase="acctpp",
        cache_dir=str(tmp_path / "c"), webhooks={_WEBHOOK_ID: _SECRET},
    )
    body = _wrap_to_account_key(account_pub, _change_body(vector))
    change = parse_webhook(  # no account_key kwarg → loaded from config on demand
        body, _headers(body), cfg,
        type_for_slug=_type_for_slug, decrypt_value=decrypt_value,
    )
    assert change.id == "chg-1"
    assert change.value == vector["text"]["plaintext"]


class _TokenResp:
    status_code = 200
    text = '{"access_token":"t","token_type":"Bearer","expires_in":3600}'
    headers: dict = {}

    def json(self):
        return {"access_token": "t", "token_type": "Bearer", "expires_in": 3600}


class _RFResp:
    status_code = 200
    headers: dict = {}

    def __init__(self):
        self._b = {"request_fields": [
            {"slug": "work_email", "label": "Work email", "type": "email",
             "one_time": False, "mandatory_provide": True, "mandatory_connected": False},
        ]}
        self.text = json.dumps(self._b)

    def json(self):
        return self._b


# ── alternative webhook auth methods (bearer / basic / header / none) ────────────


def _auth_cfg(**kw):
    """Minimal Config carrying one alt-auth field (verify never reads the PEM here)."""
    return Config(
        api_url="https://api.allme.fyi",
        client_id="svc",
        client_secret="s",
        service_private_key="unused.pem",
        key_passphrase="unused",
        **kw,
    )


def _full_data(vector, tmp_path, **extra):
    pem = tmp_path / "k.pem"
    pem.write_text(vector["encrypted_private_key_pem"], encoding="ascii")
    data = {
        "api_url": "https://api.allme.fyi",
        "client_id": "svc",
        "client_secret": "s",
        "service_private_key": str(pem),
        "key_passphrase": vector["passphrase"],
    }
    data.update(extra)
    return data


def test_verify_bearer_true():
    cfg = _auth_cfg(webhook_bearer_token="tok123")
    assert verify_webhook(b"{}", {"Authorization": "Bearer tok123"}, cfg) is True


def test_verify_bearer_false_wrong_token():
    cfg = _auth_cfg(webhook_bearer_token="tok123")
    assert verify_webhook(b"{}", {"Authorization": "Bearer nope"}, cfg) is False


def test_verify_bearer_false_missing_header():
    cfg = _auth_cfg(webhook_bearer_token="tok123")
    assert verify_webhook(b"{}", {}, cfg) is False


def test_verify_basic_true():
    cfg = _auth_cfg(webhook_basic={"username": "u", "password": "p"})
    token = base64.b64encode(b"u:p").decode("ascii")
    assert verify_webhook(b"{}", {"Authorization": "Basic " + token}, cfg) is True


def test_verify_basic_false_wrong_password():
    cfg = _auth_cfg(webhook_basic={"username": "u", "password": "p"})
    bad = base64.b64encode(b"u:wrong").decode("ascii")
    assert verify_webhook(b"{}", {"Authorization": "Basic " + bad}, cfg) is False


def test_verify_header_true_case_insensitive_name():
    cfg = _auth_cfg(webhook_header={"name": "X-My-Auth", "value": "sekret"})
    assert verify_webhook(b"{}", {"x-my-auth": "sekret"}, cfg) is True


def test_verify_header_false_wrong_value():
    cfg = _auth_cfg(webhook_header={"name": "X-My-Auth", "value": "sekret"})
    assert verify_webhook(b"{}", {"X-My-Auth": "nope"}, cfg) is False


def test_verify_none_always_true():
    cfg = _auth_cfg(webhook_auth_none=True)
    assert verify_webhook(b"anything at all", {}, cfg) is True


def test_verify_no_method_configured_false():
    cfg = _auth_cfg()
    assert verify_webhook(b"{}", {"Authorization": "Bearer x"}, cfg) is False


def test_config_rejects_two_auth_methods(vector, tmp_path):
    data = _full_data(vector, tmp_path, webhook_secret="h", webhook_bearer_token="b")
    with pytest.raises(ConfigError):
        Config._build(data)


def test_config_rejects_bearer_plus_none(vector, tmp_path):
    data = _full_data(vector, tmp_path, webhook_bearer_token="b", webhook_auth_none=True)
    with pytest.raises(ConfigError):
        Config._build(data)


def test_config_basic_requires_both_fields(vector, tmp_path):
    data = _full_data(vector, tmp_path, webhook_basic={"username": "u"})
    with pytest.raises(ConfigError):
        Config._build(data)


def test_config_header_requires_both_fields(vector, tmp_path):
    data = _full_data(vector, tmp_path, webhook_header={"name": "X-H"})
    with pytest.raises(ConfigError):
        Config._build(data)


def test_config_single_method_ok_and_method_name(vector, tmp_path):
    cfg = Config._build(_full_data(vector, tmp_path, webhook_bearer_token="b"))
    assert cfg.webhook_auth_method() == "bearer"
    cfg2 = Config._build(_full_data(vector, tmp_path, webhook_secret="h"))
    assert cfg2.webhook_auth_method() == "hmac"
    cfg3 = Config._build(_full_data(vector, tmp_path, webhook_auth_none=True))
    assert cfg3.webhook_auth_method() == "none"
