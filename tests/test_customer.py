"""CustomerClient (b2b, #168) — parse + method-shape + key-sourcing tests.

Reuses the shared decryption vector's PEM as the customer ACCOUNT key (the vector
is UNCHANGED — only read). No sign/accept surface is asserted (spec D6).
"""

import base64
import json
import os

import pytest

from allus_company_data.config import Config
from allus_company_data.customer import CustomerClient
from allus_company_data.customer_models import CustomerConnection
from allus_company_data.http import HttpClient

VECTOR_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "testdata", "decryption-vector.json")
)


@pytest.fixture(scope="module")
def vector():
    with open(VECTOR_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture
def account_pem(vector, tmp_path):
    p = tmp_path / "account-key.pem"
    p.write_text(vector["encrypted_private_key_pem"], encoding="ascii")
    return str(p)


@pytest.fixture
def config(account_pem, vector, tmp_path):
    return Config(
        api_url="https://api.allme.fyi",
        customer_client_id="acct_abc",
        customer_client_secret="topsecret",
        account_private_key=account_pem,
        account_passphrase=vector["passphrase"],
        cache_dir=str(tmp_path / "cache"),
    )


class FakeResponse:
    def __init__(self, status_code, *, json_body=None, headers=None):
        self.status_code = status_code
        self._json_body = json_body
        self.text = json.dumps(json_body) if json_body is not None else ""
        self.headers = headers or {}

    def json(self):
        if self._json_body is None:
            raise ValueError("no json body")
        return self._json_body


class FakeSession:
    def __init__(self, get_router, write_router=None):
        self._get_router = get_router
        self._write_router = write_router
        self.requests = []
        self.gets = []

    def post(self, url, data=None, headers=None):
        return FakeResponse(
            200, json_body={"access_token": "tok-1", "token_type": "Bearer", "expires_in": 3600}
        )

    def get(self, url, params=None, headers=None):
        self.gets.append({"url": url, "params": params})
        return self._get_router(url, params)

    def request(self, method, url, params=None, headers=None, json=None, data=None):
        if method.upper() == "GET":
            return self.get(url, params=params, headers=headers)
        self.requests.append({"method": method.upper(), "url": url, "json": json})
        if self._write_router is None:
            return FakeResponse(200, json_body={})
        return self._write_router(method.upper(), url, json)


def _customer(config, get_router, write_router=None):
    session = FakeSession(get_router, write_router)
    http = HttpClient(config, session=session)
    return CustomerClient(config, http=http), session


def _spki_b64(vector) -> str:
    from allus_company_data.crypto import load_private_key
    from cryptography.hazmat.primitives import serialization

    priv = load_private_key(vector["encrypted_private_key_pem"].encode("ascii"), vector["passphrase"])
    spki = priv.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(spki).decode("ascii")


# ── config ─────────────────────────────────────────────────────────────────────


def test_customer_config_requires_acct_pair(tmp_path):
    from allus_company_data.errors import ConfigError

    p = tmp_path / "c.json"
    p.write_text(json.dumps({"api_url": "https://api.allme.fyi"}), encoding="utf-8")
    with pytest.raises(ConfigError):
        Config.from_customer_file(str(p))


def test_customer_config_loads(config):
    assert config.customer_client_id == "acct_abc"
    assert config.client_id is None  # service creds absent for a customer config


# ── connections ──────────────────────────────────────────────────────────────


def test_connections_parses_company_and_services(config):
    body = {
        "connections": [
            {
                "id": "conn-1",
                "customer_type": "company",
                "company": {"user_id": "co-1", "display_name": "Acme BV", "share_code": "ACME01"},
                "company_profile": [{"slug": "company_email", "value": "hi@acme.example"}],
                "services": [
                    {"service_link_id": "sl-1", "service_id": "svc-1", "service_name": "CRM",
                     "shared": [{"slug": "support_email", "value": "s@acme.example"}],
                     "mappings": [{"request_field_id": "rf-1"}]},
                ],
            }
        ]
    }
    c, _ = _customer(config, lambda url, params: FakeResponse(200, json_body=body))
    conns = c.connections()
    assert len(conns) == 1
    conn = conns[0]
    assert isinstance(conn, CustomerConnection)
    assert conn.customer_type == "company"
    assert conn.company_name == "Acme BV"
    assert conn.company_code == "ACME01"
    assert conn.company_profile[0]["value"] == "hi@acme.example"
    assert conn.services[0].service_name == "CRM"
    assert conn.services[0].shared[0]["value"] == "s@acme.example"


# ── typed consent answers use the TARGET service key ─────────────────────────


def test_provide_consent_encrypts_to_service_key(config, vector):
    spki = _spki_b64(vector)

    def get_router(url, params):
        if "/api/keys/ACME01/CRM" in url:
            return FakeResponse(200, json_body={"public_key": spki})
        return FakeResponse(200, json_body={})

    def write_router(method, url, body):
        return FakeResponse(200, json_body={"ok": True, "echo": body})

    c, session = _customer(config, get_router, write_router)
    c.provide_consent(
        "consent-1",
        [{"request_field_id": "rf-1", "value": "billing@me.example"}],
        company_code="ACME01", service_code="CRM",
    )
    posted = session.requests[-1]
    assert posted["url"].endswith("/consents/consent-1/provide")
    decisions = posted["json"]["decisions"]
    assert decisions[0]["kind"] == "typed"
    wrapper = decisions[0]["value"]
    # It is a real hybrid wrapper decryptable by the vector key.
    from allus_company_data.crypto import decrypt, load_private_key
    priv = load_private_key(vector["encrypted_private_key_pem"].encode("ascii"), vector["passphrase"])
    assert decrypt(wrapper, priv) == "billing@me.example"


def test_decline_consent_posts(config):
    c, session = _customer(config, lambda u, p: FakeResponse(200, json_body={}))
    c.decline_consent("consent-9")
    assert session.requests[-1]["url"].endswith("/consents/consent-9/decline")


# ── documents decrypt with the ACCOUNT key ───────────────────────────────────


def test_document_file_decrypts_with_account_key(config, vector):
    from allus_company_data.crypto import load_private_key
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    priv = load_private_key(vector["encrypted_private_key_pem"].encode("ascii"), vector["passphrase"])
    pub = priv.public_key()
    plaintext = json.dumps({"file": "data:application/pdf;base64,AAA", "name": "contract.pdf"})
    aes_key, iv = os.urandom(32), os.urandom(12)
    ct = AESGCM(aes_key).encrypt(iv, plaintext.encode("utf-8"), None)
    k = pub.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    wrapper = {"_enc": 1, "k": base64.b64encode(k).decode(), "iv": base64.b64encode(iv).decode(), "d": base64.b64encode(ct).decode()}

    def get_router(url, params):
        return FakeResponse(200, json_body={"encrypted": True, "value": wrapper})

    c, _ = _customer(config, get_router)
    out = c.document_file("conn-1", "doc-1")
    assert out["name"] == "contract.pdf"


# ── D6: no sign / accept surface ─────────────────────────────────────────────


def test_no_sign_or_accept_methods():
    for banned in ("sign", "accept", "sign_document", "accept_document", "sign_email_code"):
        assert not hasattr(CustomerClient, banned), f"CustomerClient must not expose {banned} (D6)"


# ── change feed hits the customer route ──────────────────────────────────────


def test_drain_batch_uses_customer_changes(config):
    seen = {}

    def get_router(url, params):
        if "/api/customer/changes" in url:
            seen["hit"] = True
            return FakeResponse(200, json_body={"changes": [
                {"id": "ch-1", "event": "share_changed", "customer_type": "company"}
            ]})
        return FakeResponse(200, json_body={})

    c, _ = _customer(config, get_router)
    changes = c.drain_batch(10)
    assert seen.get("hit")
    assert changes[0].id == "ch-1"
    assert changes[0].customer_type == "company"
