"""Client-facade tests.

Everything is MOCKED — no live API. A ``FakeSession`` (the same shape as
test_http.py's) replays canned **hardened** API JSON: the token, the
request-fields catalog, the connections list, a single connection, the logs, the
changes feed, and a slot file endpoint. Ciphertext fields reuse the shared
decryption vector's real ``{_enc:1,...}`` wrapper + the vector's key (written to a
temp PEM the Client loads at construction), so this exercises the whole
facade → http → crypto → model wiring end-to-end without the network.

Covered:
* request_fields() parses + CACHES (exactly one HTTP catalog fetch even when
  connections()/changes need the slug→type map);
* connections() is a LAZY generator yielding typed Connections with decrypted,
  slug-keyed values; it auto-pages and stops on a short page;
* a binary value is a lazy BinaryHandle whose .bytes() GETs the slot endpoint,
  unwraps {"encrypted":true,"value":...}, decrypts → the vector's inner bytes;
* connection(id) builds one Connection;
* logs() deserializes the {total, items} shape;
* process_changes() drains the fake feed through the pump one-by-one (and the
  feed's drain-on-fetch is modeled — each fetch returns then empties).
"""

import base64
import hashlib
import json
import os

import pytest

from allus_company_data.client import Client
from allus_company_data.config import Config
from allus_company_data.crypto import BinaryHandle
from allus_company_data.errors import ConfigError
from allus_company_data.http import HttpClient
from allus_company_data.models import Connection, LogEntry, RequestField

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


@pytest.fixture
def pem_path(vector, tmp_path):
    """Write the vector's encrypted PEM to disk so the Client can load it."""
    p = tmp_path / "service-key.pem"
    p.write_text(vector["encrypted_private_key_pem"], encoding="ascii")
    return str(p)


@pytest.fixture
def config(vector, pem_path, tmp_path):
    return Config(
        api_url="https://api.allme.fyi",
        client_id="svc_abc",
        client_secret="topsecret",
        service_private_key=pem_path,
        key_passphrase=vector["passphrase"],
        cache_dir=str(tmp_path / "cache"),
    )


# ── test doubles (mirror test_http.py) ─────────────────────────────────────────


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
    """Routes GET by path to a scripted handler; POST always returns the token."""

    def __init__(self, get_router, write_router=None):
        self._get_router = get_router
        self._write_router = write_router
        self.posts = []
        self.gets = []
        self.requests = []

    def post(self, url, data=None, headers=None):
        self.posts.append({"url": url, "data": data})
        return FakeResponse(
            200,
            json_body={"access_token": "tok-1", "token_type": "Bearer", "expires_in": 3600},
        )

    def get(self, url, params=None, headers=None):
        self.gets.append({"url": url, "params": params})
        return self._get_router(url, params)

    def request(self, method, url, params=None, headers=None, json=None, data=None):
        # GET reuses the scripted get router; write verbs record + delegate to write_router.
        if method.upper() == "GET":
            return self.get(url, params=params, headers=headers)
        self.requests.append(
            {"method": method.upper(), "url": url, "params": params,
             "headers": headers, "json": json, "data": data}
        )
        if self._write_router is None:
            return FakeResponse(200, json_body={})
        return self._write_router(method.upper(), url, json, data)


def _client(config, get_router):
    session = FakeSession(get_router)
    http = HttpClient(config, session=session)
    return Client(config, http=http), session


def _encrypt_for_key(vector, plaintext: str) -> dict:
    """Encrypt a plaintext into a platform wrapper with the vector key's PUBLIC half."""
    from allus_company_data.crypto import load_private_key
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    priv = load_private_key(vector["encrypted_private_key_pem"].encode("ascii"), vector["passphrase"])
    pub = priv.public_key()
    aes_key = os.urandom(32)
    iv = os.urandom(12)
    ct = AESGCM(aes_key).encrypt(iv, plaintext.encode("utf-8"), None)
    k = pub.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return {
        "_enc": 1,
        "k": base64.b64encode(k).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
        "d": base64.b64encode(ct).decode("ascii"),
    }


_REQUEST_FIELDS_BODY = {
    "request_fields": [
        {"slug": "work_email", "label": "Work email", "type": "email",
         "one_time": False, "mandatory_provide": True, "mandatory_connected": False},
        {"slug": "billing_address", "label": "Billing address", "type": "address",
         "one_time": False, "mandatory_provide": False, "mandatory_connected": False},
        {"slug": "logo", "label": "Logo", "type": "photo",
         "one_time": True, "mandatory_provide": False, "mandatory_connected": False},
    ]
}


# ── request_fields() caches ────────────────────────────────────────────────────


def test_request_fields_parsed_and_cached(config):
    calls = {"request_fields": 0}

    def router(url, params):
        if url.endswith("/request-fields"):
            calls["request_fields"] += 1
            return FakeResponse(200, json_body=_REQUEST_FIELDS_BODY)
        raise AssertionError("unexpected GET " + url)

    client, _ = _client(config, router)
    fields = client.request_fields()
    assert [f.slug for f in fields] == ["work_email", "billing_address", "logo"]
    assert all(isinstance(f, RequestField) for f in fields)
    assert fields[0].mandatory is True

    # Cached: a second call (and the internal type lookups) does NOT re-fetch.
    client.request_fields()
    client._type_for_slug("work_email")
    assert calls["request_fields"] == 1


# ── connections() lazy generator with decrypted values ────────────────────────


def test_connections_yields_typed_decrypted(config, vector):
    addr_wrapper = _encrypt_for_key(vector, json.dumps({"city": "Utrecht", "country": "NL"}))

    page1 = {
        "total": 2,
        "items": [
            {
                "connection_id": "csc-1",
                "user_id": "person-1",
                "display_name": "Anna",
                "connected_at": "2026-06-10T00:00:00Z",
                "values": {
                    "work_email": {"value": vector["text"]["wrapper"], "live": True,
                                   "updatedAt": "2026-06-17T10:00:00Z"},
                    "billing_address": {"value": addr_wrapper, "live": False},
                    "logo": {
                        "value_url": "https://api.allme.fyi/api/company-data/connections/csc-1/slots/sf-9/file",
                        "live": True,
                    },
                },
                "pending_consent": [],
            }
        ],
    }

    def router(url, params):
        if url.endswith("/request-fields"):
            return FakeResponse(200, json_body=_REQUEST_FIELDS_BODY)
        if url.endswith("/connections"):
            # One full-but-short page (1 < limit) → generator stops after it.
            return FakeResponse(200, json_body=page1)
        raise AssertionError("unexpected GET " + url)

    client, session = _client(config, router)
    conns = list(client.connections(limit=100))
    assert len(conns) == 1
    conn = conns[0]
    assert isinstance(conn, Connection)
    assert conn.id == "csc-1"
    assert conn.person_id == "person-1"
    assert conn.display_name == "Anna"

    # text → decrypted to the vector's known plaintext
    assert conn.values["work_email"].value == vector["text"]["plaintext"]
    assert conn.values["work_email"].live is True
    # structured → parsed dict
    assert conn.values["billing_address"].value == {"city": "Utrecht", "country": "NL"}
    # binary → lazy handle, NOT fetched yet
    logo = conn.values["logo"].value
    assert isinstance(logo, BinaryHandle)
    # Only the catalog + one connections page were fetched (no slot file yet).
    conn_gets = [g for g in session.gets if g["url"].endswith("/connections")]
    assert len(conn_gets) == 1
    assert not any("/file" in g["url"] for g in session.gets)


def test_connections_auto_pages(config):
    """A full page triggers the next page; a short/empty page ends the iteration."""
    def make_item(i):
        return {"connection_id": f"c{i}", "user_id": f"p{i}", "display_name": f"N{i}",
                "values": {}}

    pages = [
        {"total": 3, "items": [make_item(1), make_item(2)]},  # full page (==limit 2)
        {"total": 3, "items": [make_item(3)]},                 # short page → stop
    ]
    state = {"i": 0}

    def router(url, params):
        if url.endswith("/request-fields"):
            return FakeResponse(200, json_body={"request_fields": []})
        if url.endswith("/connections"):
            body = pages[state["i"]]
            state["i"] += 1
            return FakeResponse(200, json_body=body)
        raise AssertionError("unexpected GET " + url)

    client, session = _client(config, router)
    ids = [c.id for c in client.connections(limit=2)]
    assert ids == ["c1", "c2", "c3"]
    # Two connections pages fetched (offset 0 then 2), then stopped on the short page.
    conn_gets = [g for g in session.gets if g["url"].endswith("/connections")]
    assert [g["params"]["offset"] for g in conn_gets] == [0, 2]


# ── binary handle fetches the slot endpoint + decrypts ─────────────────────────


def test_binary_handle_fetches_slot_and_decrypts(config, vector):
    page = {
        "total": 1,
        "items": [{
            "connection_id": "csc-1", "user_id": "person-1", "display_name": "Anna",
            "values": {"logo": {
                "value_url": "https://api.allme.fyi/api/company-data/connections/csc-1/slots/sf-9/file",
                "live": True}},
        }],
    }

    def router(url, params):
        if url.endswith("/request-fields"):
            return FakeResponse(200, json_body=_REQUEST_FIELDS_BODY)
        if url.endswith("/connections"):
            return FakeResponse(200, json_body=page)
        if url.endswith("/slots/sf-9/file"):
            # The slot endpoint serves {"encrypted":true,"value":<wrapper>}.
            return FakeResponse(200, json_body={"encrypted": True, "value": vector["binary"]["wrapper"]})
        raise AssertionError("unexpected GET " + url)

    client, session = _client(config, router)
    [conn] = list(client.connections())
    handle = conn.values["logo"].value
    assert isinstance(handle, BinaryHandle)
    assert not any("/file" in g["url"] for g in session.gets)  # lazy

    data = handle.bytes()
    assert any(g["url"].endswith("/slots/sf-9/file") for g in session.gets)
    assert hashlib.sha256(data).hexdigest() == vector["binary"]["inner_full_sha256"]


# ── connection(id) ─────────────────────────────────────────────────────────────


def test_connection_by_id(config, vector):
    detail = {
        "connection_id": "csc-7",
        "user_id": "person-7",
        "values": {"work_email": {"value": vector["text"]["wrapper"], "live": True}},
    }

    def router(url, params):
        if url.endswith("/request-fields"):
            return FakeResponse(200, json_body=_REQUEST_FIELDS_BODY)
        if url.endswith("/connections/csc-7"):
            return FakeResponse(200, json_body=detail)
        raise AssertionError("unexpected GET " + url)

    client, _ = _client(config, router)
    conn = client.connection("csc-7")
    assert conn.id == "csc-7"
    assert conn.person_id == "person-7"
    assert conn.values["work_email"].value == vector["text"]["plaintext"]


# ── logs() ──────────────────────────────────────────────────────────────────


def test_logs_deserialize(config):
    body = {
        "total": 2,
        "items": [
            {"type": "email", "message": "stale-queue alert", "metadata": {"days": 3},
             "created_at": "2026-06-17T06:00:00Z"},
            {"type": "purge", "message": "purged 4", "metadata": {"count": 4},
             "created_at": "2026-06-17T07:00:00Z"},
        ],
    }

    def router(url, params):
        if url.endswith("/logs"):
            return FakeResponse(200, json_body=body)
        raise AssertionError("unexpected GET " + url)

    client, session = _client(config, router)
    logs = client.logs(limit=50)
    assert len(logs) == 2
    assert all(isinstance(e, LogEntry) for e in logs)
    assert logs[0].type == "email"
    assert logs[0].metadata == {"days": 3}
    assert session.gets[0]["params"]["limit"] == 50


# ── process_changes() drains the feed through the pump one-by-one ──────────────


def test_process_changes_drains_through_pump(config, vector):
    # The feed is drain-on-fetch: the first /changes returns the batch, the next
    # returns empty (the API already deleted those rows).
    feed_state = {"served": False}

    def router(url, params):
        if url.endswith("/request-fields"):
            return FakeResponse(200, json_body=_REQUEST_FIELDS_BODY)
        if url.endswith("/changes"):
            if feed_state["served"]:
                return FakeResponse(200, json_body={"changes": []})
            feed_state["served"] = True
            return FakeResponse(200, json_body={"changes": [
                {"id": "chg-1", "event": "field_updated", "person_user_id": "person-1",
                 "slug": "work_email", "value": vector["text"]["wrapper"], "live": True,
                 "at": "2026-06-17T12:00:00Z"},
                {"id": "chg-2", "event": "connection_created", "person_user_id": "person-2",
                 "at": "2026-06-17T12:05:00Z"},
            ]})
        raise AssertionError("unexpected GET " + url)

    client, _ = _client(config, router)

    seen = []
    client.process_changes(lambda c: seen.append((c.id, c.event, c.value)))

    # Delivered one-by-one, in order, with the value DECRYPTED at delivery.
    assert [s[0] for s in seen] == ["chg-1", "chg-2"]
    assert seen[0][1] == "field_updated"
    assert seen[0][2] == vector["text"]["plaintext"]
    assert seen[1][1] == "connection_created"
    assert seen[1][2] is None
    # The buffer is fully drained (all acked).
    assert client.pump.buffer.pending() == []


# ── construction reads the key once (config-only keys) ────────────


def test_from_config_loads_key(vector, tmp_path):
    pem = tmp_path / "k.pem"
    pem.write_text(vector["encrypted_private_key_pem"], encoding="ascii")
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({
        "api_url": "https://api.allme.fyi",
        "client_id": "svc_abc",
        "client_secret": "s",
        "service_private_key": str(pem),
        "key_passphrase": vector["passphrase"],
        "cache_dir": str(tmp_path / "cache"),
    }), encoding="utf-8")

    client = Client.from_config(str(cfg))
    # The key is loaded into memory and the decrypt closure works on the vector.
    assert client._decrypt_value(vector["text"]["wrapper"]) == vector["text"]["plaintext"]


def test_from_config_bad_passphrase_is_config_error(vector, tmp_path):
    from allus_company_data.errors import ConfigError

    pem = tmp_path / "k.pem"
    pem.write_text(vector["encrypted_private_key_pem"], encoding="ascii")
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({
        "api_url": "https://api.allme.fyi", "client_id": "x", "client_secret": "s",
        "service_private_key": str(pem), "key_passphrase": "WRONG",
        "cache_dir": str(tmp_path / "cache"),
    }), encoding="utf-8")
    with pytest.raises(ConfigError):
        Client.from_config(str(cfg))


# ── company documents (write) ──────────────────────────────────────────────────


def _client_rw(config, get_router, write_router):
    session = FakeSession(get_router, write_router)
    http = HttpClient(config, session=session)
    return Client(config, http=http), session


def _vector_pub_spki_b64(vector):
    """The vector key's PUBLIC half as base64 SPKI/DER (what GET /api/keys returns)."""
    from allus_company_data.crypto import load_private_key
    from cryptography.hazmat.primitives import serialization

    priv = load_private_key(
        vector["encrypted_private_key_pem"].encode("ascii"), vector["passphrase"]
    )
    return base64.b64encode(
        priv.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).decode("ascii")


def _no_get(url, params):
    raise AssertionError("unexpected GET " + url)


def test_create_document_broadcast_json_is_plaintext(config):
    posted = {}

    def write_router(method, url, json_body, data):
        assert method == "POST" and url.endswith("/documents")
        posted["body"] = json_body
        return FakeResponse(201, json_body={
            "id": "d1", "kind": "document", "name": "Terms", "description": None,
            "status": "active", "payload_kind": "json", "is_private": False,
            "value": json_body["value"], "metadata": None,
            "created_at": None, "updated_at": None,
        })

    client, _ = _client_rw(config, _no_get, write_router)
    doc = client.create_document(name="Terms", payload_kind="json",
                                 json_value={"url": "x", "v": "1"}, status="active")
    assert posted["body"]["target"] is None
    assert posted["body"]["value"] == {"url": "x", "v": "1"}  # plaintext, no _enc
    assert posted["body"]["is_private"] is False
    assert doc.id == "d1" and doc.status == "active"


def test_create_document_per_person_encrypts_for_both_privacy(config, vector):
    spki = _vector_pub_spki_b64(vector)

    for is_private in (False, True):
        keys_fetched = {"n": 0}

        def get_router(url, params):
            assert url.endswith("/api/keys/ABC123")
            keys_fetched["n"] += 1
            return FakeResponse(200, json_body={"public_key": spki})

        captured = {}

        def write_router(method, url, json_body, data):
            captured["body"] = json_body
            return FakeResponse(201, json_body={
                "id": "d2", "kind": "document", "name": "PP", "description": None,
                "status": "active", "payload_kind": "json", "is_private": is_private,
                "value": json_body["value"], "metadata": None,
                "created_at": None, "updated_at": None,
            })

        client, _ = _client_rw(config, get_router, write_router)
        doc = client.create_document(
            name="PP", payload_kind="json", json_value={"plan": "pro"},
            connection_id="conn-1", share_code="ABC123", is_private=is_private,
        )
        assert keys_fetched["n"] == 1  # fetched the recipient key
        val = captured["body"]["value"]
        assert isinstance(val, dict) and val.get("_enc") == 1  # ENCRYPTED, any is_private
        assert {"k", "iv", "d"} <= set(val)
        assert captured["body"]["target"] == {"connection_id": "conn-1"}
        assert captured["body"]["is_private"] is is_private
        # round-trips through the SDK's own decrypt → the original plaintext
        from allus_company_data.crypto import decrypt, load_private_key
        priv = load_private_key(
            vector["encrypted_private_key_pem"].encode("ascii"), vector["passphrase"]
        )
        assert json.loads(decrypt(val, priv)) == {"plan": "pro"}
        assert doc.id == "d2"


def test_create_document_private_broadcast_raises(config):
    client, _ = _client_rw(config, _no_get, lambda *a: None)
    with pytest.raises(ConfigError):
        client.create_document(name="x", payload_kind="json",
                               json_value={"a": 1}, is_private=True)


def test_create_document_contract_without_target_raises(config):
    client, _ = _client_rw(config, _no_get, lambda *a: None)
    with pytest.raises(ConfigError):
        client.create_document(name="Agreement", payload_kind="json",
                               kind="agreement", requires_signature=True,
                               json_value={"a": 1})


def test_create_document_invalid_kind_raises(config):
    client, _ = _client_rw(config, _no_get, lambda *a: None)
    with pytest.raises(ConfigError):
        client.create_document(name="x", payload_kind="json",
                               kind="invalid", json_value={"a": 1})


def test_create_document_file_broadcast_uploads_file_data_uri(config):
    calls = []

    def write_router(method, url, json_body, data):
        calls.append({"method": method, "url": url, "json": json_body, "data": data})
        if url.endswith("/documents"):
            return FakeResponse(201, json_body={
                "id": "f1", "kind": "document", "name": "C", "description": None,
                "status": "active", "payload_kind": "file", "is_private": False,
                "value": {"_pending": True}, "metadata": None,
                "created_at": None, "updated_at": None,
            })
        assert url.endswith("/documents/f1/file")
        return FakeResponse(200, json_body={"id": "f1"})

    client, _ = _client_rw(config, _no_get, write_router)
    client.create_document(name="C", payload_kind="file",
                           file_bytes=b"%PDF-1.4 x", file_mime="application/pdf")
    assert calls[0]["url"].endswith("/documents") and calls[0]["json"]["target"] is None
    assert calls[1]["url"].endswith("/documents/f1/file")
    # Broadcast file upload is JSON {"file": "<data URI>", "original_name": <name>}.
    body = calls[1]["json"]
    assert calls[1]["data"] is None  # NOT raw bytes
    assert set(body.keys()) == {"file", "original_name"}
    # An extensionless name gets the extension derived from file_mime (the API
    # validates original_name's extension against an allowlist).
    assert body["original_name"] == "C.pdf"
    assert body["file"].startswith("data:application/pdf;base64,")
    assert base64.b64decode(body["file"].split(",", 1)[1]) == b"%PDF-1.4 x"


def _broadcast_file_original_name(config, *, name, file_mime, file_name=None):
    """Run a broadcast file create and return the original_name sent on /file."""
    calls = []

    def write_router(method, url, json_body, data):
        calls.append({"url": url, "json": json_body})
        if url.endswith("/documents"):
            return FakeResponse(201, json_body={
                "id": "f1", "kind": "document", "name": name, "description": None,
                "status": "active", "payload_kind": "file", "is_private": False,
                "value": {"_pending": True}, "metadata": None,
                "created_at": None, "updated_at": None,
            })
        return FakeResponse(200, json_body={"id": "f1"})

    client, _ = _client_rw(config, _no_get, write_router)
    client.create_document(name=name, payload_kind="file", file_bytes=b"%PDF-1.4 x",
                           file_mime=file_mime, file_name=file_name)
    return calls[1]["json"]["original_name"]


def test_broadcast_original_name_keeps_existing_allowed_extension(config):
    # A name that already ends in an allowed extension is sent unchanged (no doubling).
    assert _broadcast_file_original_name(config, name="Price list.pdf",
                                         file_mime="application/pdf") == "Price list.pdf"


def test_broadcast_original_name_derives_from_mime(config):
    assert _broadcast_file_original_name(config, name="Logo",
                                         file_mime="image/png") == "Logo.png"


def test_broadcast_original_name_explicit_file_name_wins(config):
    assert _broadcast_file_original_name(config, name="Anything",
                                         file_mime="application/pdf",
                                         file_name="contract-v2.pdf") == "contract-v2.pdf"


def test_create_document_file_per_person_uploads_value_wrapper_string(config, vector):
    spki = _vector_pub_spki_b64(vector)
    calls = []

    def get_router(url, params):
        return FakeResponse(200, json_body={"public_key": spki})

    def write_router(method, url, json_body, data):
        calls.append({"url": url, "json": json_body, "data": data})
        if url.endswith("/documents"):
            return FakeResponse(201, json_body={
                "id": "f2", "kind": "document", "name": "C", "description": None,
                "status": "active", "payload_kind": "file", "is_private": True,
                "value": {"_pending": True}, "metadata": None,
                "created_at": None, "updated_at": None,
            })
        return FakeResponse(200, json_body={"id": "f2"})

    client, _ = _client_rw(config, get_router, write_router)
    client.create_document(name="C", payload_kind="file", file_bytes=b"hello-bytes",
                           file_mime="application/pdf", person_user_id="u1",
                           share_code="ABC123", is_private=True)
    # Per-person file upload is JSON {"value": "<wrapper serialized to a STRING>"}.
    body = calls[1]["json"]
    assert calls[1]["data"] is None  # NOT a bare wrapper / raw bytes
    assert set(body.keys()) == {"value"}
    assert isinstance(body["value"], str)  # the API requires a STRING value
    wrapper = json.loads(body["value"])
    assert wrapper.get("_enc") == 1  # ciphertext wrapper, not the raw file
    # decrypt → the {"file":"data:...base64,..."} envelope holding the original bytes
    from allus_company_data.crypto import decrypt, load_private_key
    priv = load_private_key(
        vector["encrypted_private_key_pem"].encode("ascii"), vector["passphrase"]
    )
    env = json.loads(decrypt(wrapper, priv))
    assert env["file"].startswith("data:application/pdf;base64,")
    assert base64.b64decode(env["file"].split(",", 1)[1]) == b"hello-bytes"


def test_document_verbs_hit_right_path(config):
    seen = []

    def get_router(url, params):
        if url.endswith("/documents"):
            return FakeResponse(200, json_body={"total": 0, "items": []})
        if "/documents/d9" in url:
            return FakeResponse(200, json_body={"id": "d9", "payload_kind": "json",
                                                "is_private": False, "value": {"a": 1}})
        raise AssertionError("unexpected GET " + url)

    def write_router(method, url, json_body, data):
        seen.append((method, url, json_body))
        return FakeResponse(200, json_body={"id": "d9", "payload_kind": "json",
                                            "is_private": False, "value": {"a": 1},
                                            "status": "ended"})

    client, _ = _client_rw(config, get_router, write_router)
    assert client.list_documents(status="active") == []
    assert client.document("d9").id == "d9"
    client.update_document_status("d9", "ended")
    client.update_document_metadata("d9", name="renamed")
    client.delete_document("d9")
    methods = [(m, u.split("/api/company-data")[-1]) for m, u, _ in seen]
    assert ("PUT", "/documents/d9") in methods
    assert methods.count(("PUT", "/documents/d9")) == 2
    assert ("DELETE", "/documents/d9") in methods


# ── connect requests (service-initiated; idea 2) ────────────────────────────────


def test_send_connect_request(config):
    captured = {}

    def write_router(method, url, json_body, data):
        assert method == "POST" and url.endswith("/company-data/connect-requests")
        captured["body"] = json_body
        return FakeResponse(201, json_body={"request_id": "req-1"})

    client, _ = _client_rw(config, _no_get, write_router)
    rid = client.send_connect_request("ABC123")
    assert rid == "req-1"
    assert captured["body"] == {"share_code": "ABC123"}


def test_send_connect_request_trims(config):
    captured = {}

    def write_router(method, url, json_body, data):
        captured["body"] = json_body
        return FakeResponse(201, json_body={"request_id": "req-2"})

    client, _ = _client_rw(config, _no_get, write_router)
    assert client.send_connect_request("  XYZ789 ") == "req-2"
    assert captured["body"] == {"share_code": "XYZ789"}


def test_send_connect_request_blank_raises(config):
    client, _ = _client_rw(config, _no_get, lambda *a: None)
    with pytest.raises(ConfigError):
        client.send_connect_request("   ")


def test_send_connect_request_no_id_raises(config):
    from allus_company_data.errors import ApiError

    def write_router(method, url, json_body, data):
        return FakeResponse(201, json_body={})

    client, _ = _client_rw(config, _no_get, write_router)
    with pytest.raises(ApiError):
        client.send_connect_request("ABC123")


def test_change_parses_connect_request_outcome_events(config):
    """connection_request_accepted/_rejected surface request_id; no slug/value."""
    from allus_company_data.models import Change

    accepted = Change.from_api(
        {"id": "c1", "event": "connection_request_accepted", "request_id": "req-9",
         "person_user_id": "person-1", "share_code": "P1CODE", "at": "2026-06-23T10:00:00Z"},
        type_for_slug=lambda s: None, decrypt_value=lambda v: v,
    )
    assert accepted.event == "connection_request_accepted"
    assert accepted.request_id == "req-9"
    assert accepted.person_id == "person-1"
    assert accepted.share_code == "P1CODE"
    assert accepted.slug is None and accepted.value is None

    rejected = Change.from_api(
        {"id": "c2", "event": "connection_request_rejected", "request_id": "req-8",
         "person_user_id": "person-2", "at": "2026-06-23T11:00:00Z"},
        type_for_slug=lambda s: None, decrypt_value=lambda v: v,
    )
    assert rejected.event == "connection_request_rejected"
    assert rejected.request_id == "req-8"

    # request_id stays None for unrelated events.
    field_evt = Change.from_api(
        {"id": "c3", "event": "connection_created", "person_user_id": "person-3"},
        type_for_slug=lambda s: None, decrypt_value=lambda v: v,
    )
    assert field_evt.request_id is None
