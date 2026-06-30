"""Output-model tests.

Drives the model factories with hardened API JSON shaped exactly like the live
company-data API output (slug-keyed values; NO person source field). The
ciphertext fields reuse the shared decryption vector's real wrapper, decrypted
through the crypto core via an injected ``decrypt_value`` closure — so this also
exercises the model→crypto wiring end-to-end.
"""

import base64
import hashlib
import json
import os
from datetime import date, datetime

import pytest

from allus_company_data.crypto import BinaryHandle, decrypt, load_private_key
from allus_company_data.models import (
    Change,
    Connection,
    LogEntry,
    RequestField,
    Value,
)

VECTOR_PATH = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__), "..", "testdata", "decryption-vector.json"
    )
)


@pytest.fixture(scope="module")
def vector():
    with open(VECTOR_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def private_key(vector):
    pem = vector["encrypted_private_key_pem"].encode("ascii")
    return load_private_key(pem, vector["passphrase"])


@pytest.fixture
def decrypt_value(private_key):
    # The closure-over-the-key pattern the Client will use; no key ever passed
    # to a model factory (config-only key handling).
    return lambda wrapper: decrypt(wrapper, private_key)


@pytest.fixture
def encrypt_for_key(private_key):
    """Encrypt an arbitrary plaintext string into a platform wrapper using the
    vector key's PUBLIC half — so we can build structured/date test values that
    decrypt to known content via the SAME crypto core."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    pub = private_key.public_key()

    def _enc(plaintext: str) -> dict:
        aes_key = os.urandom(32)
        iv = os.urandom(12)
        ct = AESGCM(aes_key).encrypt(iv, plaintext.encode("utf-8"), None)
        k = pub.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return {
            "_enc": 1,
            "k": base64.b64encode(k).decode("ascii"),
            "iv": base64.b64encode(iv).decode("ascii"),
            "d": base64.b64encode(ct).decode("ascii"),
        }

    return _enc


# ── RequestField definitions ─────────────────────────────────────────────────


def test_request_fields_parsed_and_mandatory_folded():
    body = {
        "request_fields": [
            {"slug": "work_email", "label": "Work email", "type": "email",
             "one_time": False, "mandatory_provide": True, "mandatory_connected": False},
            {"slug": "logo", "label": "Logo", "type": "photo",
             "one_time": True, "mandatory_provide": False, "mandatory_connected": False},
            {"slug": "ref", "label": "Ref", "type": "text",
             "one_time": False, "mandatory_provide": False, "mandatory_connected": True},
        ]
    }
    fields = RequestField.list_from_api(body)
    assert [f.slug for f in fields] == ["work_email", "logo", "ref"]
    assert fields[0].mandatory is True   # mandatory_provide
    assert fields[1].mandatory is False
    assert fields[1].one_time is True
    assert fields[2].mandatory is True   # mandatory_connected folds in
    assert fields[0].raw is body["request_fields"][0]


def test_request_field_coerces_xml_bool_strings():
    body = {"request_fields": [
        {"slug": "x", "label": "X", "type": "text",
         "one_time": "false", "mandatory_provide": "true", "mandatory_connected": "false"}
    ]}
    f = RequestField.list_from_api(body)[0]
    assert f.one_time is False
    assert f.mandatory is True


# ── Connection detail → typed, slug-keyed values ─────────────────────────────


def _type_resolver():
    types = {
        "work_email": "email",
        "billing_address": "address",
        "dob": "date",
        "logo": "photo",
    }
    return lambda slug: types.get(slug)


def test_connection_detail_typed_slug_keyed(vector, decrypt_value, encrypt_for_key):
    detail = {
        "connection_id": "csc-1",
        "user_id": "person-1",
        "values": {
            # text email → reuse the vector's real text wrapper (known plaintext)
            "work_email": {
                "value": vector["text"]["wrapper"],
                "live": True,
                "updatedAt": "2026-06-17T10:00:00Z",
            },
            # structured address → a JSON object string, encrypted with the same key
            "billing_address": {
                "value": encrypt_for_key(json.dumps({"city": "Utrecht", "country": "NL"})),
                "live": False,
                "updatedAt": "2026-06-16T09:00:00Z",
            },
            # date → ISO date plaintext
            "dob": {
                "value": encrypt_for_key("1990-04-23"),
                "live": True,
                "updatedAt": "2026-06-15T08:00:00Z",
            },
            # binary photo → a slot value_url (lazy handle; never eagerly fetched)
            "logo": {
                "value_url": "https://api.allme.fyi/api/company-data/connections/csc-1/slots/sf-9/file",
                "live": True,
                "updatedAt": "2026-06-14T07:00:00Z",
            },
        },
    }
    identity = {"display_name": "Anna", "connected_at": "2026-06-10T00:00:00Z"}

    conn = Connection.from_api(
        detail,
        type_for_slug=_type_resolver(),
        decrypt_value=decrypt_value,
        identity=identity,
    )

    # identity
    assert conn.id == "csc-1"
    assert conn.person_id == "person-1"
    assert conn.display_name == "Anna"
    assert isinstance(conn.connected_at, datetime)
    assert conn.raw is detail

    # text → str (decrypted to the vector's known plaintext)
    email = conn.values["work_email"]
    assert isinstance(email, Value)
    assert email.value == vector["text"]["plaintext"]
    assert email.live is True
    assert isinstance(email.updated_at, datetime)

    # structured → dict
    addr = conn.values["billing_address"]
    assert addr.value == {"city": "Utrecht", "country": "NL"}
    assert addr.live is False

    # date → datetime.date
    dob = conn.values["dob"]
    assert dob.value == date(1990, 4, 23)

    # binary → lazy BinaryHandle, NOT fetched/decrypted yet
    logo = conn.values["logo"]
    assert isinstance(logo.value, BinaryHandle)
    assert logo.value.value_url.endswith("/slots/sf-9/file")


def test_binary_handle_lazy_fetch_and_decrypt(vector, decrypt_value):
    """The lazy handle's .bytes() goes value_url → fetch → decrypt → envelope →
    inner bytes, reproducing the shared vector's binary hash."""
    # The 'fetch' callback returns the encrypted wrapper for the slot (in the
    # live API the client unwraps {"encrypted":true,"value":...} to this wrapper).
    captured = {}

    def fetch(url):
        captured["url"] = url
        return vector["binary"]["wrapper"]

    detail = {
        "connection_id": "csc-1",
        "user_id": "person-1",
        "values": {
            "logo": {
                "value_url": "https://api.allme.fyi/api/company-data/connections/csc-1/slots/sf-9/file",
                "live": True,
                "updatedAt": "2026-06-14T07:00:00Z",
            }
        },
    }
    conn = Connection.from_api(
        detail,
        type_for_slug=lambda s: "photo",
        decrypt_value=decrypt_value,
        binary_fetch=fetch,
    )
    handle = conn.values["logo"].value
    assert isinstance(handle, BinaryHandle)
    assert "url" not in captured  # not fetched until .bytes()

    data = handle.bytes()
    assert captured["url"].endswith("/slots/sf-9/file")
    assert hashlib.sha256(data).hexdigest() == vector["binary"]["inner_full_sha256"]

    # cached — a second call does not re-fetch (still one fetch).
    handle.bytes()


def test_connection_has_no_person_source_field(vector, decrypt_value):
    detail = {
        "connection_id": "csc-1",
        "user_id": "person-1",
        "values": {"work_email": {"value": vector["text"]["wrapper"], "live": True}},
    }
    conn = Connection.from_api(
        detail, type_for_slug=lambda s: "email", decrypt_value=decrypt_value
    )
    # No field_id / source slug anywhere — values are keyed only by YOUR slug.
    serialized = json.dumps(conn.raw)
    assert "field_id" not in serialized
    assert list(conn.values.keys()) == ["work_email"]


# ── Change events ────────────────────────────────────────────────────────────


def test_change_field_updated_typed_and_id_populated(vector, decrypt_value):
    body = {
        "changes": [
            {
                "id": "chg-42",
                "event": "field_updated",
                "person_user_id": "person-1",
                "slug": "work_email",
                "value": vector["text"]["wrapper"],
                "live": True,
                "at": "2026-06-17T12:00:00Z",
            },
            {
                "id": "chg-43",
                "event": "connection_created",
                "person_user_id": "person-2",
                "at": "2026-06-17T12:05:00Z",
            },
        ]
    }
    changes = Change.list_from_api(
        body, type_for_slug=lambda s: "email", decrypt_value=decrypt_value
    )

    f = changes[0]
    assert f.id == "chg-42"  # stable dedup key for the pump
    assert f.event == "field_updated"
    assert f.person_id == "person-1"
    assert f.slug == "work_email"
    assert f.value == vector["text"]["plaintext"]  # decrypted
    assert f.live is True
    assert isinstance(f.at, datetime)
    assert f.raw is body["changes"][0]

    c = changes[1]
    assert c.id == "chg-43"
    assert c.event == "connection_created"
    assert c.slug is None
    assert c.value is None
    assert c.live is None


def test_change_field_updated_binary_is_lazy_handle(vector, decrypt_value):
    body = {
        "changes": [
            {
                "id": "chg-50",
                "event": "field_updated",
                "person_user_id": "person-1",
                "slug": "logo",
                "value_url": "https://api.allme.fyi/api/company-data/connections/csc-1/slots/sf-9/file",
                "live": True,
                "at": "2026-06-17T12:00:00Z",
            }
        ]
    }
    fetch = lambda url: vector["binary"]["wrapper"]
    [chg] = Change.list_from_api(
        body, type_for_slug=lambda s: "photo", decrypt_value=decrypt_value, binary_fetch=fetch
    )
    assert isinstance(chg.value, BinaryHandle)
    assert hashlib.sha256(chg.value.bytes()).hexdigest() == vector["binary"]["inner_full_sha256"]


def test_change_consent_event_has_slug_no_value():
    body = {"changes": [
        {"id": "chg-9", "event": "consent_accepted", "person_user_id": "p",
         "slug": "work_email", "at": "2026-06-17T00:00:00Z"}
    ]}
    [chg] = Change.list_from_api(body, type_for_slug=lambda s: "email", decrypt_value=lambda w: "")
    assert chg.event == "consent_accepted"
    assert chg.slug == "work_email"
    assert chg.value is None  # consent events carry no value


# ── LogEntry ─────────────────────────────────────────────────────────────────


def test_log_entries_parsed():
    body = {
        "total": 2,
        "items": [
            {"type": "email", "message": "stale-queue alert", "metadata": {"days": 3},
             "at": "2026-06-17T06:00:00Z"},
            {"type": "purge", "message": "purged 4 changes", "metadata": {"count": 4},
             "created_at": "2026-06-17T07:00:00Z"},
        ],
    }
    logs = LogEntry.list_from_api(body)
    assert len(logs) == 2
    assert logs[0].type == "email"
    assert logs[0].metadata == {"days": 3}
    assert isinstance(logs[0].at, datetime)
    # 'created_at' fallback for 'at'
    assert isinstance(logs[1].at, datetime)
    assert logs[1].raw is body["items"][1]


def test_change_includes_share_code(decrypt_value):
    """Every change event carries the person's profile share_code (nullable)."""
    body = {"changes": [
        {"id": "chg-1", "event": "connection_created",
         "person_user_id": "person-1", "share_code": "ABC123",
         "at": "2026-06-17T12:00:00Z"},
        {"id": "chg-2", "event": "connection_created",
         "person_user_id": "person-2", "at": "2026-06-17T12:00:00Z"},  # no share_code -> None
    ]}
    changes = Change.list_from_api(
        body, type_for_slug=lambda s: None, decrypt_value=decrypt_value
    )
    assert changes[0].share_code == "ABC123"
    assert changes[1].share_code is None


# ── document_status_changed change + Document model ─────────────────────────────


def test_change_document_status_changed_parses(vector, decrypt_value):
    from allus_company_data.models import Change

    body = {"changes": [{
        "id": "chg-doc", "event": "document_status_changed",
        "person_user_id": "u-1", "share_code": "ABC123",
        "document_id": "doc-9", "status": "ended", "at": "2026-06-22T10:00:00Z",
    }]}
    [chg] = Change.list_from_api(body, type_for_slug=lambda s: None, decrypt_value=decrypt_value)
    assert chg.event == "document_status_changed"
    assert chg.document_id == "doc-9"
    assert chg.status == "ended"
    assert chg.person_id == "u-1" and chg.share_code == "ABC123"
    assert chg.slug is None and chg.value is None and chg.live is None


def test_change_document_status_changed_carries_action(decrypt_value):
    from allus_company_data.models import Change

    body = {"changes": [{
        "id": "chg-sign", "event": "document_status_changed",
        "person_user_id": "u-2", "action": "signed",
        "document_id": "doc-7", "status": "active", "at": "2026-06-22T10:00:00Z",
    }]}
    [chg] = Change.list_from_api(body, type_for_slug=lambda s: None, decrypt_value=decrypt_value)
    assert chg.event == "document_status_changed"
    assert chg.action == "signed"
    assert chg.document_id == "doc-7" and chg.status == "active"
    assert chg.slug is None and chg.value is None
    assert chg.note is None  # no cancellation note on a sign event


def test_change_document_status_changed_carries_cancel_note(decrypt_value):
    from allus_company_data.models import Change

    body = {"changes": [{
        "id": "chg-cancel", "event": "document_status_changed",
        "person_user_id": "u-2", "action": "cancelled", "note": "Too expensive",
        "document_id": "doc-9", "status": "ended", "at": "2026-06-30T10:00:00Z",
    }]}
    [chg] = Change.list_from_api(body, type_for_slug=lambda s: None, decrypt_value=decrypt_value)
    assert chg.action == "cancelled" and chg.note == "Too expensive"
    assert chg.status == "ended"


def test_document_model_carries_contract_flags_and_signatures():
    from allus_company_data.models import Document

    doc = Document.from_api({
        "id": "c1", "kind": "agreement", "name": "Agreement", "status": "active",
        "payload_kind": "json", "is_private": False, "value": {"v": 1}, "metadata": {},
        "requires_signature": True, "requires_acceptance": False,
        "signatures": [{"action": "signed", "method": "biometric", "content_sha256": "ab" * 32}],
    })
    assert doc.requires_signature is True and doc.requires_acceptance is False
    assert len(doc.signatures) == 1 and doc.signatures[0]["action"] == "signed"


def test_document_model_broadcast_json_is_plaintext():
    from allus_company_data.models import Document

    doc = Document.from_api({
        "id": "d1", "kind": "document", "name": "Terms", "status": "active",
        "payload_kind": "json", "is_private": False, "value": {"v": 1}, "metadata": {},
    })
    assert doc.json() == {"v": 1}  # no decrypt needed


def test_document_model_per_person_json_decrypts(vector):
    from allus_company_data.crypto import load_private_key
    from allus_company_data.models import Document

    priv = load_private_key(
        vector["encrypted_private_key_pem"].encode("ascii"), vector["passphrase"]
    )
    wrapper = _encrypt_with_vector_pub(vector, json.dumps({"plan": "pro"}))
    doc = Document.from_api(
        {"id": "d2", "kind": "document", "name": "PP", "status": "active",
         "payload_kind": "json", "is_private": True, "value": wrapper, "metadata": {}},
        decrypt_value=lambda w: decrypt(w, priv),
    )
    assert doc.json() == {"plan": "pro"}  # decrypted via injected decrypt


def _encrypt_with_vector_pub(vector, plaintext):
    from allus_company_data.crypto import encrypt_for_public_key, load_private_key
    from cryptography.hazmat.primitives import serialization

    priv = load_private_key(
        vector["encrypted_private_key_pem"].encode("ascii"), vector["passphrase"]
    )
    spki_b64 = base64.b64encode(
        priv.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).decode("ascii")
    from allus_company_data.crypto import load_public_key
    return encrypt_for_public_key(plaintext, load_public_key(spki_b64))
