"""Company-side contract-flow run methods — fully mocked (no live API).

Reuses test_client.py's FakeSession + the shared decryption vector key (written
to a temp PEM the Client loads). Exercises:

* trigger_flow_run / flow_runs / flow_run hit the right paths + parse FlowRun;
* _decrypt_run_answers decrypts ONLY the company's copies (for_user_id ==
  company_user_id) with the service key;
* submit_flow_answers produces one encrypted copy PER bound party (service key
  for the company, recipient key for the person) and the correct next_node/leaf
  from LOCAL evaluation of the graph;
* a document-mode leaf leaves the run generating, and generate_flow_document
  posts a valid {otk, values} (otk=32 bytes, values=base64(iv||ct||tag)) that
  round-trips back to the answer map;
* process_flow_run chains submit + generate on a company-leaf document flow.
"""

import base64
import json
import os

import pytest

from allus_company_data.client import Client
from allus_company_data.config import Config
from allus_company_data.crypto import load_private_key
from allus_company_data.http import HttpClient
from allus_company_data.models import FlowRun

from test_client import FakeResponse, FakeSession, _encrypt_for_key, _vector_pub_spki_b64

VECTOR_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "testdata", "decryption-vector.json")
)

COMPANY_UID = "company-1"
PERSON_UID = "person-1"


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
        client_id="svc_abc",
        client_secret="topsecret",
        service_private_key=str(pem),
        key_passphrase=vector["passphrase"],
        cache_dir=str(tmp_path / "cache"),
    )


def _client_rw(config, get_router, write_router):
    session = FakeSession(get_router, write_router)
    http = HttpClient(config, session=session)
    return Client(config, http=http), session


# A two-node, two-party flow: company node 'n1' → person node 'n2' (single edge),
# plus a branch off n1 to a leaf 'n_end' guarded by a value condition.
_DEF = {
    "output_mode": "data_only",
    "parties": [{"key": "company"}, {"key": "person"}],
    "nodes": [
        {"key": "n1", "party": "company"},
        {"key": "n2", "party": "person"},
        {"key": "n_end", "party": "person"},
    ],
    "edges": [
        # Ordered: the guarded edge is tried first (sort 0), the fallthrough second.
        {"from": "n1", "to": "n_end", "sort": 0, "condition": {"field": "tier", "op": "eq", "value": "vip"}},
        {"from": "n1", "to": "n2", "sort": 1, "condition": None},
    ],
}


def _run_obj(*, status="awaiting_company", current="n1", answers=None, definition=None, output_mode=None):
    d = dict(definition or _DEF)
    if output_mode is not None:
        d = {**d, "output_mode": output_mode}
    return {
        "id": "run-1",
        "flow_id": "flow-1",
        "flow_version": 3,
        "service_id": "svc-1",
        "connection_id": "csc-1",
        "company_user_id": COMPANY_UID,
        "bindings": {"company": COMPANY_UID, "person": PERSON_UID},
        "status": status,
        "current_node": current,
        "document_id": None,
        "output_mode": d.get("output_mode"),
        "definition": d,
        "answers": answers or [],
        "created_at": None,
        "updated_at": None,
    }


# ── trigger / list / get ──────────────────────────────────────────────────────


def test_trigger_flow_run(config):
    captured = {}

    def write_router(method, url, json_body, data):
        captured["method"] = method
        captured["url"] = url
        captured["body"] = json_body
        return FakeResponse(201, json_body=_run_obj())

    client, _ = _client_rw(config, _no_get, write_router)
    run = client.trigger_flow_run("flow-1", connection_id="csc-1",
                                  bindings={"company": COMPANY_UID, "person": PERSON_UID})
    assert captured["method"] == "POST"
    assert captured["url"].endswith("/company-data/flows/flow-1/runs")
    assert captured["body"]["target"] == {"connection_id": "csc-1"}
    assert captured["body"]["bindings"]["person"] == PERSON_UID
    assert isinstance(run, FlowRun)
    assert run.id == "run-1" and run.company_party_key == "company"
    assert run.service_user_id == COMPANY_UID


def test_flow_runs_default_awaiting_company(config):
    def get_router(url, params):
        assert url.endswith("/company-data/flow-runs")
        assert params == {"status": "awaiting_company"}
        return FakeResponse(200, json_body={"total": 1, "items": [_run_obj()]})

    client, _ = _client_rw(config, get_router, lambda *a: None)
    runs = client.flow_runs()
    assert len(runs) == 1 and runs[0].status == "awaiting_company"


def test_flow_run_by_id(config):
    def get_router(url, params):
        assert url.endswith("/company-data/flow-runs/run-1")
        return FakeResponse(200, json_body=_run_obj())

    client, _ = _client_rw(config, get_router, lambda *a: None)
    assert client.flow_run("run-1").current_node == "n1"


# ── decrypt only the company's copies ─────────────────────────────────────────


def test_decrypt_run_answers_only_company_copies(config, vector):
    company_wrapper = _encrypt_for_key(vector, "ACME BV")  # the company can read this
    answers = [
        {"slug": "company_name", "for_user_id": COMPANY_UID, "value": company_wrapper},
        # A person copy: same key here (test simplification) but for_user_id != company → skipped.
        {"slug": "company_name", "for_user_id": PERSON_UID, "value": company_wrapper},
        {"slug": "other", "for_user_id": "stranger", "value": company_wrapper},
    ]
    client, _ = _client_rw(config, _no_get, lambda *a: None)
    run = FlowRun.from_api(_run_obj(answers=answers))
    decoded = client._decrypt_run_answers(run)
    assert decoded == {"company_name": "ACME BV"}  # only the company's copy


# ── submit: per-party fan-out + local routing ─────────────────────────────────


def test_submit_fans_out_per_party_and_routes_fallthrough(config, vector):
    spki = _vector_pub_spki_b64(vector)

    def get_router(url, params):
        # The person public key is resolved via the connection's share_code.
        if url.endswith("/company-data/connections/csc-1"):
            return FakeResponse(200, json_body={"connection_id": "csc-1", "share_code": "ABC123"})
        if url.endswith("/api/keys/ABC123"):
            return FakeResponse(200, json_body={"public_key": spki})
        raise AssertionError("unexpected GET " + url)

    captured = {}

    def write_router(method, url, json_body, data):
        captured["url"] = url
        captured["body"] = json_body
        return FakeResponse(200, json_body=_run_obj(status="awaiting_person", current="n2"))

    client, _ = _client_rw(config, get_router, write_router)
    run = FlowRun.from_api(_run_obj())  # at n1 (company), no 'tier' → fallthrough to n2
    out = client.submit_flow_answers(run, {"company_name": "ACME BV"})

    body = captured["body"]
    assert captured["url"].endswith("/company-data/flow-runs/run-1/answers")
    # ONE answer, with a copy for EACH bound party (company + person).
    assert len(body["answers"]) == 1
    vals = body["answers"][0]["values"]
    assert {v["for_user_id"] for v in vals} == {COMPANY_UID, PERSON_UID}
    for v in vals:
        assert isinstance(v["value"], dict) and v["value"].get("_enc") == 1
    # The company's own copy round-trips with the service private key.
    priv = load_private_key(vector["encrypted_private_key_pem"].encode("ascii"), vector["passphrase"])
    from allus_company_data.crypto import decrypt as _decrypt
    company_copy = next(v for v in vals if v["for_user_id"] == COMPANY_UID)
    assert _decrypt(company_copy["value"], priv) == "ACME BV"
    # Local routing: no 'tier' answered → guarded edge fails → fallthrough n2 (a person node).
    assert body["next_node"] == "n2"
    assert body["next_party"] == "person"
    assert "leaf" not in body
    assert out.status == "awaiting_person"


def test_submit_routes_guarded_edge_when_condition_true(config, vector):
    spki = _vector_pub_spki_b64(vector)

    def get_router(url, params):
        if url.endswith("/company-data/connections/csc-1"):
            return FakeResponse(200, json_body={"connection_id": "csc-1", "share_code": "ABC123"})
        if url.endswith("/api/keys/ABC123"):
            return FakeResponse(200, json_body={"public_key": spki})
        raise AssertionError("unexpected GET " + url)

    captured = {}

    def write_router(method, url, json_body, data):
        captured["body"] = json_body
        return FakeResponse(200, json_body=_run_obj(status="awaiting_person", current="n_end"))

    client, _ = _client_rw(config, get_router, write_router)
    run = FlowRun.from_api(_run_obj())
    # Fill 'tier'='vip' → the guarded n1→n_end edge matches FIRST (sort 0), so the
    # submit routes to n_end (the current node n1 has edges, so this is not a leaf submit;
    # leaf-ness is about the CURRENT node having no outgoing edges, not the target).
    client.submit_flow_answers(run, {"tier": "vip"})
    assert captured["body"]["next_node"] == "n_end"
    assert "leaf" not in captured["body"]


def test_submit_uses_supplied_party_pubkeys_without_fetch(config, vector):
    """party_pubkeys lets the caller skip the share_code → /api/keys resolution."""
    priv = load_private_key(vector["encrypted_private_key_pem"].encode("ascii"), vector["passphrase"])
    person_pub = priv.public_key()  # reuse the vector key as the 'person' key for the test

    def get_router(url, params):
        raise AssertionError("no GET expected when party_pubkeys supplied: " + url)

    captured = {}

    def write_router(method, url, json_body, data):
        captured["body"] = json_body
        return FakeResponse(200, json_body=_run_obj(status="awaiting_person", current="n2"))

    client, _ = _client_rw(config, get_router, write_router)
    run = FlowRun.from_api(_run_obj())
    client.submit_flow_answers(run, {"company_name": "X"}, party_pubkeys={PERSON_UID: person_pub})
    vals = captured["body"]["answers"][0]["values"]
    assert {v["for_user_id"] for v in vals} == {COMPANY_UID, PERSON_UID}


# ── generate (document leaf) ──────────────────────────────────────────────────


def test_generate_flow_document_posts_otk_and_blob(config, vector):
    company_wrapper = _encrypt_for_key(vector, "ACME BV")
    answers = [{"slug": "company_name", "for_user_id": COMPANY_UID, "value": company_wrapper}]

    captured = {}

    def write_router(method, url, json_body, data):
        captured["url"] = url
        captured["body"] = json_body
        return FakeResponse(200, json_body={"document_id": "doc-9", "status": "awaiting_signature"})

    client, _ = _client_rw(config, _no_get, write_router)
    run = FlowRun.from_api(_run_obj(status="generating", current="n1", answers=answers,
                                    output_mode="document"))
    res = client.generate_flow_document(run)
    assert res == {"document_id": "doc-9", "status": "awaiting_signature"}
    assert captured["url"].endswith("/company-data/flow-runs/run-1/generate")

    otk = base64.b64decode(captured["body"]["otk"])
    blob = base64.b64decode(captured["body"]["values"])
    assert len(otk) == 32
    assert len(blob) >= 12 + 16  # iv(12) + at least the tag(16)
    # Reproduce the server's read: iv(12) || ct || tag(16), AES-256-GCM.
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    iv, ct_with_tag = blob[:12], blob[12:]
    plain = AESGCM(otk).decrypt(iv, ct_with_tag, None)
    assert json.loads(plain) == {"company_name": "ACME BV"}


# ── process_flow_run: chains submit + generate on a company-leaf document flow ─


def test_process_flow_run_company_leaf_document_chains_generate(config, vector):
    spki = _vector_pub_spki_b64(vector)
    # A single-node document flow: n1 is a company leaf (no outgoing edges).
    single = {
        "output_mode": "document",
        "parties": [{"key": "company"}, {"key": "person"}],
        "nodes": [{"key": "n1", "party": "company"}],
        "edges": [],
    }

    state = {"posts": []}

    def get_router(url, params):
        if url.endswith("/company-data/flow-runs/run-1"):
            # First load = awaiting_company at n1; after generate = awaiting_signature.
            status = "awaiting_signature" if state["posts"] else "awaiting_company"
            doc_id = "doc-9" if state["posts"] else None
            r = _run_obj(status=status, current="n1", definition=single, output_mode="document")
            r["document_id"] = doc_id
            return FakeResponse(200, json_body=r)
        if url.endswith("/company-data/connections/csc-1"):
            return FakeResponse(200, json_body={"connection_id": "csc-1", "share_code": "ABC123"})
        if url.endswith("/api/keys/ABC123"):
            return FakeResponse(200, json_body={"public_key": spki})
        raise AssertionError("unexpected GET " + url)

    def write_router(method, url, json_body, data):
        state["posts"].append(url)
        if url.endswith("/answers"):
            r = _run_obj(status="generating", current="n1", definition=single, output_mode="document")
            return FakeResponse(200, json_body=r)
        assert url.endswith("/generate")
        return FakeResponse(200, json_body={"document_id": "doc-9", "status": "awaiting_signature"})

    client, _ = _client_rw(config, get_router, write_router)
    run = client.process_flow_run("run-1", lambda node, answers: {"company_name": "ACME BV"})
    # Submitted answers, then chained generate, then reloaded → awaiting_signature.
    assert any(u.endswith("/answers") for u in state["posts"])
    assert any(u.endswith("/generate") for u in state["posts"])
    assert run.status == "awaiting_signature"
    assert run.document_id == "doc-9"


def test_process_flow_run_not_our_turn_returns_untouched(config):
    def get_router(url, params):
        return FakeResponse(200, json_body=_run_obj(status="awaiting_person", current="n2"))

    called = {"n": 0}

    def fill(node, answers):
        called["n"] += 1
        return {"x": "y"}

    client, _ = _client_rw(config, get_router, lambda *a: None)
    run = client.process_flow_run("run-1", fill)
    assert run.status == "awaiting_person"
    assert called["n"] == 0  # fill_node never invoked — not the company's turn


# helper imported lazily so the no-GET assertion message is clear
def _no_get(url, params):
    raise AssertionError("unexpected GET " + url)
