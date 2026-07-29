"""Verified fields — the SDK's automatic verified: bool on decrypted values."""
import hashlib
from allus_company_data.models import Value, Change


def _decrypt_plain(pt):
    # A trivial decrypt_value that returns the wrapper's inline plaintext (email is a str field).
    return lambda wrapper: pt


def test_value_verified_true_on_match():
    pt = "alice@example.com"
    salt = "0011223344556677"
    h = hashlib.sha256((salt + pt).encode("utf-8")).hexdigest()
    obj = {"value": pt, "live": True, "verified_hash": h, "verified_salt": salt}
    v = Value.from_api("email_personal", obj, field_type="email", decrypt_value=_decrypt_plain(pt))
    assert v.verified is True


def test_value_verified_false_on_mismatch():
    pt = "alice@example.com"
    salt = "0011223344556677"
    obj = {"value": pt, "live": True, "verified_hash": "deadbeef" * 8, "verified_salt": salt}
    v = Value.from_api("email_personal", obj, field_type="email", decrypt_value=_decrypt_plain(pt))
    assert v.verified is False


def test_value_verified_false_when_absent():
    pt = "alice@example.com"
    obj = {"value": pt, "live": True}
    v = Value.from_api("email_personal", obj, field_type="email", decrypt_value=_decrypt_plain(pt))
    assert v.verified is False


def test_change_field_updated_verified():
    pt = "bob@example.com"
    salt = "aabbccddeeff0011"
    h = hashlib.sha256((salt + pt).encode("utf-8")).hexdigest()
    obj = {"id": "c1", "event": "field_updated", "person_user_id": "u1", "slug": "email_personal",
           "value": pt, "verified_hash": h, "verified_salt": salt}
    ch = Change.from_api(obj, type_for_slug=lambda s: "email", decrypt_value=_decrypt_plain(pt))
    assert ch.verified is True
    # tamper the plaintext -> unverified
    obj2 = dict(obj, value="attacker@evil.com")
    ch2 = Change.from_api(obj2, type_for_slug=lambda s: "email", decrypt_value=_decrypt_plain("attacker@evil.com"))
    assert ch2.verified is False
