"""Shared field-type value validation.

Pure + i18n-free field-type validation, kept byte-aligned with the shared
cross-implementation contract by
``testdata/contract-field-validation-vector.json``. Spec:
``docs/superpowers/specs/2026-07-15-field-type-validation-design.html``.

Contract: :func:`is_field_value_valid(type, value) -> bool`. Empty value = valid
(required is the caller's job). Only present, non-empty sub-fields of a
structured type are checked. An unknown / ``text`` type accepts anything.

The SDK validates the PLAINTEXT before it is encrypted, at the value-submit
surfaces only (never on share / propagate).
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

from .country_data import COUNTRY_CODES, DIAL_CODES, US_STATE_CODES

# country/nationality store an ISO 3166-1 alpha-2 code; address state = USPS 2-letter code.
# The code lists come from the generated country data (do NOT inline them — they would rot).
_COUNTRY_CODE_SET = frozenset(COUNTRY_CODES)
_US_STATE_CODE_SET = frozenset(US_STATE_CODES)

_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_URL_RE = re.compile(r"^https?://[^\s/$.?#][^\s]*\.[^\s]{2,}$", re.IGNORECASE)
_MIME_RE = re.compile(r"^[\w.+-]+/[\w.+-]+$")
_PHONE_RE = re.compile(r"^\+?\d{4,15}$")
_CARD_RE = re.compile(r"^\d{12,19}$")
_URL_SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)
_PHONE_STRIP_RE = re.compile(r"[ \-().]")
_CARD_STRIP_RE = re.compile(r"[ -]")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

_GENDER = ("Male", "Female", "Non-binary", "Prefer not to say")

# structured types: each allowed key -> sub-rule. {} = any string; {"int": True} =
# JSON integer; {"re": ...} = string matching a regex; {"kind": ...} = reuse a kind.
_OBJ: dict[str, dict[str, dict]] = {
    "address": {
        "postal_code": {"re": re.compile(r"^[A-Za-z0-9][A-Za-z0-9 -]{1,9}$")},
        "country": {"kind": "countryCode"}, "state": {"kind": "usState"},
        "street": {}, "building_number": {}, "affix": {}, "city": {},
    },
    "creditcard": {
        "number": {"kind": "card"},
        "expiry": {"re": re.compile(r"^(0[1-9]|1[0-2])/\d{2}(\d{2})?$")},
        "cvc": {"re": re.compile(r"^\d{3,4}$")},
        "name": {},
    },
    "bank": {
        "swift": {"re": re.compile(r"^[A-Za-z]{6}[A-Za-z0-9]{2}([A-Za-z0-9]{3})?$")},
        "routing_number": {"re": re.compile(r"^\d{9}$")},
        "account_number": {"re": re.compile(r"^[A-Za-z0-9 ]{4,34}$")},
        "account_holder": {}, "bank_name": {},
    },
    "document": {
        "size": {"int": True}, "mime_type": {"re": _MIME_RE}, "name": {}, "file": {},
        "original_name": {},
    },
    "legal_document": {
        "size": {"int": True}, "expiry_date": {"kind": "date"}, "mime_type": {"re": _MIME_RE},
        "document_number": {}, "file": {}, "original_name": {},
    },
}

_RULES: dict[str, dict] = {
    "email": {"kind": "regex", "re": _EMAIL_RE},
    "phone": {"kind": "phone"},
    "url": {"kind": "url"},
    "date": {"kind": "date"}, "date_of_birth": {"kind": "date"},
    "gender": {"kind": "enum", "values": _GENDER},
    "address": {"kind": "object"}, "creditcard": {"kind": "object"}, "bank": {"kind": "object"},
    "document": {"kind": "object"}, "legal_document": {"kind": "object"},
    "number": {"kind": "number"}, "boolean": {"kind": "boolean"},
    "country": {"kind": "countryCode"}, "nationality": {"kind": "countryCode"},
    # text + unknown => no rule => accept anything
}

_DAYS_IN_MONTH = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def _luhn_ok(digits: str) -> bool:
    total = 0
    dbl = False
    for i in range(len(digits) - 1, -1, -1):
        d = ord(digits[i]) - 48
        if d < 0 or d > 9:
            return False
        if dbl:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        dbl = not dbl
    return total % 10 == 0


def _days_in_month(y: int, m: int) -> int:
    if m == 2:
        leap = (y % 4 == 0 and y % 100 != 0) or y % 400 == 0
        return 29 if leap else 28
    return _DAYS_IN_MONTH[m - 1]


def _valid_date(s: str) -> bool:
    if not _DATE_RE.match(s):
        return False
    y = int(s[0:4])
    m = int(s[5:7])
    d = int(s[8:10])
    if m < 1 or m > 12:
        return False
    if d < 1 or d > _days_in_month(y, m):
        return False
    return True


def _finite_number(value: str) -> bool:
    if value.strip() == "":
        return False
    try:
        n = float(value)
    except (TypeError, ValueError):
        return False
    return n == n and n not in (float("inf"), float("-inf"))


def _apply_kind(kind: str, value: str) -> bool:
    """Content checks reused by top-level rules AND structured sub-rules."""
    if kind == "phone":
        return bool(_PHONE_RE.match(_PHONE_STRIP_RE.sub("", value)))
    if kind == "url":
        u = value if _URL_SCHEME_RE.match(value) else f"https://{value}"
        return bool(_URL_RE.match(u))
    if kind == "date":
        return _valid_date(value)
    if kind == "card":
        s = _CARD_STRIP_RE.sub("", value)
        return bool(_CARD_RE.match(s)) and _luhn_ok(s)
    if kind == "number":
        return _finite_number(value)
    if kind == "boolean":
        return value == "true" or value == "false"
    if kind == "countryCode":
        return value in _COUNTRY_CODE_SET
    if kind == "usState":
        return value in _US_STATE_CODE_SET
    return True


def _valid_object(field_type: str, raw: str) -> bool:
    try:
        o = json.loads(raw)
    except (ValueError, TypeError):
        return False
    if not isinstance(o, dict):
        return False
    spec = _OBJ[field_type]
    for k, v in o.items():
        sub = spec.get(k)
        if sub is None:  # unknown key
            return False
        if sub.get("int"):
            # A JSON integer (but not a bool, which is an int subclass in Python).
            if isinstance(v, bool) or not isinstance(v, int):
                return False
            continue
        if not isinstance(v, str):
            return False
        if v == "":  # empty sub-field ok (partial fill)
            continue
        rx = sub.get("re")
        if rx is not None and not rx.match(v):
            return False
        kind = sub.get("kind")
        if kind is not None and not _apply_kind(kind, v):
            return False
    return True


def is_field_value_valid(field_type: Optional[str], value: Any) -> bool:
    """True if ``value`` is an acceptable plaintext for ``field_type``.

    Empty value is valid. An unknown / ``text`` type accepts anything.
    """
    s = "" if value is None else str(value)
    if s == "":
        return True
    rule = _RULES.get(field_type or "")
    if rule is None:
        return True
    kind = rule["kind"]
    if kind == "regex":
        return bool(rule["re"].match(s))
    if kind == "enum":
        return s in rule["values"]
    if kind == "object":
        return _valid_object(field_type, s)  # type: ignore[arg-type]
    return _apply_kind(kind, s)


def field_value_error(field_type: Optional[str], value: Any) -> Optional[str]:
    """``None`` when valid, else the ``field_type`` tag (for i18n error mapping)."""
    return None if is_field_value_valid(field_type, value) else (field_type or "")


def is_valid_country_code(code: Optional[str]) -> bool:
    """True if ``code`` is an assigned ISO 3166-1 alpha-2 country code."""
    return code in _COUNTRY_CODE_SET


def dial_code_for(code: Optional[str]) -> Optional[str]:
    """The ITU E.164 dial code (digits only, no ``+``) for a country code, or ``None``."""
    return DIAL_CODES.get(code or "")


__all__ = [
    "is_field_value_valid",
    "field_value_error",
    "is_valid_country_code",
    "dial_code_for",
]
