"""Country-data helpers.

What a value must satisfy for its field TYPE lives in
:mod:`allus_company_data.field_types`: a type is a row in the served registry and
:class:`~allus_company_data.field_types.FieldTypeRegistry` is the one interpreter of
those rows. These two helpers are about the bundled country dataset itself, which no
registry row carries.
"""

from __future__ import annotations

from typing import Optional

from .country_data import COUNTRY_CODES, DIAL_CODES

_COUNTRY_CODE_SET = frozenset(COUNTRY_CODES)


def is_valid_country_code(code: Optional[str]) -> bool:
    """True if ``code`` is an assigned ISO 3166-1 alpha-2 country code."""
    return code in _COUNTRY_CODE_SET


def dial_code_for(code: Optional[str]) -> Optional[str]:
    """The ITU E.164 dial code (digits only, no ``+``) for a country code, or ``None``."""
    return DIAL_CODES.get(code or "")


__all__ = [
    "is_valid_country_code",
    "dial_code_for",
]
