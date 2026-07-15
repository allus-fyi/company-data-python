"""Field-type value validation parity — every case in the shared vector must pass.

The same ``contract-field-validation-vector.json`` pins the web reference
(``frontend/src/fieldValidation.js``) and the iOS / Android / SDK ports; this
asserts the Python port agrees case-for-case.
"""

import json
import os

import pytest

from allus_company_data.field_validation import field_value_error, is_field_value_valid

VECTOR_PATH = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__), "..", "testdata", "contract-field-validation-vector.json"
    )
)


def _cases():
    with open(VECTOR_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)["cases"]


@pytest.mark.parametrize("case", _cases(), ids=lambda c: c["name"])
def test_vector_case(case):
    assert is_field_value_valid(case["type"], case["value"]) is case["valid"]


def test_vector_has_all_cases():
    # Guard against an accidental truncation of the committed vector.
    assert len(_cases()) == 100


def test_field_value_error_tag():
    assert field_value_error("email", "a@b.co") is None
    assert field_value_error("email", "nope") == "email"
    assert field_value_error("text", "anything") is None
