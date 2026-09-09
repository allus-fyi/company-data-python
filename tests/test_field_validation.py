"""Field-type value validation parity — every case in the shared vector must pass.

The same ``contract-field-validation-vector.json`` pins the shared
cross-implementation contract; this asserts the Python port agrees case-for-case.
Its ``registry`` member is the row set every case is resolved against.
"""

import json
import os

import pytest

from allus_company_data.field_types import FieldTypeRegistry

VECTOR_PATH = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__), "..", "testdata", "contract-field-validation-vector.json"
    )
)


def _vector():
    with open(VECTOR_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _cases():
    return _vector()["cases"]


REGISTRY = FieldTypeRegistry(_vector()["registry"])


@pytest.mark.parametrize("case", _cases(), ids=lambda c: c["name"])
def test_vector_case(case):
    # ``options`` is the caller's own option list, present only on a choice case.
    assert (
        REGISTRY.is_field_value_valid(case["type"], case["value"], case.get("options"))
        is case["valid"]
    )


def test_vector_has_all_cases():
    # Guard against an accidental truncation of the committed vector.
    assert len(_cases()) == 177


@pytest.mark.parametrize("case", _vector()["resolve_cases"], ids=lambda c: c["name"])
def test_vector_resolve(case):
    assert REGISTRY.resolve(case["type"]) == case["resolved"]


@pytest.mark.parametrize("case", _vector()["accepts_cases"], ids=lambda c: c["name"])
def test_vector_accepts(case):
    assert REGISTRY.accepts(case["requested"], case["actual"]) is case["accepts"]


@pytest.mark.parametrize("case", _vector()["ordered_cases"], ids=lambda c: c["name"])
def test_vector_ordered(case):
    assert REGISTRY.ordered(case["types"]) == case["ordered"]


@pytest.mark.parametrize(
    "case", _vector()["effective_type_cases"], ids=lambda c: c["name"]
)
def test_vector_effective_type(case):
    assert REGISTRY.effective_type(case["type"]) == case["effective_type"]


def test_vector_derived_sets():
    sets = _vector()["derived_sets"]
    assert REGISTRY.requestable_types() == sets["requestable_types"]
    assert REGISTRY.flow_types() == sets["flow_types"]
    assert REGISTRY.claimable_types() == sets["claimable_types"]


def test_field_value_error_tag():
    assert REGISTRY.field_value_error("email", "a@b.co") is None
    assert REGISTRY.field_value_error("email", "nope") == "validation"
    assert REGISTRY.field_value_error("text", "anything") is None
