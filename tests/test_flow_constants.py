"""Flow-constants parity — every case in the shared constants vector must pass.

The same ``contract-flow-constants-vector.json`` pins the JS reference and the
web / iOS / Android / PHP ports; this asserts the Python ``compute_constants``
port agrees byte-for-byte. Sibling of ``test_flow_condition.py``.
"""

import json
import os

import pytest

from allus_company_data.flow_condition import (
    compute_constants,
    evaluate_flow_condition,
    resolved_constants,
)

_TESTDATA = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "testdata"))
VECTOR_PATH = os.path.join(_TESTDATA, "contract-flow-constants-vector.json")
CONDITION_VECTOR_PATH = os.path.join(_TESTDATA, "contract-flow-condition-vector.json")


def _cases():
    with open(VECTOR_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)["cases"]


def _condition_cases():
    with open(CONDITION_VECTOR_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)["cases"]


def _same(a, b):
    # Strict equality matching the vector: a bool is NOT a number, so True never
    # equals 1; None equals only None; numbers compare by value (6.0 == 6).
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    return a == b


@pytest.mark.parametrize("case", _cases(), ids=lambda c: c["name"])
def test_constants_vector_case(case):
    out = compute_constants(case["constants"], case["answers"], case["reference_date"])
    for key, expected in case["expect"].items():
        assert key in out, f"{case['name']}: constant {key!r} missing from result"
        assert _same(out[key], expected), (
            f"{case['name']}: {key} = {out[key]!r}, expected {expected!r}"
        )


@pytest.mark.parametrize("case", _cases(), ids=lambda c: c["name"])
def test_resolved_constants_is_constants_only(case):
    # resolved_constants returns the computed constant values ONLY — exactly the
    # vector's ``expect`` shape (declared constant keys, answers NOT folded in).
    out = resolved_constants(case["constants"], case["answers"], case["reference_date"])
    assert set(out.keys()) == set(case["expect"].keys())
    for key, expected in case["expect"].items():
        assert _same(out[key], expected), (
            f"{case['name']}: {key} = {out[key]!r}, expected {expected!r}"
        )


@pytest.mark.parametrize("case", _condition_cases(), ids=lambda c: c["name"])
def test_wrapper_preserves_condition_vector(case):
    # The 4-arg wrapper with no constants must behave exactly like ``evaluate``.
    assert evaluate_flow_condition(case["condition"], case["answers"]) is case["expect"]


def test_constants_vector_has_all_cases():
    # Guard: the committed vector is the 51-case set (catch an accidental truncation).
    assert len(_cases()) == 51
