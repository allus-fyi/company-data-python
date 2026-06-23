"""FlowConditionEvaluator parity — every case in the shared vector must pass.

The same ``contract-flow-condition-vector.json`` pins the PHP reference and the
web / iOS / Android ports; this asserts the Python port agrees byte-for-byte.
"""

import json
import os

import pytest

from allus_company_data.flow_condition import evaluate

VECTOR_PATH = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__), "..", "testdata", "contract-flow-condition-vector.json"
    )
)


def _cases():
    with open(VECTOR_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)["cases"]


@pytest.mark.parametrize("case", _cases(), ids=lambda c: c["name"])
def test_vector_case(case):
    assert evaluate(case["condition"], case["answers"]) is case["expect"]


def test_vector_has_all_cases():
    # Guard: the committed vector is the 27-case set (catch an accidental truncation).
    assert len(_cases()) == 27
