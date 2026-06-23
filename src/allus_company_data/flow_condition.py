"""Pure port of the platform ``FlowConditionEvaluator`` (A-spec §4).

A condition is one of:

* ``None`` / a non-object → always ``True`` (the "no condition" short-circuit).
* a boolean node ``{op: "and"|"or"|"not", children: [...]}`` (``not`` = exactly one child).
* a comparison leaf ``{field, op, value}`` with ``op`` in
  ``eq ne lt le gt ge in nin answered empty``.

``answers`` is the decrypted ``{slug: value}`` map.

Frozen semantics (pinned by ``contract-flow-condition-vector.json``):

* A blank/missing answer is "unanswered": it never satisfies ``eq``/``ne``/an
  ordered comparison (always ``False``); ``empty`` is ``True`` on it,
  ``answered`` is ``False``. ``nin`` is ``True`` on an unanswered field
  (it is not a member of the list).
* ``eq``/``ne``: booleans compare by truth, numbers (with numeric-string
  coercion) by value, otherwise strings compare exactly.
* ``in``/``nin``: membership in the array ``value`` via the same loose equality.
* Ordered comparisons (``lt``/``le``/``gt``/``ge``): if BOTH operands are numeric
  (number or numeric string) → numeric compare; if BOTH are non-numeric →
  string compare (so ``YYYY-MM-DD`` dates sort chronologically); a MIXED pair
  (one numeric, one not) → ``False``.
* ``and`` over ``[]`` → ``True``; ``or`` over ``[]`` → ``False``.

This is the single source of routing / show-if / option-availability across
web, iOS, Android, the PHP reference, and every SDK language.
"""

from __future__ import annotations

from typing import Any, Mapping

_BOOL_OPS = ("and", "or", "not")


def evaluate(condition: Any, answers: Mapping[str, Any]) -> bool:
    if condition is None:
        return True
    if not isinstance(condition, dict):
        return True
    op = condition.get("op")
    if op in _BOOL_OPS:
        kids = condition.get("children") or []
        if op == "and":
            return all(evaluate(c, answers) for c in kids)
        if op == "or":
            return any(evaluate(c, answers) for c in kids)
        return not evaluate(kids[0] if kids else None, answers)  # not

    slug = condition.get("field")
    target = condition.get("value")
    val = answers.get(slug)

    if op == "answered":
        return _answered(val)
    if op == "empty":
        return not _answered(val)
    if op == "in":
        return isinstance(target, list) and any(_loose_eq(x, val) for x in target)
    if op == "nin":
        return not (isinstance(target, list) and any(_loose_eq(x, val) for x in target))

    if not _answered(val):
        return False
    if op == "eq":
        return _loose_eq(target, val)
    if op == "ne":
        return not _loose_eq(target, val)
    if op in ("lt", "gt", "le", "ge"):
        a, b = _to_num(val), _to_num(target)
        if a is not None and b is not None:
            return {"lt": a < b, "gt": a > b, "le": a <= b, "ge": a >= b}[op]
        # Mixed (one numeric, one not) → False; both non-numeric → string compare.
        if a is not None or b is not None:
            return False
        sa, sb = _str(val), _str(target)
        return {"lt": sa < sb, "gt": sa > sb, "le": sa <= sb, "ge": sa >= sb}[op]
    return False


def _answered(v: Any) -> bool:
    return v is not None and not (isinstance(v, str) and v == "")


def _to_num(v: Any):
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str) and v.strip() != "":
        try:
            return float(v)
        except ValueError:
            return None
    return None


def _loose_eq(a: Any, b: Any) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return bool(a) == bool(b)
    na, nb = _to_num(a), _to_num(b)
    if na is not None and nb is not None:
        return na == nb
    return _str(a) == _str(b)


def _str(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return str(v)


__all__ = ["evaluate"]
