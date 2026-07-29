"""Pure port of the platform's flow condition evaluation semantics (A-spec §4).

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

This is the Python implementation of the shared routing / show-if /
option-availability contract, pinned by test vectors so every implementation
agrees byte-for-byte.
"""

from __future__ import annotations

import math
import re
from datetime import date
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
    # Substring ops (text): contains needs an answer (like in); not_contains is true
    # when unanswered (like nin). Case-sensitive; empty needle counts as contained.
    if op == "contains":
        return _answered(val) and _str(target) in _str(val)
    if op == "not_contains":
        return not (_answered(val) and _str(target) in _str(val))

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


# ── Flow constants (computed variables) ──────────────────────────────────────
# Pure port of the platform's constant-computation semantics. ``compute_constants`` materialises each
# constant into a NEW slug→value map (answers + {key: value}) in dependency
# order, so a condition leaf {field: <constKey>} resolves through the unchanged
# ``evaluate`` above. ``None`` propagates: an unresolved operand yields
# ``None``; a ``None`` constant behaves like an unanswered field in conditions.
# Pinned by ``contract-flow-constants-vector.json`` (51 cases).

_DATE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})$")


def _lit_value(expr: dict) -> Any:
    return expr.get("value")  # a missing "value" → None


def _parse_flow_date(v: Any):
    """Parse a strict ISO ``YYYY-MM-DD`` string as a calendar date, else None.

    ``datetime.date`` rejects impossible dates (2026-02-30 → ValueError), so no
    separate round-trip check is needed. Non-strings and non-ISO values → None.
    """
    if not isinstance(v, str):
        return None
    m = _DATE_RE.match(v.strip())
    if m is None:
        return None
    try:
        return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None


def _diff_days(frm: date, to: date) -> int:
    return (to - frm).days  # exact whole calendar days; sign follows to - from


def _diff_months(frm: date, to: date) -> int:
    n = (to.year - frm.year) * 12 + (to.month - frm.month)
    if to.day < frm.day:
        n -= 1
    return n


def _diff_years(frm: date, to: date) -> int:
    n = to.year - frm.year
    if (to.month, to.day) < (frm.month, frm.day):  # standard age boundary
        n -= 1
    return n


def _round_half_away(n: float) -> int:
    # Half away from zero: 2.5→3, -2.5→-3 (NOT Python's banker's ``round()``).
    return -math.floor(-n + 0.5) if n < 0 else math.floor(n + 0.5)


def _fin(r: Any):
    # Pinned non-finite policy: math never yields Infinity/NaN — overflow → None.
    return r if math.isfinite(r) else None


def eval_expr(expr: Any, answers: Mapping[str, Any], reference_date: Any) -> Any:
    """Evaluate one expr AST node against ``answers`` → value | None."""
    if not isinstance(expr, dict):
        return None
    t = expr.get("type")

    if t == "lit":
        return _lit_value(expr)

    if t == "ref":
        # Operand not in the map (absent, cycle back-edge, or stored None) → None.
        return answers.get(expr.get("key"))

    if t == "today":
        return reference_date if isinstance(reference_date, str) and reference_date != "" else None

    if t == "if":
        for cs in (expr.get("cases") or []):
            if isinstance(cs, dict) and evaluate(cs.get("when"), answers):
                return eval_expr(cs.get("then"), answers, reference_date)
        return eval_expr(expr.get("else"), answers, reference_date)  # else is required

    if t == "concat":
        sep = expr.get("sep")
        if not isinstance(sep, str):
            sep = ""
        parts = []
        for p in (expr.get("parts") or []):
            v = eval_expr(p, answers, reference_date)
            parts.append("" if v is None else _str(v))  # null part → ""
        return sep.join(parts)

    if t == "datediff":
        frm = _parse_flow_date(eval_expr(expr.get("from"), answers, reference_date))
        to = _parse_flow_date(eval_expr(expr.get("to"), answers, reference_date))
        if frm is None or to is None:  # non-date operand → None
            return None
        unit = expr.get("unit")
        if unit == "days":
            return _diff_days(frm, to)
        if unit == "weeks":
            return math.trunc(_diff_days(frm, to) / 7)  # toward zero (NOT flooring //)
        if unit == "months":
            return _diff_months(frm, to)
        if unit == "years":
            return _diff_years(frm, to)
        return None

    if t == "math":
        nums = [_to_num(eval_expr(a, answers, reference_date)) for a in (expr.get("args") or [])]
        # Any null / non-numeric (incl. bool) arg → None; a non-finite arg (a
        # string like "1e309" coercing to inf) → None (pinned non-finite policy).
        if any(n is None or not math.isfinite(n) for n in nums):
            return None
        op = expr.get("op")
        if op == "add":
            return _fin(sum(nums))  # identity 0, variadic
        if op == "mul":
            r = 1.0
            for n in nums:
                r *= n
            return _fin(r)  # identity 1, variadic
        if op == "sub":
            return _fin(nums[0] - nums[1]) if len(nums) >= 2 else None
        if op == "div":
            return _fin(nums[0] / nums[1]) if len(nums) >= 2 and nums[1] != 0 else None  # /0 → None
        if op == "mod":
            # Truncated remainder (JS %), NOT Python's flooring % — math.fmod.
            return _fin(math.fmod(nums[0], nums[1])) if len(nums) >= 2 and nums[1] != 0 else None
        if op == "neg":
            return _fin(-nums[0]) if nums else None
        if op == "abs":
            return _fin(abs(nums[0])) if nums else None
        if op == "round":
            return _fin(_round_half_away(nums[0])) if nums else None  # half away from zero
        if op == "floor":
            return _fin(math.floor(nums[0])) if nums else None
        if op == "ceil":
            return _fin(math.ceil(nums[0])) if nums else None
        return None

    return None


def _collect_cond_const_refs(cond: Any, const_keys: set, acc: dict) -> None:
    """Add constant keys named by a when-condition's {field} leaves (for ordering)."""
    if not isinstance(cond, dict):
        return
    if cond.get("op") in _BOOL_OPS:
        for ch in (cond.get("children") or []):
            _collect_cond_const_refs(ch, const_keys, acc)
        return
    f = cond.get("field")
    if isinstance(f, str) and f in const_keys:
        acc[f] = True


def _collect_expr_const_refs(expr: Any, const_keys: set, acc: dict) -> None:
    """Add the constant keys an expression (and its when-conditions) references.

    ``acc`` is a dict used as an insertion-ordered set, so dependency iteration
    is deterministic across ports (every language breaks the same cycle edge).
    """
    if not isinstance(expr, dict):
        return
    t = expr.get("type")
    if t == "ref":
        k = expr.get("key")
        if isinstance(k, str) and k in const_keys:
            acc[k] = True
        return
    if t in ("lit", "today"):
        return
    if t == "if":
        for cs in (expr.get("cases") or []):
            if isinstance(cs, dict):
                _collect_cond_const_refs(cs.get("when"), const_keys, acc)
                _collect_expr_const_refs(cs.get("then"), const_keys, acc)
        _collect_expr_const_refs(expr.get("else"), const_keys, acc)
        return
    if t == "concat":
        for p in (expr.get("parts") or []):
            _collect_expr_const_refs(p, const_keys, acc)
        return
    if t == "datediff":
        _collect_expr_const_refs(expr.get("from"), const_keys, acc)
        _collect_expr_const_refs(expr.get("to"), const_keys, acc)
        return
    if t == "math":
        for a in (expr.get("args") or []):
            _collect_expr_const_refs(a, const_keys, acc)
        return


def compute_constants(constants: Any, answers: Mapping[str, Any], reference_date: Any) -> dict:
    """Return a NEW map = ``answers`` + {key: value} for every constant.

    Constants are evaluated in topological (dependency) order via a 3-colour DFS
    over the constant→constant reference graph; declared array order is
    irrelevant. A ref to an operand not yet in the map resolves to None; None
    propagates. Cycles (rejected by the author-side validator) are broken
    defensively — a back-edge operand reads None.
    """
    out = dict(answers or {})
    lst = constants if isinstance(constants, list) else []
    by_key: dict = {}
    for c in lst:
        if isinstance(c, dict) and isinstance(c.get("key"), str):
            by_key[c["key"]] = c
    const_keys = set(by_key.keys())

    order: list = []
    state: dict = {}  # key → 0 visiting (grey) | 1 done (black)

    def visit(key: str) -> None:
        if key in state:  # grey (cycle back-edge → break) or black (done)
            return
        state[key] = 0
        deps: dict = {}  # insertion-ordered set (C8: deterministic iteration)
        _collect_expr_const_refs(by_key[key].get("expr"), const_keys, deps)
        for dep in deps:
            if dep in by_key:
                visit(dep)
        state[key] = 1
        order.append(key)  # post-order → dependencies precede dependents

    for c in lst:
        if isinstance(c, dict) and isinstance(c.get("key"), str):
            visit(c["key"])

    for key in order:
        out[key] = eval_expr(by_key[key].get("expr"), out, reference_date)
    return out


def evaluate_flow_condition(
    condition: Any,
    answers: Mapping[str, Any],
    constants: Any = None,
    reference_date: Any = None,
) -> bool:
    """Materialise constants, then evaluate the condition unchanged.

    Backward compatible: the old 2-arg call ``evaluate_flow_condition(cond, answers)``
    (the former alias for ``evaluate``) yields ``evaluate(cond, dict(answers))``,
    which is identical since ``evaluate`` only reads the map.
    """
    return evaluate(condition, compute_constants(constants, answers, reference_date))


def resolved_constants(constants: Any, answers: Mapping[str, Any], reference_date: Any) -> dict:
    """Return the computed constant values ONLY — a ``{key: value}`` map.

    Convenience for reading a (data_only) run's constants: pass the pinned
    definition's ``constants`` list, the decrypted answers, and the run's
    immutable ``reference_date`` (``run.reference_date``). The answers are NOT
    folded into the result — one entry per declared constant key.
    """
    full = compute_constants(constants, answers, reference_date)
    out: dict = {}
    for c in (constants if isinstance(constants, list) else []):
        if isinstance(c, dict) and isinstance(c.get("key"), str):
            out[c["key"]] = full.get(c["key"])
    return out


__all__ = [
    "evaluate",
    "eval_expr",
    "compute_constants",
    "evaluate_flow_condition",
    "resolved_constants",
]
