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

import json
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
# Pinned by ``contract-flow-constants-vector.json`` (62 cases).

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
        # max/min are variadic and skip what is not a number: only the args that coerce to a
        # FINITE number take part, so a None or text arg never nulls the whole result. They run
        # before the None guard below for exactly that reason; no numeric arg at all → None.
        if expr.get("op") in ("max", "min"):
            found = []
            for a in (expr.get("args") or []):
                n = _to_num(eval_expr(a, answers, reference_date))
                if n is not None and math.isfinite(n):
                    found.append(n)
            if not found:
                return None
            return max(found) if expr.get("op") == "max" else min(found)
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


def resolved_constants(
    constants: Any,
    answers: Mapping[str, Any],
    reference_date: Any,
    plugin_slugs: Any = None,
) -> dict:
    """Return the computed constant values ONLY — a ``{key: value}`` map.

    Convenience for reading a (data_only) run's constants: pass the pinned
    definition's ``constants`` list, the decrypted answers, and the run's
    immutable ``reference_date`` (``run.reference_date``). The answers are NOT
    folded into the result — one entry per declared constant key.

    ``plugin_slugs`` — the definition's plugin element slugs — expands every plugin
    answer first (``expand_plugin_answers``), so a constant can read ``slug``,
    ``slug.<block>`` and ``slug.<output>``; omit it when the flow has no plugin element.
    """
    source = expand_plugin_answers(answers, plugin_slugs) if plugin_slugs is not None else answers
    full = compute_constants(constants, source, reference_date)
    out: dict = {}
    for c in (constants if isinstance(constants, list) else []):
        if isinstance(c, dict) and isinstance(c.get("key"), str):
            out[c["key"]] = full.get(c["key"])
    return out


# ── Plugin answers. Pure; pinned by the shared constants vector. ───────────────────────────────
# A plugin answer's plaintext is a self-describing JSON object:
#   {"plugin","type","blocks":[{key,kind,label,id?,value}],"outputs":[{key,type,label,value}]}
# An answer without an ``outputs`` array is unfinished.

_PLUGIN_KEY = re.compile(r"^[a-z][a-z0-9_]{0,39}$")


def _parse_plugin_object(plaintext: Any):
    """The plaintext parsed as a JSON object, or None when it is not a string holding one."""
    if not isinstance(plaintext, str):
        return None
    try:
        parsed = json.loads(plaintext)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _plugin_key_ok(key: Any) -> bool:
    return isinstance(key, str) and key != "id" and _PLUGIN_KEY.fullmatch(key) is not None


def _plugin_summary(answer: dict) -> str:
    """The blocks' values in stored order, each stringified, joined by " / "."""
    blocks = answer.get("blocks") if isinstance(answer.get("blocks"), list) else []
    return " / ".join(_str(b.get("value") if isinstance(b, dict) else None) for b in blocks)


def expand_plugin_answers(answers: Mapping[str, Any], plugin_slugs: Any) -> dict:
    """Expand every plugin answer of ``answers`` into the keys a condition, a constant or a bound reads.

    Returns a NEW map; the input is not changed. For each slug of ``plugin_slugs`` whose answer
    is a string: a value that is not a JSON object is left as it is; a JSON object without an
    ``outputs`` array is an unfinished answer and its entry is REMOVED; a finished one is
    replaced by its summary (the blocks' values joined by " / ") and adds ``slug.<block>`` (the
    block's stored value), ``slug.<block>.id`` (a ``search_select`` block's picked id, as a
    string) and ``slug.<output>`` (the output's typed value). A block or output key that is
    ``id`` or does not match ``^[a-z][a-z0-9_]{0,39}$``, and a None value, add nothing. A slug
    not in ``plugin_slugs`` is never touched.
    """
    out = dict(answers or {})
    for slug in (plugin_slugs if isinstance(plugin_slugs, (list, tuple)) else []):
        if not isinstance(slug, str) or slug not in out:
            continue
        answer = _parse_plugin_object(out[slug])
        if answer is None:
            continue
        if not isinstance(answer.get("outputs"), list):
            del out[slug]
            continue
        out[slug] = _plugin_summary(answer)
        for b in (answer.get("blocks") if isinstance(answer.get("blocks"), list) else []):
            if not isinstance(b, dict) or not _plugin_key_ok(b.get("key")):
                continue
            key = b["key"]
            if b.get("value") is not None:
                out[f"{slug}.{key}"] = b["value"]
            if b.get("kind") == "search_select" and b.get("id") is not None:
                out[f"{slug}.{key}.id"] = _str(b["id"])
        for o in answer["outputs"]:
            if not isinstance(o, dict) or not _plugin_key_ok(o.get("key")):
                continue
            if o.get("value") is not None:
                out[f"{slug}.{o['key']}"] = o["value"]
    return out


def plugin_answer_summary(plaintext: Any):
    """A plugin answer's summary (its blocks' values joined by " / "), or None when it is unfinished or not one."""
    answer = _parse_plugin_object(plaintext)
    if answer is None or not isinstance(answer.get("outputs"), list):
        return None
    return _plugin_summary(answer)


def plugin_answer_view(plaintext: Any):
    """A plugin answer for display, or None.

    ``{"blocks": [{label, value}], "outputs": [{label, type, value}]}`` in stored order (a
    ``search_select`` block's value is its option label); None when the plaintext is not a
    JSON object with an ``outputs`` array.
    """
    answer = _parse_plugin_object(plaintext)
    if answer is None or not isinstance(answer.get("outputs"), list):
        return None

    def member(o: Any, name: str) -> Any:
        return o.get(name) if isinstance(o, dict) else None

    blocks = answer.get("blocks") if isinstance(answer.get("blocks"), list) else []
    return {
        "blocks": [{"label": member(b, "label"), "value": member(b, "value")} for b in blocks],
        "outputs": [
            {"label": member(o, "label"), "type": member(o, "type"), "value": member(o, "value")}
            for o in answer["outputs"]
        ],
    }


# ── Helpers the SDK's own flow code reads (not part of the package's public surface). ─────


def flow_number(v: Any):
    """The evaluator's own number coercion: a finite number, a numeric string, else None."""
    n = _to_num(v)
    return n if n is not None and math.isfinite(n) else None


def flow_date(v: Any):
    """The evaluator's strict ``YYYY-MM-DD`` reading, or None."""
    return _parse_flow_date(v)


def flow_string(v: Any) -> str:
    """The evaluator's own stringification."""
    return _str(v)


def flow_expr_refs(expr: Any) -> list:
    """Every key an expression reads: its ``ref`` keys and the fields of its ``if`` conditions."""
    acc: dict = {}

    def walk_cond(cond: Any) -> None:
        if not isinstance(cond, dict):
            return
        if cond.get("op") in _BOOL_OPS:
            for ch in (cond.get("children") or []):
                walk_cond(ch)
            return
        if isinstance(cond.get("field"), str):
            acc[cond["field"]] = True

    def walk(node: Any) -> None:
        if not isinstance(node, dict):
            return
        t = node.get("type")
        if t == "ref":
            if isinstance(node.get("key"), str):
                acc[node["key"]] = True
        elif t == "if":
            for cs in (node.get("cases") or []):
                if isinstance(cs, dict):
                    walk_cond(cs.get("when"))
                    walk(cs.get("then"))
            walk(node.get("else"))
        elif t == "concat":
            for p in (node.get("parts") or []):
                walk(p)
        elif t == "datediff":
            walk(node.get("from"))
            walk(node.get("to"))
        elif t == "math":
            for a in (node.get("args") or []):
                walk(a)

    walk(expr)
    return list(acc)


__all__ = [
    "evaluate",
    "eval_expr",
    "compute_constants",
    "evaluate_flow_condition",
    "resolved_constants",
    "expand_plugin_answers",
    "plugin_answer_summary",
    "plugin_answer_view",
]
