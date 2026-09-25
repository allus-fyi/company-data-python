"""Plugin fields on a contract-flow step, from the company party's side.

A flow element of kind ``plugin`` asks a company-configured plugin: its blocks are answered by
picks and typed values, its inputs are wired to earlier flow keys, and its outputs come back
from the plugin. The SDK talks to the plugin through the platform's forwarder:

1. a PASS from the run's pass route (``{pass, forwarder_url, plugins, specs}``);
2. the request ``{field_type, op, block?, query?, picks, values, inputs, reply_key}`` sealed to
   the plugin's public key with the platform wrapper, ``reply_key`` being the public half of a
   fresh RSA-2048 pair made for the call;
3. ``POST {forwarder_url}/call`` ``{pass, plugin_id, request}`` over a PLAIN transport — the API
   client attaches the bearer token and rebuilds paths against the API base, so it must never
   carry this call;
4. the reply ``{reply}`` opened with the private half of the reply pair.

Inputs and bounds are read from ONE live answer map: the run's answers this party can read,
overlaid with the caller's draft for the current step's slugs, plugin answers expanded,
constants computed. Another party's private value is never sent to a plugin.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Set

import requests

from .crypto import (
    DecryptError,
    decrypt,
    encrypt_for_public_key,
    generate_reply_key_pair,
    load_public_key,
)
from .errors import ApiError, ConfigError, PluginInputUnavailable, ValidationError
from .flow_condition import (
    compute_constants,
    eval_expr,
    expand_plugin_answers,
    flow_date,
    flow_expr_refs,
    flow_number,
    flow_string,
)


# ── the pass and the reply shapes ─────────────────────────────────────────────


@dataclass
class PluginPass:
    """A short-lived pass for the plugins of the run's current step.

    ``plugins`` lists ``{"id", "public_key"}`` — ``public_key`` is None while the plugin's
    description is missing or failed; ``specs`` maps a slug to the plugin field's spec
    ``{plugin_id, field_type, snapshot, inputs}``. Calls go to ``POST {forwarder_url}/call``.
    """

    pass_: str
    forwarder_url: str
    plugins: List[dict] = field(default_factory=list)
    specs: Dict[str, dict] = field(default_factory=dict)
    raw: dict = field(default_factory=dict, repr=False)

    @classmethod
    def from_api(cls, body: Any) -> "PluginPass":
        body = body if isinstance(body, dict) else {}
        plugins = []
        for p in body.get("plugins") or []:
            if isinstance(p, dict) and p.get("id") is not None:
                key = p.get("public_key")
                plugins.append({"id": str(p["id"]), "public_key": key if isinstance(key, str) and key else None})
        specs = {k: v for k, v in (body.get("specs") or {}).items() if isinstance(v, dict)} if isinstance(body.get("specs"), dict) else {}
        return cls(
            pass_=str(body.get("pass") or ""),
            forwarder_url=str(body.get("forwarder_url") or ""),
            plugins=plugins,
            specs=specs,
            raw=body,
        )

    def public_key_of(self, plugin_id: str) -> Optional[str]:
        for p in self.plugins:
            if p["id"] == plugin_id:
                return p["public_key"]
        return None


@dataclass
class PluginOptions:
    """A plugin's option list for one block (``[{"id", "label"}]``); ``more`` says the list was cut."""

    options: List[dict]
    more: bool
    raw: dict = field(default_factory=dict, repr=False)

    @classmethod
    def from_reply(cls, reply: dict) -> "PluginOptions":
        options = []
        for o in reply.get("options") or []:
            if isinstance(o, dict) and o.get("id") is not None:
                options.append({"id": str(o["id"]), "label": "" if o.get("label") is None else str(o["label"])})
        return cls(options=options, more=reply.get("more") is True, raw=reply)


@dataclass
class PluginOutputs:
    """A plugin's outputs for the picks and inputs sent, typed as the plugin declared them."""

    outputs: Dict[str, Any]
    raw: dict = field(default_factory=dict, repr=False)
    picks_invalid: bool = False


@dataclass
class PluginPicksInvalid:
    """The plugin answered that the picks no longer fit the current inputs or each other.

    Clear the picks, pick again, and call ``plugin_outputs`` again before submitting.
    """

    raw: dict = field(default_factory=dict, repr=False)
    picks_invalid: bool = True


# ── the party's view of a run ─────────────────────────────────────────────────


@dataclass
class FlowPartyView:
    """What a party can read of a run — the inputs to the live answer map and the privacy rules."""

    definition: dict
    current_node: Optional[str]
    reference_date: Optional[str]
    stored: Dict[str, Any]              # the run's answers this party can read, decrypted
    private_slugs: Optional[List[str]]  # the run's private_slugs; None = unknown
    own_party_keys: Set[str]            # the party keys bound to the caller


def _nodes(definition: dict) -> List[dict]:
    return [n for n in (definition.get("nodes") or []) if isinstance(n, dict)]


def _elements(node: dict) -> List[dict]:
    return [e for e in (node.get("elements") or []) if isinstance(e, dict)]


def plugin_slugs_of(definition: dict) -> List[str]:
    """The slugs of every plugin element of the definition."""
    return [
        el["slug"]
        for n in _nodes(definition)
        for el in _elements(n)
        if el.get("kind") == "plugin" and isinstance(el.get("slug"), str)
    ]


def _node_elements(definition: dict, node_key: Optional[str]) -> Dict[str, dict]:
    """The field and plugin elements of one node, by slug."""
    out: Dict[str, dict] = {}
    for n in _nodes(definition):
        if n.get("key") != node_key:
            continue
        for el in _elements(n):
            if el.get("kind") in ("field", "plugin") and isinstance(el.get("slug"), str):
                out[el["slug"]] = el
    return out


def _element_node(definition: dict, slug: str):
    """The node an element slug sits on, with the element → ``(node, element)`` or None."""
    for n in _nodes(definition):
        for el in _elements(n):
            if el.get("slug") == slug and el.get("kind") in ("field", "plugin"):
                return n, el
    return None


def _current_draft(view: FlowPartyView, draft: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """The draft entries that belong to the current step; everything else is ignored."""
    own = _node_elements(view.definition, view.current_node)
    return {slug: v for slug, v in (draft or {}).items() if slug in own}


def live_answer_map(view: FlowPartyView, draft: Optional[Mapping[str, Any]] = None) -> dict:
    """The ONE live answer map.

    The answers the party can read, overlaid with the draft for the current step's slugs,
    plugin answers expanded, constants computed at the run's reference date.
    """
    merged = dict(view.stored)
    merged.update(_current_draft(view, draft))
    expanded = expand_plugin_answers(merged, plugin_slugs_of(view.definition))
    return compute_constants(view.definition.get("constants"), expanded, view.reference_date)


def _constants_by_key(definition: dict) -> Dict[str, dict]:
    return {
        c["key"]: c
        for c in (definition.get("constants") or [])
        if isinstance(c, dict) and isinstance(c.get("key"), str)
    }


def _draft_source_refs(definition: dict, slug: str) -> List[str]:
    """The keys a current-step draft value is derived from: a field's ``default`` refs.

    A plugin answer derives from nothing here — its outputs are never private, whatever inputs
    produced them.
    """
    found = _element_node(definition, slug)
    if found is None or found[1].get("kind") != "field":
        return []
    default = found[1].get("default")
    return [] if default is None else flow_expr_refs(default)


def _is_private_source(key: str, view: FlowPartyView, draft: Mapping[str, Any], seen: Optional[set] = None) -> bool:
    """Whether a flow key's value is private to someone else, fail-closed.

    A constant is private when any key it reads is. A key on the current step taken from the
    draft is private only when its field's default reads a private source — whatever the draft
    value is; a plugin answer is never private. Any other key is private when its slug is in ``private_slugs``; with no ``private_slugs`` list,
    a key another party answered is private.
    """
    seen = set() if seen is None else seen
    if key in seen:
        return False
    seen.add(key)
    constant = _constants_by_key(view.definition).get(key)
    if constant is not None:
        return any(_is_private_source(ref, view, draft, seen) for ref in flow_expr_refs(constant.get("expr")))
    base = key.split(".")[0]
    if base in draft:
        return any(_is_private_source(ref, view, draft, seen) for ref in _draft_source_refs(view.definition, base))
    if view.private_slugs is not None:
        return base in view.private_slugs or key in view.private_slugs
    found = _element_node(view.definition, base)
    party = found[0].get("party") if found is not None else None
    return party is None or str(party) not in view.own_party_keys


def is_draft_private(view: FlowPartyView, slug: str, draft: Mapping[str, Any]) -> bool:
    """Whether a value the party submits for ``slug`` is private.

    Its field's default reads a private source. A plugin answer never is. ``draft`` holds the
    submitted slugs.
    """
    own = _current_draft(view, draft)
    if slug not in own:
        return False
    return _is_private_source(slug, view, own)


_UNCONVERTED = object()


def _convert_input(input_type: Any, value: Any) -> Any:
    """Convert a value to a plugin input's declared type, or ``_UNCONVERTED``."""
    if input_type == "number":
        n = flow_number(value)
        if n is None:
            return _UNCONVERTED
        # A whole number travels as a JSON integer.
        return int(n) if n.is_integer() else n
    if input_type == "date":
        return value.strip() if isinstance(value, str) and flow_date(value) is not None else _UNCONVERTED
    if input_type == "boolean":
        if isinstance(value, bool):
            return value
        if value == "true":
            return True
        if value == "false":
            return False
        return _UNCONVERTED
    if input_type == "text":
        return flow_string(value)
    return _UNCONVERTED


def _resolve_inputs(spec: dict, live: Mapping[str, Any], view: FlowPartyView, draft: Mapping[str, Any]) -> dict:
    """The inputs of a plugin call, each converted to its declared type.

    A REQUIRED input that is unwired, unanswered, another party's private value or not
    convertible raises :class:`PluginInputUnavailable`; an OPTIONAL one is left out of the call.
    """
    snapshot = spec.get("snapshot") if isinstance(spec.get("snapshot"), dict) else {}
    wiring = spec.get("inputs") if isinstance(spec.get("inputs"), dict) else {}
    out: dict = {}
    for d in snapshot.get("inputs") or []:
        if not isinstance(d, dict) or not isinstance(d.get("key"), str):
            continue
        key = d["key"]
        required = d.get("required") is True
        ref = wiring.get(key)
        reason = None
        source = ref if isinstance(ref, str) and ref else None
        if source is None:
            reason = "unwired"
        else:
            raw = live.get(source)
            if raw is None or raw == "":
                reason = "unanswered"
            elif _is_private_source(source, view, draft):
                reason = "other_party_private"
            else:
                converted = _convert_input(d.get("type"), raw)
                if converted is _UNCONVERTED:
                    reason = "not_convertible"
                else:
                    out[key] = converted
        if reason is not None and required:
            raise PluginInputUnavailable(key, source, reason)
    return out


@dataclass
class PreparedPluginCall:
    """What one plugin call needs, resolved from the run and its pass."""

    plugin_id: str
    field_type: str
    inputs: dict


def prepare_plugin_call(
    view: FlowPartyView, pass_: PluginPass, slug: str, draft: Optional[Mapping[str, Any]] = None
) -> PreparedPluginCall:
    """Resolve the plugin element ``slug`` of the current step.

    Its spec comes from the pass, else the pinned definition; its inputs are read from the
    live answer map.
    """
    element = _node_elements(view.definition, view.current_node).get(slug)
    if element is None or element.get("kind") != "plugin":
        raise ConfigError(f"{slug!r} is not a plugin field on the run's current step")
    spec = pass_.specs.get(slug) or (element.get("plugin") if isinstance(element.get("plugin"), dict) else None)
    if spec is None or spec.get("plugin_id") is None or spec.get("field_type") is None:
        raise ConfigError(f"plugin field {slug!r} carries no plugin spec")
    own = _current_draft(view, draft)
    inputs = _resolve_inputs(spec, live_answer_map(view, own), view, own)
    return PreparedPluginCall(plugin_id=str(spec["plugin_id"]), field_type=str(spec["field_type"]), inputs=inputs)


# ── bounds ────────────────────────────────────────────────────────────────────


def check_flow_bounds(definition: dict, slug: str, value: Any, live: Mapping[str, Any], reference_date: Any) -> None:
    """Refuse a value outside its flow field's ``min``/``max``, each computed over the live answer map.

    A bound that computes to None is no bound. Numbers compare as numbers and dates as
    dates; a value that is neither is left to type validation. Raises
    :class:`ValidationError` naming the bound (``bound``, ``bound_value``).
    """
    found = _element_node(definition, slug)
    if found is None or found[1].get("kind") != "field":
        return
    element = found[1]
    field_type = element.get("field_type")
    for which in ("min", "max"):
        expr = element.get(which)
        if expr is None:
            continue
        bound = eval_expr(expr, live, reference_date)
        if bound is None or isinstance(bound, bool):
            continue
        outside = None
        bn = flow_number(bound)
        if bn is not None:
            vn = flow_number(value)
            if vn is not None:
                outside = vn < bn if which == "min" else vn > bn
        else:
            bd, vd = flow_date(bound), flow_date(value)
            if bd is not None and vd is not None:
                outside = vd < bd if which == "min" else vd > bd
        if outside:
            raise ValidationError(slug, field_type, which, bound)


# ── the forwarder call ────────────────────────────────────────────────────────


def _post_forwarder(forwarder_url: str, payload: dict):
    """POST to the forwarder with a plain request: no bearer token, and the URL exactly as the pass named it."""
    try:
        resp = requests.post(
            f"{forwarder_url}/call",
            data=json.dumps(payload),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        raise ApiError(0, None, f"request to the plugin forwarder failed: {exc}") from exc
    try:
        body = resp.json() if resp.content else None
    except ValueError:
        body = None
    return resp.status_code, body if isinstance(body, dict) else {}


def call_plugin(
    first_pass: PluginPass,
    renew_pass: Callable[[], PluginPass],
    call: PreparedPluginCall,
    request: dict,
) -> dict:
    """One plugin call: seal, post, open.

    A ``409 plugin.key_changed`` reseals once with the key it returns; a 401 or 403 fetches a
    new pass once. Every other refusal surfaces as an :class:`ApiError` carrying the
    forwarder's status and key (``plugin.not_responding``, ``plugin.busy``,
    ``plugin.rate_limited``, ``plugin.unavailable``, …).
    """
    reply_private, reply_spki = generate_reply_key_pair()
    plaintext = json.dumps({**request, "field_type": call.field_type, "inputs": call.inputs, "reply_key": reply_spki})
    pass_ = first_pass
    public_key = pass_.public_key_of(call.plugin_id)
    resealed = renewed = False
    while True:
        if public_key is None:
            raise ApiError(0, "plugin.not_responding", f"plugin {call.plugin_id} publishes no usable key")
        sealed = json.dumps(encrypt_for_public_key(plaintext, load_public_key(public_key)))
        status, body = _post_forwarder(pass_.forwarder_url, {"pass": pass_.pass_, "plugin_id": call.plugin_id, "request": sealed})
        error_key = body.get("error_key") if isinstance(body.get("error_key"), str) else None
        if status == 200:
            wrapper = body.get("reply")
            if not isinstance(wrapper, (str, dict)):
                raise DecryptError("plugin reply carries no sealed reply")
            plain = decrypt(wrapper, reply_private)
            try:
                opened = json.loads(plain)
            except ValueError as exc:
                raise DecryptError("plugin reply plaintext is not valid JSON") from exc
            if not isinstance(opened, dict):
                raise DecryptError("plugin reply plaintext must be a JSON object")
            return opened
        if status == 409 and error_key == "plugin.key_changed" and not resealed and isinstance(body.get("public_key"), str):
            public_key = body["public_key"]
            resealed = True
            continue
        if status in (401, 403) and not renewed:
            pass_ = renew_pass()
            public_key = pass_.public_key_of(call.plugin_id)
            renewed = True
            continue
        details = {k: v for k, v in body.items() if k not in ("error", "error_key")}
        message = body.get("error")
        raise ApiError(status, error_key, None if message is None else str(message), details)


def outputs_result(reply: dict):
    """Turn an ``outputs`` reply into :class:`PluginOutputs` or :class:`PluginPicksInvalid`."""
    if reply.get("picks_invalid") is True:
        return PluginPicksInvalid(raw=reply)
    outputs = reply.get("outputs")
    return PluginOutputs(outputs=dict(outputs) if isinstance(outputs, dict) else {}, raw=reply)


__all__ = [
    "PluginPass",
    "PluginOptions",
    "PluginOutputs",
    "PluginPicksInvalid",
]
