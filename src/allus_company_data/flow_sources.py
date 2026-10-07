"""A document leaf's participant PDF sources and the generation inputs they need.

A leaf output rule's PDF is a company template (``asset_key``), a flow field's answer
(``source_field: slug`` → source key ``field:<slug>``) or what a bound customer shared on its
connection (``source_connection: {party, request_slug}`` → ``conn:<party>:<request_slug>``).
The generating party uploads its own copy of every HELD source of the run's current leaf,
sealed under the call's one-time key, before it calls ``/generate``; the server refuses a
generate whose inputs are not exactly the held set.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from .crypto import new_one_time_key, one_time_key_bundle, one_time_key_seal
from .errors import ApiError


def sealed_string(sealed_value: Any) -> str:
    """A sealed wrapper as the JSON string a flow-answer or upload body carries."""
    return sealed_value if isinstance(sealed_value, str) else json.dumps(sealed_value)


def seal_answer_values(body: Any) -> Any:
    """``body`` with every ``answers[].values[].value`` sent as the sealed wrapper's JSON string.

    A value that already is a string, and everything else in the body, stays as it is; the
    caller's own structure is not modified.
    """
    answers = body.get("answers") if isinstance(body, dict) else None
    if not isinstance(answers, list):
        return body

    def seal_answer(a: Any) -> Any:
        values = a.get("values") if isinstance(a, dict) else None
        if not isinstance(values, list):
            return a
        return {
            **a,
            "values": [
                {**v, "value": sealed_string(v["value"])}
                if isinstance(v, dict) and v.get("value") is not None
                else v
                for v in values
            ],
        }

    return {**body, "answers": [seal_answer(a) for a in answers]}


def file_ref(value: Any) -> Optional[str]:
    """The file a plaintext ``{"_enc_file": file, …}`` answer value names, else ``None``.

    A captured, uploaded or frozen-linked file answer is that plaintext reference, never a
    ciphertext wrapper; every other answer value is a wrapper and answers ``None``.
    """
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return None
    if isinstance(value, dict):
        f = value.get("_enc_file")
        if isinstance(f, str) and f:
            return f
    return None


@dataclass(frozen=True)
class HeldSource:
    """One held participant source of the current leaf.

    ``kind`` is ``"field"`` (``slug`` the flow field, ``file`` the generating party's own answer
    file) or ``"conn"`` (``file`` the generating party's own copy made at run start).
    """

    source_key: str
    kind: str
    slug: Optional[str]
    file: str


def held_sources(
    definition: dict,
    node_key: Optional[str],
    answers: List[dict],
    own_user_id: Optional[str],
    source_files: Dict[str, str],
) -> List[HeldSource]:
    """The held set of the leaf ``node_key``, in rule order, each source key once.

    Reads every rule of every output of the leaf (a leaf with the older ``pdfs`` list carries
    template rules only). ``field:<slug>`` is held when the generating party's own answer copy
    for the slug (``for_user_id == own_user_id``) is a file reference; ``conn:<party>:<slug>``
    when ``source_files`` (the run read's own copies) names it.
    """
    node = next(
        (n for n in definition.get("nodes") or [] if isinstance(n, dict) and n.get("key") == node_key),
        None,
    )
    if node is None or not isinstance(node.get("outputs"), list):
        return []
    own_files: Dict[str, str] = {}
    for row in answers:
        if isinstance(row, dict) and own_user_id is not None and row.get("for_user_id") == own_user_id:
            f = file_ref(row.get("value"))
            if f is not None and isinstance(row.get("slug"), str):
                own_files[row["slug"]] = f
    out: List[HeldSource] = []
    seen = set()
    for output in node["outputs"]:
        rules = output.get("rules") if isinstance(output, dict) else None
        for rule in rules if isinstance(rules, list) else []:
            if not isinstance(rule, dict):
                continue
            field = rule.get("source_field")
            conn = rule.get("source_connection")
            if isinstance(field, str) and field:
                key = f"field:{field}"
                if key not in seen and field in own_files:
                    seen.add(key)
                    out.append(HeldSource(key, "field", field, own_files[field]))
            elif isinstance(conn, dict) and isinstance(conn.get("party"), str) and isinstance(conn.get("request_slug"), str):
                key = f"conn:{conn['party']}:{conn['request_slug']}"
                f = source_files.get(key)
                if key not in seen and isinstance(f, str) and f:
                    seen.add(key)
                    out.append(HeldSource(key, "conn", None, f))
    return out


def generate_with_inputs(
    post: Callable[[str, dict], Any],
    generate_path: str,
    answers: dict,
    held: List[HeldSource],
    envelope_of: Callable[[HeldSource], str],
) -> Any:
    """Upload each held source, then POST ``generate_path`` with ``{otk, values, inputs}``.

    ``envelope_of`` fetches and decrypts the generating party's own copy of one source to its
    envelope JSON string. Each envelope is sealed under the SAME one-time key as ``values`` and
    POSTed to ``{generate_path}/inputs`` as ``{source_key, value}`` → ``{input}``; ``inputs`` is
    ``[]`` when nothing is held.
    """
    otk = new_one_time_key()
    inputs = []
    for src in held:
        res = post(
            f"{generate_path}/inputs",
            {"source_key": src.source_key, "value": one_time_key_seal(otk, envelope_of(src))},
        )
        ident = res.get("input") if isinstance(res, dict) else None
        if not isinstance(ident, str) or not ident:
            raise ApiError(0, None, f"generate/inputs answered no input for {src.source_key}")
        inputs.append({"source_key": src.source_key, "input": ident})
    body = one_time_key_bundle(answers, otk)
    body["inputs"] = inputs
    return post(generate_path, body)


__all__ = ["HeldSource", "file_ref", "generate_with_inputs", "held_sources"]
