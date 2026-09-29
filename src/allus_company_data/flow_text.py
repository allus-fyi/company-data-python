"""The value tags a contract-flow TEXT element names.

Read by the platform's text grammar: HTML tags are removed first, ``\\[`` ``\\]`` ``\\{`` ``\\\\``
are escapes, and a ``{{…}}`` an escape breaks is not a tag. A tag inside a link address
(``[a href=X]``) is a tag too. A starter compiles the values of the definition's non-owner PARTY
tags before it starts a run (:meth:`Client.trigger_flow_run`).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

_HTML_TAG = re.compile(r"</?[a-zA-Z][^<>]*>")
_TAG_AT = re.compile(r"\{\{\s*([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){0,2})\s*\}\}", re.IGNORECASE)
_ESCAPABLE = "[]{\\"


def _address_closes(s: str, start: int) -> bool:
    i = start
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s) and s[i + 1] in _ESCAPABLE:
            i += 2
            continue
        if s[i] == "]":
            return True
        i += 1
    return False


def flow_text_tags(body: str) -> List[str]:
    """Every value-tag key a text body names — in its text and its link addresses — lower-cased, first use first."""
    s = _HTML_TAG.sub("", body or "")
    out: List[str] = []
    in_address = False
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s) and s[i + 1] in _ESCAPABLE:
            i += 2
            continue
        if c == "{":
            m = _TAG_AT.match(s, i)
            if m:
                k = m.group(1).lower()
                if k not in out:
                    out.append(k)
                i = m.end()
                continue
        if in_address and c == "]":
            in_address = False
            i += 1
            continue
        if not in_address and c == "[" and s[i:i + 8].lower() == "[a href=" and _address_closes(s, i + 8):
            in_address = True
            i += 8
            continue
        i += 1
    return out


@dataclass(frozen=True)
class PartyTag:
    """One non-owner party tag of a definition: the tag, its party key and its field (request slug)."""

    tag: str
    party: str
    field: str


def _body_of(el: dict) -> str:
    for k in ("body", "text", "label"):
        v = el.get(k)
        if isinstance(v, str) and v:
            return v
    return ""


def non_owner_party_tags(definition: dict) -> List[PartyTag]:
    """The definition's NON-OWNER party tags — the tags whose values a starter compiles and seals."""
    types = {}
    for p in (definition or {}).get("parties") or []:
        if isinstance(p, dict) and isinstance(p.get("key"), str):
            t = p.get("type")
            types[p["key"].lower()] = t if isinstance(t, str) and t else None
    out: List[PartyTag] = []
    for n in (definition or {}).get("nodes") or []:
        for el in (n.get("elements") or []) if isinstance(n, dict) else []:
            if not isinstance(el, dict) or el.get("kind") != "text":
                continue
            for tag in flow_text_tags(_body_of(el)):
                if "." not in tag:
                    continue
                party, field = tag.split(".", 1)
                if party not in types or types[party] == "owner":
                    continue
                if all(x.tag != tag for x in out):
                    out.append(PartyTag(tag=tag, party=party, field=field))
    return out
