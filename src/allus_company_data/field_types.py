"""The field-type registry — the whole of what a contact-field TYPE means.

A type is a ROW, not a literal: the row says what its parent is, which primitive
draws it, which named check verifies it, which additive regexes it must match,
which sub-fields it carries and on which storage lane its value lives. The rows
are served by ``GET /api/contact-field-types``; this module interprets them, so
adding a type that reuses existing primitives and checks is a row and nothing
else.

TWO FIXED VOCABULARIES, and only these two are code. :data:`INPUTS` names the
editor a value is drawn with and :data:`CHECKS` what is verified beyond a regex;
a row may only name a member of each, so a new member is code here rather than
data.

INHERITANCE. A child inherits any column it leaves ``None`` from its nearest
ancestor that sets it — ``input``, ``lane``, ``check``, ``options``, ``fields``.
``validation`` is the exception and is ADDITIVE: a value must match the regex of
every ancestor that has one, root first, plus the type's own.
:meth:`FieldTypeRegistry.resolve` answers the row with every inherited column
filled in and the validations in that order, and every consumer works on that
resolved definition rather than on a raw row.

Pinned case-for-case by ``testdata/contract-field-validation-vector.json``.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Pattern, Sequence

from .country_data import COUNTRY_CODES, US_STATE_CODES

# The storage lanes a value can live on. ``inline`` is the value itself; the other
# two are files.
LANES = ("inline", "photo", "document")

# The drawing primitives a row may name. A new member is code here, not a row.
INPUTS = (
    "line",
    "date",
    "list",
    "multilist",
    "country",
    "nationality",
    "state",
    "phone",
    "composite",
    "file",
    "pages",
)

# The named checks a row may name — verification beyond a regex. A new member is code
# here, not a row.
CHECKS = ("url", "card", "number", "integer", "decimal", "float")

# The lanes each primitive can store on. ``file`` is the only primitive with a
# choice, which is why a root with that input is the only row whose lane an
# operator picks.
INPUT_LANES: Dict[str, Sequence[str]] = {
    "line": ("inline",),
    "date": ("inline",),
    "list": ("inline",),
    "multilist": ("inline",),
    "country": ("inline",),
    "nationality": ("inline",),
    "state": ("inline",),
    "phone": ("inline",),
    "composite": ("inline",),
    "file": ("photo", "document"),
    "pages": ("document",),
}

# The primitives a sub-field entry may name: no composite nesting and no binary.
ENTRY_INPUTS = ("line", "date", "list", "country", "nationality", "state", "phone")

# The members a ``file``/``pages`` envelope carries itself. They belong to the
# primitive, so a ``fields`` entry may never claim one — the entries are the extra
# metadata beside them.
ENVELOPE_MEMBERS = (
    "file",
    "pages",
    "original_name",
    "mime_type",
    "size",
    "name",
    "full",
    "thumb",
)

_COUNTRY_CODE_SET = frozenset(COUNTRY_CODES)
_US_STATE_CODE_SET = frozenset(US_STATE_CODES)

_URL_RE = re.compile(r"^https?://[^\s/$.?#][^\s]*\.[^\s]{2,}$", re.IGNORECASE)
_URL_SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)
_MIME_RE = re.compile(r"^[\w.+-]+/[\w.+-]+$")
_PHONE_RE = re.compile(r"^\+?\d{4,15}$")
_PHONE_STRIP_RE = re.compile(r"[ \-().]")
_CARD_RE = re.compile(r"^\d{12,19}$")
_CARD_STRIP_RE = re.compile(r"[ -]")
# Numeric grammars accept ASCII digits only, so a hex literal, an Infinity/NaN
# spelling or a Unicode digit is refused rather than accepted by the language's own
# numeric reader.
_INTEGER_RE = re.compile(r"^-?[0-9]+$")
# decimal(10,2) is a FIXED shape: up to 8 integer digits + up to 2 decimal digits.
_DECIMAL_RE = re.compile(r"^-?[0-9]{1,8}(\.[0-9]{1,2})?$")
# Float accepts decimal or scientific notation.
_FLOAT_RE = re.compile(r"^-?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

_DAYS_IN_MONTH = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)

# The members ONE page of a ``pages`` envelope may carry.
PAGE_MEMBERS = ("label", "file", "original_name", "mime_type", "size")

# The page slots the multi-page upload draws: a front, an optional back, repeatable
# extras.
PAGE_LABELS = ("front", "back", "additional")

# The longest a stored ``validation`` regex may be.
MAX_VALIDATION_LENGTH = 200

# Compiled stored regexes, keyed by the raw pattern. ``False`` records a pattern
# this engine cannot compile, so it is attempted once rather than per value.
_COMPILED: Dict[str, Any] = {}


def _days_in_month(year: int, month: int) -> int:
    if month == 2:
        leap = (year % 4 == 0 and year % 100 != 0) or year % 400 == 0
        return 29 if leap else 28
    return _DAYS_IN_MONTH[month - 1]


def is_calendar_date(value: str) -> bool:
    """A real calendar date in ``YYYY-MM-DD``."""
    if not _DATE_RE.match(value):
        return False
    year, month, day = int(value[0:4]), int(value[5:7]), int(value[8:10])
    if month < 1 or month > 12:
        return False
    return 1 <= day <= _days_in_month(year, month)


def _luhn_ok(digits: str) -> bool:
    total = 0
    dbl = False
    for i in range(len(digits) - 1, -1, -1):
        d = ord(digits[i]) - 48
        if d < 0 or d > 9:
            return False
        if dbl:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        dbl = not dbl
    return total % 10 == 0


def _finite_number(value: str) -> bool:
    if value == "":
        return False
    try:
        n = float(value)
    except (TypeError, ValueError):
        return False
    return n == n and n not in (float("inf"), float("-inf"))


def normalise_for_check(check: str, value: str) -> str:
    """The CANONICAL FORM a named check verifies.

    It is also the form a regex below that check is tested against, since the
    check is what states it. A check with nothing to normalise, and a name that is
    not a check at all, answer the value unchanged.
    """
    if check == "url":
        return value if _URL_SCHEME_RE.match(value) else "https://" + value
    if check == "card":
        return _CARD_STRIP_RE.sub("", value)
    if check in ("number", "integer", "decimal", "float"):
        return value.strip()
    return value


def apply_check(check: str, value: str) -> Optional[str]:
    """One named check, applied to the whole value in its canonical form.

    ``None`` when the value passes, else the check's name.
    """
    normalised = normalise_for_check(check, value)
    if check == "url":
        ok = bool(_URL_RE.match(normalised))
    elif check == "card":
        ok = bool(_CARD_RE.match(normalised)) and _luhn_ok(normalised)
    elif check == "number":
        ok = _finite_number(normalised)
    elif check == "integer":
        ok = bool(_INTEGER_RE.match(normalised))
    elif check == "decimal":
        ok = bool(_DECIMAL_RE.match(normalised))
    elif check == "float":
        ok = bool(_FLOAT_RE.match(normalised))
    else:
        ok = True
    return None if ok else check


def compile_regex(regex: str) -> Optional[Pattern[str]]:
    """A stored regex anchored to the WHOLE value, or ``None`` when it cannot compile."""
    cached = _COMPILED.get(regex)
    if cached is not None:
        return None if cached is False else cached
    try:
        compiled: Any = re.compile("^(?:" + regex + ")$")
    except re.error:
        compiled = False
    _COMPILED[regex] = compiled
    return None if compiled is False else compiled


def matches(regex: str, value: str) -> bool:
    """Whether a value matches a stored regex, which is anchored to the whole value.

    A pattern that cannot be compiled is refused at write, so reaching this with
    one means the stored row predates the rule it is now held to: no verdict can
    be stated, and refusing the value would refuse every value of that type.
    """
    compiled = compile_regex(regex)
    return compiled is None or compiled.match(value) is not None


def _is_option_array(value: str, options: Sequence[str]) -> bool:
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError):
        return False
    if not isinstance(decoded, list):
        return False
    return all(isinstance(e, str) and e in options for e in decoded)


class FieldTypeRegistry:
    """The served rows, interpreted.

    Built from the raw ``GET /api/contact-field-types`` array and held for the life
    of the client that fetched it. An instance with no rows knows no type, which is
    the honest answer for a client that has not loaded the registry: every type
    resolves as unknown and validates as "accept anything".
    """

    def __init__(self, rows: Iterable[dict] = ()) -> None:
        self._rows: Dict[str, dict] = {}
        for row in rows or ():
            if isinstance(row, dict) and row.get("type"):
                self._rows[str(row["type"])] = row
        self._resolved: Dict[str, dict] = {}

    # ── the tree ─────────────────────────────────────────────────────────────

    def rows(self) -> Dict[str, dict]:
        """The raw rows keyed by type."""
        return self._rows

    def types(self) -> List[str]:
        """Every type the registry carries."""
        return list(self._rows.keys())

    def knows(self, field_type: Optional[str]) -> bool:
        """Whether the registry carries this type at all."""
        return (field_type or "") in self._rows

    def resolve(self, field_type: Optional[str]) -> dict:
        """The resolved definition: every inherited column filled in, validations root-first.

        A type the registry does not carry resolves to the UNKNOWN definition —
        every column ``None``, no validations, ``known`` false. That is a distinct
        answer from a known type with nothing set, and callers must read it as
        "this client cannot draw or store this", never as a default.
        """
        key = field_type or ""
        cached = self._resolved.get(key)
        if cached is None:
            cached = self._resolved[key] = self._resolve_in(key)
        return cached

    def _resolve_in(self, field_type: str) -> dict:
        row = self._rows.get(field_type)
        if row is None:
            return {
                "type": field_type,
                "parent": None,
                "label": field_type,
                "is_system": False,
                "known": False,
                "input": None,
                "lane": None,
                "check": None,
                "options": None,
                "fields": None,
                "validations": [],
            }

        # Walk to the root collecting the chain, then fill downward: the nearest
        # ancestor that sets an inherited column wins, and the validations come out
        # root-first.
        chain: List[dict] = []
        seen: Dict[str, bool] = {}
        cursor: Optional[str] = field_type
        while cursor is not None and cursor in self._rows and cursor not in seen:
            seen[cursor] = True
            chain.append(self._rows[cursor])
            cursor = self._rows[cursor].get("parent")
        chain.reverse()

        definition: dict = {
            "type": field_type,
            "parent": row.get("parent"),
            "label": row.get("label") or field_type,
            "is_system": bool(row.get("is_system")),
            "known": True,
            "input": None,
            "lane": None,
            "check": None,
            "options": None,
            "fields": None,
            "validations": [],
        }
        for ancestor in chain:
            for column in ("input", "lane", "check", "options", "fields"):
                if ancestor.get(column) is not None:
                    definition[column] = ancestor[column]
            validation = ancestor.get("validation")
            if validation:
                definition["validations"].append(str(validation))
        return definition

    def descendants(self, field_type: str) -> List[str]:
        """The type and every descendant of it, for an ``IN`` list.

        An unknown type answers itself alone, so a query keyed on a type the
        registry does not carry still addresses that type rather than nothing.
        """
        out = [field_type]
        frontier = {field_type}
        # Bounded by the number of rows: each pass adds only types not already collected.
        for _ in range(len(self._rows)):
            if not frontier:
                break
            nxt = set()
            for candidate, row in self._rows.items():
                parent = row.get("parent")
                if parent is not None and parent in frontier and candidate not in out:
                    out.append(candidate)
                    nxt.add(candidate)
            frontier = nxt
        return out

    def accepts(self, requested: str, actual: str) -> bool:
        """Whether a request for ``requested`` is answered by a field of ``actual``."""
        return actual == requested or actual in self.descendants(requested)

    # ── storage lane ─────────────────────────────────────────────────────────

    def is_binary(self, field_type: Optional[str]) -> bool:
        """Whether this type's value is a file rather than an inline value."""
        lane = self.resolve(field_type)["lane"]
        return lane is not None and lane != "inline"

    def is_document_like(self, field_type: Optional[str]) -> bool:
        """Whether this type uses the document upload/storage lane."""
        return self.resolve(field_type)["lane"] == "document"

    def is_id_document(self, field_type: Optional[str]) -> bool:
        """Whether this type carries the multi-page ID-document envelope."""
        return self.resolve(field_type)["input"] == "pages"

    def binary_types(self) -> List[str]:
        """Every type on a lane other than ``inline``."""
        return [t for t in self.types() if self.is_binary(t)]

    def document_like_types(self) -> List[str]:
        """Every type on the ``document`` lane."""
        return [t for t in self.types() if self.is_document_like(t)]

    def id_document_types(self) -> List[str]:
        """Every type drawn by the multi-page upload."""
        return [t for t in self.types() if self.is_id_document(t)]

    # ── derived sets ─────────────────────────────────────────────────────────

    def is_option_less_choice(self, field_type: str) -> bool:
        """A choice type whose options are supplied elsewhere.

        It is usable only where something else carries them — a flow element — so
        it is offered for no contact field, no request row and no claim.
        """
        definition = self.resolve(field_type)
        return definition["input"] in ("list", "multilist") and not definition["options"]

    def options_for(
        self, field_type: Optional[str], supplied_options: Optional[Sequence[str]] = None
    ) -> Optional[List[str]]:
        """The option domain a choice value is held to.

        The ROW's own resolved options when it carries any, else the ones the caller
        supplies, and NEVER a merge of the two — a row that states its domain owns
        it, and a row that states none borrows the caller's whole.

        ``None`` means neither source has a domain: an option-less row asked about
        with nothing supplied. A value cannot be measured against that, so
        :meth:`validate` refuses rather than testing membership of an empty list,
        which would refuse every value including a legitimate one.

        Public so a caller can RENDER exactly the domain the validator will enforce.
        """
        row_options = self.resolve(field_type)["options"]
        if row_options:
            return [str(o) for o in row_options]
        if supplied_options:
            return [str(o) for o in supplied_options]
        return None

    def requestable_types(self) -> List[str]:
        """The types a contact field, a service request row or an admin field may declare."""
        return [t for t in self.types() if not self.is_option_less_choice(t)]

    def flow_types(self) -> List[str]:
        """The requestable set plus the option-less choice types, whose options a flow element supplies."""
        out = self.requestable_types()
        return out + [t for t in self.types() if self.is_option_less_choice(t)]

    def claimable_types(self) -> List[str]:
        """The requestable set on the ``inline`` lane.

        A file can never be sealed to a relying party's app key, so no claim can
        name a binary type.
        """
        return [t for t in self.requestable_types() if self.resolve(t)["lane"] == "inline"]

    # ── display ──────────────────────────────────────────────────────────────

    def label_for(self, field_type: str) -> str:
        """The label to render.

        A seeded row's ``label`` is the ``fieldtype_*`` translation key and a
        data-added row's is the literal an operator typed; ``is_system`` is the
        discriminator, and a literal is rendered verbatim rather than looked up.
        """
        return self.resolve(field_type)["label"]

    def ordered(self, types: Sequence[str]) -> List[str]:
        """The requested types in display order.

        Roots A→Z, each followed by its own children A→Z, recursively, by the
        stored ``label``. A requested type the registry does not carry sorts after
        the tree, so a picker built from a stale set still shows every entry it was
        given.
        """
        wanted = set(types)
        out: List[str] = []

        def children_of(parent: Optional[str]) -> List[str]:
            found = [
                (str(row.get("label") or name), name)
                for name, row in self._rows.items()
                if row.get("parent") == parent
            ]
            found.sort(key=lambda pair: (pair[0].lower(), pair[0]))
            return [name for _, name in found]

        def walk(parent: Optional[str]) -> None:
            for name in children_of(parent):
                if name in wanted:
                    out.append(name)
                walk(name)

        walk(None)
        unknown = sorted((t for t in types if t not in out), key=lambda t: (t.lower(), t))
        return out + unknown

    def effective_type(self, field_type: str) -> str:
        """The nearest ancestor, self included, that is ``date`` or ``number``; else the type itself.

        It collapses a type to the domain its comparison operators are chosen
        from; nothing in :meth:`validate` consults it, and no value's shape follows
        it.
        """
        seen: Dict[str, bool] = {}
        cursor: Optional[str] = field_type
        while cursor is not None and cursor in self._rows and cursor not in seen:
            seen[cursor] = True
            if cursor in ("date", "number"):
                return cursor
            cursor = self._rows[cursor].get("parent")
        return field_type

    # ── validation ───────────────────────────────────────────────────────────

    def validate(
        self,
        field_type: Optional[str],
        value: Any,
        supplied_options: Optional[Sequence[str]] = None,
    ) -> Optional[str]:
        """Validate a plaintext value against a type.

        The one fixed order: the primitive's own rule, then the resolved check,
        then every regex root-first, then the sub-field entries.
        The CHECK's normalised value is what those regexes see; the primitive's is
        not.

        An EMPTY value is valid — required is the caller's job — and a type the
        registry does not carry accepts anything, which is the pinned answer for a
        client older than a type.

        ``supplied_options`` is the caller's own option list, for a choice type
        whose row states none of its own (:meth:`options_for`).

        ``None`` when valid, else the name of the first failing rule.
        """
        text = "" if value is None else str(value)
        if text == "":
            return None
        definition = self.resolve(field_type)
        if not definition["known"]:
            return None

        failure = self._apply_primitive(
            definition, text, self.options_for(field_type, supplied_options)
        )
        if failure is not None:
            return failure

        # A CHECK'S NORMALISATION CARRIES; A PRIMITIVE'S DOES NOT, and the asymmetry
        # is the rule rather than an oversight. A check states the canonical form of
        # the value it verifies — a URL with its scheme, a card number without its
        # separators — so a regex a child adds below it describes that form and is
        # tested against it. A primitive draws a value it does not rewrite, so
        # nothing it does reaches the regex step.
        matched = text
        check = definition["check"]
        if check:
            failure = apply_check(check, text)
            if failure is not None:
                return failure
            matched = normalise_for_check(check, text)
        for regex in definition["validations"]:
            if not matches(regex, matched):
                return "validation"
        return None

    def is_field_value_valid(
        self,
        field_type: Optional[str],
        value: Any,
        supplied_options: Optional[Sequence[str]] = None,
    ) -> bool:
        """True when ``value`` is an acceptable plaintext for ``field_type``."""
        return self.validate(field_type, value, supplied_options) is None

    def field_value_error(
        self,
        field_type: Optional[str],
        value: Any,
        supplied_options: Optional[Sequence[str]] = None,
    ) -> Optional[str]:
        """``None`` when valid, else the name of the first failing rule."""
        return self.validate(field_type, value, supplied_options)

    def _apply_primitive(
        self, definition: dict, value: str, options: Optional[Sequence[str]]
    ) -> Optional[str]:
        """The primitive's own rule, plus the sub-field entries for the three that carry them.

        ``options`` is the domain a choice value is held to, already resolved by
        :meth:`options_for`; ``None`` is "there is no domain", which is refused
        rather than tested.
        """
        primitive = definition["input"]
        if primitive is None or primitive == "line":
            return None
        if primitive == "date":
            return None if is_calendar_date(value) else "date"
        if primitive == "list":
            if options is None:
                return "options_unavailable"
            return None if value in options else "list"
        if primitive == "multilist":
            if options is None:
                return "options_unavailable"
            return None if _is_option_array(value, options) else "multilist"
        if primitive in ("country", "nationality"):
            return None if value in _COUNTRY_CODE_SET else primitive
        if primitive == "state":
            return None if value in _US_STATE_CODE_SET else "state"
        if primitive == "phone":
            return None if _PHONE_RE.match(_PHONE_STRIP_RE.sub("", value)) else "phone"
        if primitive == "composite":
            return self._validate_object(value, definition["fields"] or [], ())
        if primitive in ("file", "pages"):
            return self._validate_object(value, definition["fields"] or [], ENVELOPE_MEMBERS)
        return None

    def _validate_object(
        self, value: str, fields: Sequence[Any], envelope_members: Sequence[str]
    ) -> Optional[str]:
        """A JSON object value: no unknown key, every required entry present, each entry valid.

        ``envelope_members`` are the primitive's own members, accepted beside the
        entries and validated by :func:`_validate_envelope_member` — the one home for
        what each of them looks like.
        """
        try:
            obj = json.loads(value)
        except (TypeError, ValueError):
            return "object"
        if not isinstance(obj, dict):
            return "object"

        entries = {
            str(e["key"]): e
            for e in fields
            if isinstance(e, dict) and e.get("key") is not None
        }

        for key, raw in obj.items():
            key = str(key)
            entry = entries.get(key)
            if entry is not None:
                if not isinstance(raw, str):
                    return key
                if raw != "" and _validate_entry(entry, raw) is not None:
                    return key
                continue
            if key not in envelope_members:
                return "unknown_key"
            member_failure = _validate_envelope_member(key, raw)
            if member_failure is not None:
                return member_failure

        for key, entry in entries.items():
            if entry.get("required") and (key not in obj or obj[key] == ""):
                return key
        return None


def _validate_envelope_member(key: str, raw: Any) -> Optional[str]:
    """ONE member of a ``file``/``pages`` envelope, by its own shape.

    The single home for what each member looks like, so a member added to the
    envelope is one branch here and nothing else. ``size`` is a JSON integer,
    ``pages`` the multi-page list below, ``mime_type`` a MIME string when it carries
    anything, and every other member a string.
    """
    if key == "pages":
        return _validate_pages(raw)
    if key == "size":
        # A JSON integer, and a bool is not one even though Python makes it an int
        # subclass.
        if isinstance(raw, bool) or not isinstance(raw, int):
            return "size"
        return None
    if not isinstance(raw, str):
        return key
    if key == "mime_type" and raw != "" and not _MIME_RE.match(raw):
        return "mime_type"
    return None


def _validate_pages(raw: Any) -> Optional[str]:
    """The ``pages`` member of an ID-document envelope: a LIST of page objects.

    Never a scalar. Each page names one uploaded file plus that file's own
    metadata. ``file`` is the reference and is required; ``label`` says which slot
    the page fills, and the slots are exactly the ones the multi-page editor draws —
    a front, an optional back, and repeatable extras. An empty list is a document
    whose pages have not been uploaded yet, which is a valid envelope.
    """
    if not isinstance(raw, list):
        return "pages"
    for page in raw:
        if not isinstance(page, dict):
            return "pages"
        for key, member in page.items():
            key = str(key)
            if key not in PAGE_MEMBERS:
                return "pages"
            if key == "label":
                if not isinstance(member, str) or member not in PAGE_LABELS:
                    return "pages"
                continue
            if key == "file":
                if not isinstance(member, str) or member == "":
                    return "pages"
                continue
            if _validate_envelope_member(key, member) is not None:
                return "pages"
        if "file" not in page:
            return "pages"
    return None


def _validate_entry(entry: dict, value: str) -> Optional[str]:
    """One sub-field entry: its primitive rule, then its check, then its regex."""
    primitive = str(entry.get("input") or "line")
    options = entry.get("options") or []
    failure: Optional[str] = None
    if primitive == "date":
        failure = None if is_calendar_date(value) else "date"
    elif primitive == "list":
        failure = None if value in options else "list"
    elif primitive in ("country", "nationality"):
        failure = None if value in _COUNTRY_CODE_SET else primitive
    elif primitive == "state":
        failure = None if value in _US_STATE_CODE_SET else "state"
    elif primitive == "phone":
        failure = None if _PHONE_RE.match(_PHONE_STRIP_RE.sub("", value)) else "phone"
    if failure is not None:
        return failure

    # The entry runs the same primitive → check → regex order a top-level value
    # does, and the check's normalisation carries into its regex for the same reason
    # it does there — so a composite's entry can never disagree with a value of the
    # same shape.
    matched = value
    check = entry.get("check")
    if isinstance(check, str) and check != "":
        if apply_check(check, value) is not None:
            return check
        matched = normalise_for_check(check, value)
    regex = entry.get("validation")
    if isinstance(regex, str) and regex != "" and not matches(regex, matched):
        return "validation"
    return None


__all__ = [
    "FieldTypeRegistry",
    "LANES",
    "INPUTS",
    "CHECKS",
    "INPUT_LANES",
    "ENTRY_INPUTS",
    "ENVELOPE_MEMBERS",
    "MAX_VALIDATION_LENGTH",
]
