"""Master zone file tokenizer and parser (RFC 1035 style, project subset).

Supported:
  * $ORIGIN and $TTL directives
  * ``;`` comments, ``( )`` line continuation, quoted strings
  * owner omitted via leading whitespace (previous owner is reused)
  * TTL and class (IN only) in either order, both optional
  * ``@`` and relative names
"""

from .errors import ParseError, UnknownTypeError
from .names import absolutize, canon_zone
from .records import (KNOWN_TYPES, TYPE_RE, Record, parse_rdata, parse_ttl)


class LogicalLine:
    """One logical (possibly multi-line) entry from a master file."""

    __slots__ = ("tokens", "start_line", "leading_ws")

    def __init__(self, tokens, start_line, leading_ws):
        self.tokens = tokens
        self.start_line = start_line
        self.leading_ws = leading_ws

    def __repr__(self):
        return "LogicalLine(line=%d, ws=%r, %r)" % (
            self.start_line, self.leading_ws, self.tokens)


def tokenize(text):
    """Split master-file *text* into a list of LogicalLine.

    Handles comments, parentheses and quoted strings.  Quoted tokens keep
    their surrounding quotes so later stages can tell them apart from
    bare tokens (only TXT rdata may be quoted).
    """
    lines = []
    tokens = []
    cur = []
    depth = 0
    start_line = None      # physical line where the logical line began
    leading_ws = False     # did the logical line begin with whitespace?
    line_no = 1
    line_start_ws = False  # current physical line began with whitespace
    seen_char = False      # any token character seen on this physical line
    i = 0
    n = len(text)

    def flush_token():
        if cur:
            tokens.append("".join(cur))
            del cur[:]

    def flush_line():
        nonlocal tokens, start_line, leading_ws
        if tokens:
            lines.append(LogicalLine(tokens, start_line, leading_ws))
        tokens = []
        start_line = None
        leading_ws = False

    while i < n:
        c = text[i]
        if c == "\n":
            flush_token()
            if depth == 0:
                flush_line()
            line_no += 1
            line_start_ws = False
            seen_char = False
            i += 1
            continue
        if c in " \t\r":
            flush_token()
            if not seen_char:
                line_start_ws = True
            i += 1
            continue
        if c == ";":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "(":
            flush_token()
            depth += 1
            seen_char = True
            i += 1
            continue
        if c == ")":
            flush_token()
            depth -= 1
            if depth < 0:
                raise ParseError("unbalanced ')'", line_no)
            seen_char = True
            i += 1
            continue
        if c == '"':
            # A quoted string is a token of its own; keep it raw (quotes
            # included) and respect backslash escapes while scanning.
            flush_token()
            if start_line is None:
                start_line = line_no
                leading_ws = line_start_ws
            j = i + 1
            buf = ['"']
            closed = False
            while j < n:
                d = text[j]
                if d == "\\" and j + 1 < n:
                    buf.append(d)
                    buf.append(text[j + 1])
                    if text[j + 1] == "\n":
                        line_no += 1
                    j += 2
                    continue
                buf.append(d)
                if d == '"':
                    closed = True
                    j += 1
                    break
                if d == "\n":
                    line_no += 1
                j += 1
            if not closed:
                raise ParseError("unterminated quoted string", line_no)
            tokens.append("".join(buf))
            seen_char = True
            i = j
            continue
        # ordinary token character
        if start_line is None:
            start_line = line_no
            leading_ws = line_start_ws
        cur.append(c)
        seen_char = True
        i += 1

    if depth > 0:
        raise ParseError("unbalanced '('", line_no)
    flush_token()
    flush_line()
    return lines


class FileState:
    """Mutable parse state shared by master and increment parsers."""

    def __init__(self, origin, default_ttl=None):
        self.origin = origin
        self.default_ttl = default_ttl
        self.last_owner = None


def parse_record_line(ll, state, preserve_unknown):
    """Parse one record LogicalLine into a Record (TTL may be None)."""
    tokens = list(ll.tokens)
    if ll.leading_ws:
        if state.last_owner is None:
            raise ParseError("record without an owner name "
                             "(no previous record to inherit from)",
                             ll.start_line)
        owner = state.last_owner
    else:
        owner = absolutize(tokens.pop(0), state.origin, ll.start_line)
        state.last_owner = owner

    ttl = None
    class_seen = False
    while tokens:
        head = tokens[0]
        if ttl is None and head.isdigit():
            ttl = parse_ttl(head, ll.start_line)
            tokens.pop(0)
            continue
        upper = head.upper()
        if not class_seen and upper == "IN":
            class_seen = True
            tokens.pop(0)
            continue
        if upper in ("CH", "HS", "CS"):
            raise ParseError("unsupported record class %r (only IN)" % head,
                             ll.start_line)
        break

    if not tokens:
        raise ParseError("missing record type", ll.start_line)
    rtype = tokens.pop(0).upper()
    if rtype.startswith("$"):
        raise ParseError("directive %r is not allowed here" % rtype, ll.start_line)
    if not TYPE_RE.match(rtype):
        raise ParseError("bad record type %r" % rtype, ll.start_line)
    if any(t.startswith('"') for t in tokens) and rtype in KNOWN_TYPES \
            and rtype != "TXT":
        raise ParseError("quoted strings are only valid in TXT rdata",
                         ll.start_line)

    if rtype in KNOWN_TYPES:
        rdata = parse_rdata(rtype, tokens, state.origin, ll.start_line)
        known = True
    else:
        if not preserve_unknown:
            raise UnknownTypeError(
                "unknown record type %r (enable preserve_unknown to keep "
                "it as raw text)" % rtype, ll.start_line)
        # Preserved verbatim (whitespace normalized); semantics unknown.
        rdata = " ".join(tokens)
        known = False

    if ttl is None:
        ttl = state.default_ttl
    return Record(owner, rtype, ttl, rdata, known=known, line_no=ll.start_line)


class ParsedMaster:
    def __init__(self, zone, records, default_ttl):
        self.zone = zone
        self.records = records
        self.default_ttl = default_ttl


def parse_master(text, zone, preserve_unknown=False):
    """Parse a master zone file for *zone*.

    Returns a ParsedMaster.  The zone name is authoritative: records
    falling outside it are rejected later by validation, and the SOA
    must sit at the zone apex.
    """
    zone = canon_zone(zone)
    state = FileState(origin=zone)
    records = []
    for ll in tokenize(text):
        head = ll.tokens[0]
        if head.startswith("$"):
            _directive(ll, state)
            continue
        records.append(parse_record_line(ll, state, preserve_unknown))
    _fill_default_ttls(records, state)
    return ParsedMaster(zone, records, state.default_ttl)


def _directive(ll, state):
    name = ll.tokens[0].upper()
    args = ll.tokens[1:]
    if name == "$ORIGIN":
        if len(args) != 1:
            raise ParseError("$ORIGIN takes exactly one argument", ll.start_line)
        state.origin = absolutize(args[0], state.origin, ll.start_line)
    elif name == "$TTL":
        if len(args) != 1:
            raise ParseError("$TTL takes exactly one argument", ll.start_line)
        state.default_ttl = parse_ttl(args[0], ll.start_line)
    elif name == "$INCLUDE":
        raise ParseError("$INCLUDE is not supported", ll.start_line)
    else:
        raise ParseError("unsupported directive %r" % ll.tokens[0], ll.start_line)


def _fill_default_ttls(records, state):
    """Fill missing TTLs: $TTL value, else the SOA minimum (RFC 2308)."""
    missing = [r for r in records if r.ttl is None]
    if not missing:
        return
    fallback = state.default_ttl
    if fallback is None:
        soas = [r for r in records if r.rtype == "SOA"]
        if soas:
            from .records import soa_fields
            fallback = soa_fields(soas[0].rdata)[6]  # minimum
    if fallback is None:
        raise ParseError("record(s) without TTL and neither $TTL nor an "
                         "SOA record provides a default",
                         missing[0].line_no)
    for r in missing:
        r.ttl = fallback
