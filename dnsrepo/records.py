"""Record model and per-type rdata parsing / canonical formatting.

Supported types (project scope): A, AAAA, CNAME, MX, TXT, NS, SOA.
Unknown types may be preserved as raw text (known=False) but their
semantics are never interpreted: rdata is stored verbatim (whitespace
normalized) and emitted unchanged.
"""

import ipaddress
import re

from .errors import ParseError
from .names import absolutize

KNOWN_TYPES = frozenset(["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"])

TYPE_RE = re.compile(r"^(TYPE[0-9]+|[A-Z][A-Z0-9-]*)$")

UINT32_MAX = 2 ** 32 - 1
TTL_MAX = 2 ** 31 - 1  # RFC 2181


class Record:
    """A single resource record.

    ``owner`` is a canonical absolute name.  ``rdata`` is the canonical
    text form for known types, or the preserved raw text for unknown
    types (``known`` False).  ``line_no`` is the 1-based line in the
    source file where the record was introduced; None for synthesized
    records (e.g. an auto-bumped SOA serial).  ``introduced_in`` /
    ``source_file`` describe the version that introduced the record and
    are filled in by the repository layer.
    """

    __slots__ = ("owner", "rtype", "ttl", "rdata", "known",
                 "line_no", "introduced_in", "source_file")

    def __init__(self, owner, rtype, ttl, rdata, known=True,
                 line_no=None, introduced_in=None, source_file=None):
        self.owner = owner
        self.rtype = rtype
        self.ttl = ttl
        self.rdata = rdata
        self.known = known
        self.line_no = line_no
        self.introduced_in = introduced_in
        self.source_file = source_file

    def key(self):
        """Identity of the record as a zone member (lineage excluded)."""
        return (self.owner, self.rtype, self.ttl, self.rdata)

    def to_line(self, origin=None):
        """Render as a master-file line (owner relative to *origin*)."""
        from .names import relative
        owner = relative(self.owner, origin) if origin else self.owner
        return "%s %d IN %s %s" % (owner, self.ttl, self.rtype, self.rdata)

    def __eq__(self, other):
        return isinstance(other, Record) and self.key() == other.key()

    def __hash__(self):
        return hash(self.key())

    def __repr__(self):
        return "Record(%s %s %s %r)" % (self.owner, self.ttl, self.rtype, self.rdata)


# --------------------------------------------------------------------------
# rdata parsing helpers
# --------------------------------------------------------------------------

def _uint(text, lo, hi, what, line):
    try:
        value = int(text, 10)
    except ValueError:
        raise ParseError("%s must be a number, got %r" % (what, text), line)
    if not lo <= value <= hi:
        raise ParseError("%s %d out of range %d..%d" % (what, value, lo, hi), line)
    return value


def parse_ttl(text, line=None):
    return _uint(text, 0, TTL_MAX, "TTL", line)


def parse_rdata(rtype, tokens, origin, line):
    """Parse rdata *tokens* of a known type into canonical text form."""
    parser = _PARSERS[rtype]
    return parser(tokens, origin, line)


def _need(tokens, count, rtype, line):
    if len(tokens) < count:
        raise ParseError("%s record needs %d rdata field(s), got %d"
                         % (rtype, count, len(tokens)), line)
    if len(tokens) > count:
        raise ParseError("%s record has unexpected extra rdata: %s"
                         % (rtype, " ".join(tokens[count:])), line)


def _parse_a(tokens, origin, line):
    _need(tokens, 1, "A", line)
    try:
        return str(ipaddress.IPv4Address(tokens[0]))
    except ipaddress.AddressValueError:
        raise ParseError("bad IPv4 address %r" % tokens[0], line)


def _parse_aaaa(tokens, origin, line):
    _need(tokens, 1, "AAAA", line)
    try:
        return ipaddress.IPv6Address(tokens[0]).compressed
    except ipaddress.AddressValueError:
        raise ParseError("bad IPv6 address %r" % tokens[0], line)


def _parse_name(tokens, origin, line):
    _need(tokens, 1, "name", line)
    return absolutize(tokens[0], origin, line)


def _parse_mx(tokens, origin, line):
    _need(tokens, 2, "MX", line)
    pref = _uint(tokens[0], 0, 65535, "MX preference", line)
    exchange = absolutize(tokens[1], origin, line)
    return "%d %s" % (pref, exchange)


def _parse_soa(tokens, origin, line):
    _need(tokens, 7, "SOA", line)
    mname = absolutize(tokens[0], origin, line)
    rname = absolutize(tokens[1], origin, line)
    numbers = [_uint(t, 0, UINT32_MAX, "SOA field", line) for t in tokens[2:]]
    return "%s %s %s" % (mname, rname, " ".join(str(n) for n in numbers))


def _parse_txt(tokens, origin, line):
    if not tokens:
        raise ParseError("TXT record needs at least one character-string", line)
    strings = [_txt_token_to_bytes(t, line) for t in tokens]
    return " ".join(quote_txt(s) for s in strings)


_PARSERS = {
    "A": _parse_a,
    "AAAA": _parse_aaaa,
    "CNAME": _parse_name,
    "NS": _parse_name,
    "MX": _parse_mx,
    "SOA": _parse_soa,
    "TXT": _parse_txt,
}


# --------------------------------------------------------------------------
# TXT character-strings
# --------------------------------------------------------------------------

def _txt_token_to_bytes(token, line):
    """Decode one TXT token (quoted with escapes, or bare) to bytes."""
    if token.startswith('"'):
        if len(token) < 2 or not token.endswith('"'):
            raise ParseError("unterminated quoted string", line)
        return decode_txt_escapes(token[1:-1], line)
    if '"' in token:
        raise ParseError("misplaced quote in TXT rdata", line)
    data = token.encode("utf-8")
    if len(data) > 255:
        raise ParseError("TXT character-string exceeds 255 octets", line)
    return data


def decode_txt_escapes(text, line=None):
    """Decode the inside of a quoted string: \\X and \\DDD escapes."""
    out = bytearray()
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch != "\\":
            out.extend(ch.encode("utf-8"))
            i += 1
            continue
        if i + 1 >= n:
            raise ParseError("trailing backslash in quoted string", line)
        nxt = text[i + 1]
        if nxt.isdigit():
            digits = text[i + 1:i + 4]
            if len(digits) != 3 or not digits.isdigit():
                raise ParseError("bad escape: \\DDD needs exactly three digits", line)
            value = int(digits, 10)
            if value > 255:
                raise ParseError("escape \\%s exceeds 255" % digits, line)
            out.append(value)
            i += 4
        else:
            out.extend(nxt.encode("utf-8"))
            i += 2
    if len(out) > 255:
        raise ParseError("TXT character-string exceeds 255 octets", line)
    return bytes(out)


def quote_txt(data):
    """Canonical quoted form of one TXT character-string (bytes)."""
    parts = ['"']
    for byte in data:
        if byte == 0x22:  # "
            parts.append('\\"')
        elif byte == 0x5C:  # \
            parts.append("\\\\")
        elif 0x20 <= byte <= 0x7E:
            parts.append(chr(byte))
        else:
            parts.append("\\%03d" % byte)
    parts.append('"')
    return "".join(parts)


# --------------------------------------------------------------------------
# SOA helpers
# --------------------------------------------------------------------------

def soa_fields(rdata):
    """Split canonical SOA rdata into (mname, rname, serial, refresh, retry, expire, minimum)."""
    parts = rdata.split(" ")
    if len(parts) != 7:
        raise ParseError("malformed SOA rdata %r" % rdata)
    return (parts[0], parts[1]) + tuple(int(p) for p in parts[2:])


def soa_with_serial(rdata, serial):
    """Return canonical SOA rdata with the serial field replaced."""
    mname, rname, _serial, refresh, retry, expire, minimum = soa_fields(rdata)
    return "%s %s %d %d %d %d %d" % (mname, rname, serial, refresh, retry, expire, minimum)


# --------------------------------------------------------------------------
# serial arithmetic (RFC 1982)
# --------------------------------------------------------------------------

SERIAL_SPACE = 2 ** 32


def serial_gt(a, b):
    """True if *a* is strictly greater than *b* in RFC 1982 arithmetic."""
    a %= SERIAL_SPACE
    b %= SERIAL_SPACE
    return a != b and (a - b) % SERIAL_SPACE < SERIAL_SPACE // 2
