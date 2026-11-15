"""Increment (delta) zone files.

An increment file describes changes against a declared baseline:

    $ZONE example.com.
    $PREREQ 2024010100      ; serial of the baseline this delta applies to
    $SERIAL 2024010101      ; serial of the version this delta produces

    $ADD
    www 300 IN A 192.0.2.10

    $REPLACE
    @ IN MX 10 mail.example.com.    ; redefines the whole MX RRset at @

    $DELETE
    old A                           ; delete the A RRset at old
    junk                            ; delete every record at junk
    gone TXT "obsolete"             ; delete one specific record
    $END

The increment is only applied when the repository's current serial for
the zone equals $PREREQ.  $SERIAL must be greater than $PREREQ in
RFC 1982 arithmetic.  Unless the delta itself replaces the apex SOA,
the SOA serial is bumped to $SERIAL automatically.
"""

from .errors import DeltaError, ParseError, SerialError
from .names import absolutize, canon_zone
from .records import (KNOWN_TYPES, TYPE_RE, Record, parse_rdata, parse_ttl,
                      serial_gt, soa_fields, soa_with_serial)
from .zonefile import FileState, parse_record_line, tokenize

SERIAL_MAX = 2 ** 32 - 1


class DeleteSpec:
    """One $DELETE line: owner, optional rtype, optional rdata."""

    __slots__ = ("owner", "rtype", "rdata", "line_no")

    def __init__(self, owner, rtype, rdata, line_no):
        self.owner = owner
        self.rtype = rtype
        self.rdata = rdata
        self.line_no = line_no

    def __repr__(self):
        return "DeleteSpec(%s %s %r)" % (self.owner, self.rtype, self.rdata)


class Increment:
    def __init__(self, zone, prereq, serial, adds, replaces, deletes):
        self.zone = zone
        self.prereq = prereq
        self.serial = serial
        self.adds = adds
        self.replaces = replaces
        self.deletes = deletes


def parse_increment(text, preserve_unknown=False):
    """Parse an increment file into an Increment."""
    state = FileState(origin=None)
    zone = prereq = serial = None
    section = None
    adds, replaces, deletes = [], [], []

    for ll in tokenize(text):
        head = ll.tokens[0]
        if head.startswith("$"):
            name = head.upper()
            args = ll.tokens[1:]
            if name == "$ZONE":
                if zone is not None or section is not None:
                    raise ParseError("$ZONE must appear exactly once, before "
                                     "any section", ll.start_line)
                if len(args) != 1:
                    raise ParseError("$ZONE takes exactly one argument",
                                     ll.start_line)
                zone = canon_zone(args[0])
                state.origin = zone
            elif name in ("$PREREQ", "$SERIAL"):
                if zone is None:
                    raise ParseError("$ZONE must come before %s" % name,
                                     ll.start_line)
                if section is not None:
                    raise ParseError("%s must appear before any section" % name,
                                     ll.start_line)
                if len(args) != 1 or not args[0].isdigit():
                    raise ParseError("%s needs one numeric serial" % name,
                                     ll.start_line)
                value = int(args[0])
                if value > SERIAL_MAX:
                    raise ParseError("serial %d out of range" % value,
                                     ll.start_line)
                if name == "$PREREQ":
                    if prereq is not None:
                        raise ParseError("duplicate $PREREQ", ll.start_line)
                    prereq = value
                else:
                    if serial is not None:
                        raise ParseError("duplicate $SERIAL", ll.start_line)
                    serial = value
            elif name in ("$ADD", "$REPLACE", "$DELETE"):
                if zone is None:
                    raise ParseError("$ZONE must come before sections",
                                     ll.start_line)
                section = name[1:]
                state.last_owner = None
            elif name == "$ORIGIN":
                if len(args) != 1:
                    raise ParseError("$ORIGIN takes exactly one argument",
                                     ll.start_line)
                state.origin = absolutize(args[0], state.origin, ll.start_line)
            elif name == "$TTL":
                if len(args) != 1:
                    raise ParseError("$TTL takes exactly one argument",
                                     ll.start_line)
                state.default_ttl = parse_ttl(args[0], ll.start_line)
            elif name == "$END":
                break
            else:
                raise ParseError("unsupported directive %r" % head,
                                 ll.start_line)
            continue

        if section is None:
            raise ParseError("record outside of $ADD/$REPLACE/$DELETE "
                             "section", ll.start_line)
        if section == "DELETE":
            deletes.append(_parse_delete(ll, state))
        else:
            rec = parse_record_line(ll, state, preserve_unknown)
            (adds if section == "ADD" else replaces).append(rec)

    if zone is None:
        raise ParseError("missing $ZONE directive")
    if prereq is None:
        raise ParseError("missing $PREREQ directive")
    if serial is None:
        raise ParseError("missing $SERIAL directive")

    seen = {}
    for rec in adds + replaces:
        key = rec.key()
        if key in seen:
            raise ParseError("duplicate record in increment (first seen on "
                             "line %d)" % seen[key], rec.line_no)
        seen[key] = rec.line_no
    return Increment(zone, prereq, serial, adds, replaces, deletes)


def _parse_delete(ll, state):
    tokens = list(ll.tokens)
    if ll.leading_ws:
        raise ParseError("$DELETE lines need an explicit owner name",
                         ll.start_line)
    owner = absolutize(tokens.pop(0), state.origin, ll.start_line)
    if tokens and tokens[0].upper() == "IN":
        tokens.pop(0)
    if not tokens:
        return DeleteSpec(owner, None, None, ll.start_line)
    if tokens[0].isdigit():
        raise ParseError("TTL is not allowed in $DELETE lines", ll.start_line)
    rtype = tokens.pop(0).upper()
    if not TYPE_RE.match(rtype):
        raise ParseError("bad record type %r" % rtype, ll.start_line)
    if tokens:
        if rtype in KNOWN_TYPES:
            rdata = parse_rdata(rtype, tokens, state.origin, ll.start_line)
        else:
            # Unknown types are matched on their preserved raw text.
            rdata = " ".join(tokens)
    else:
        rdata = None
    return DeleteSpec(owner, rtype, rdata, ll.start_line)


def apply_increment(base_records, inc, zone):
    """Apply *inc* to *base_records*, returning the new record list.

    Pure function: does not touch storage.  Carried records keep their
    lineage (``introduced_in``); new records have it set to None for the
    caller to fill.  Raises DeltaError when a directive does not match
    the baseline content.
    """
    # Records in the delta without a TTL fall back to the increment's
    # $TTL (applied at parse time) or the baseline SOA minimum.
    base_soa = [r for r in base_records
                if r.rtype == "SOA" and r.owner == zone]
    base_minimum = soa_fields(base_soa[0].rdata)[6] if base_soa else None
    for rec in inc.adds + inc.replaces:
        if rec.ttl is None:
            if base_minimum is None:
                raise ParseError("record without TTL and no baseline SOA "
                                 "minimum to inherit", rec.line_no)
            rec.ttl = base_minimum

    # Reject contradictory directives before mutating anything.
    delete_coverage = set()
    for spec in inc.deletes:
        delete_coverage.add((spec.owner, spec.rtype))
    replace_groups = {}
    for rec in inc.replaces:
        replace_groups.setdefault((rec.owner, rec.rtype), []).append(rec)
    for owner, rtype in replace_groups:
        if (owner, rtype) in delete_coverage or (owner, None) in delete_coverage:
            raise DeltaError("%s %s is both deleted and replaced" %
                             (owner, rtype))
    for rec in inc.adds:
        if (rec.owner, rec.rtype) in replace_groups:
            raise DeltaError("%s %s appears in both $ADD and $REPLACE" %
                             (rec.owner, rec.rtype))

    state = {r.key(): r for r in base_records}
    touched_soa = False

    # 1. deletes
    for spec in inc.deletes:
        if spec.owner == zone and spec.rtype in (None, "SOA"):
            touched_soa = True
        if spec.rtype is None:
            keys = [k for k in state if k[0] == spec.owner]
        elif spec.rdata is None:
            keys = [k for k in state
                    if k[0] == spec.owner and k[1] == spec.rtype]
        else:
            keys = [k for k in state
                    if k[0] == spec.owner and k[1] == spec.rtype
                    and k[3] == spec.rdata]
        if not keys:
            raise DeltaError("nothing to delete matching line %d (%s)" %
                             (spec.line_no, _spec_text(spec)))
        for key in keys:
            del state[key]

    # 2. replaces (per RRset)
    for (owner, rtype), recs in replace_groups.items():
        if (owner, rtype) == (zone, "SOA"):
            touched_soa = True
        for key in [k for k in state if k[0] == owner and k[1] == rtype]:
            del state[key]
        for rec in recs:
            state[rec.key()] = rec

    # 3. adds
    for rec in inc.adds:
        # A record is identified by owner/type/rdata here: re-adding the
        # same data with a different TTL would create an inconsistent
        # RRset, so it is rejected (use $REPLACE to restate an RRset).
        if any(k[0] == rec.owner and k[1] == rec.rtype and k[3] == rec.rdata
               for k in state):
            raise DeltaError("$ADD of a record that already exists: %s" %
                             rec.to_line())
        if rec.owner == zone and rec.rtype == "SOA":
            touched_soa = True
        state[rec.key()] = rec

    # 4. SOA serial maintenance
    soas = [r for r in state.values()
            if r.rtype == "SOA" and r.owner == zone]
    if touched_soa:
        if len(soas) == 1 and soa_fields(soas[0].rdata)[2] != inc.serial:
            raise SerialError(
                "increment sets SOA serial %d but declares $SERIAL %d" %
                (soa_fields(soas[0].rdata)[2], inc.serial))
    elif len(soas) == 1:
        old = soas[0]
        del state[old.key()]
        bumped = Record(old.owner, "SOA", old.ttl,
                        soa_with_serial(old.rdata, inc.serial),
                        known=True, line_no=None, introduced_in=None)
        state[bumped.key()] = bumped

    return sorted(state.values(),
                  key=lambda r: (r.owner, r.rtype, r.rdata, r.ttl))


def _spec_text(spec):
    parts = [spec.owner]
    if spec.rtype:
        parts.append(spec.rtype)
    if spec.rdata:
        parts.append(spec.rdata)
    return " ".join(parts)
