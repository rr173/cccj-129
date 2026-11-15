"""Pre-publish zone validation.

Every publish (master or increment) validates the complete resulting
zone.  A zone that fails validation is never published.
"""

from .errors import (CNAMEConflictError, CNAMELoopError, OutOfZoneError,
                     SerialError, ValidationError)
from .names import in_zone
from .records import soa_fields


def validate_zone(records, zone, serial=None):
    """Validate a complete zone, returning its SOA serial.

    *records* is the full record list; *zone* the canonical zone name.
    When *serial* is given, the apex SOA serial must equal it.

    Checks: zone boundary, exactly one SOA at the apex, no duplicate
    records, CNAME/other-data conflicts, CNAME loops.
    """
    for rec in records:
        if not in_zone(rec.owner, zone):
            raise OutOfZoneError("record owner %s is outside zone %s" %
                                 (rec.owner, zone))

    soas = [r for r in records if r.rtype == "SOA"]
    if len(soas) != 1:
        raise ValidationError("zone %s must contain exactly one SOA record, "
                              "found %d" % (zone, len(soas)))
    soa = soas[0]
    if soa.owner != zone:
        raise ValidationError("SOA record must be at the zone apex %s, "
                              "found at %s" % (zone, soa.owner))
    soa_serial = soa_fields(soa.rdata)[2]
    if serial is not None and soa_serial != serial:
        raise SerialError("SOA serial %d does not match declared serial %d" %
                          (soa_serial, serial))

    seen = {}
    for rec in records:
        key = rec.key()
        if key in seen:
            raise ValidationError(
                "duplicate record %s (lines %s and %s)" %
                (rec.to_line(), seen[key], rec.line_no))
        seen[key] = rec.line_no

    by_owner = {}
    for rec in records:
        by_owner.setdefault(rec.owner, []).append(rec)
    for owner, recs in by_owner.items():
        cnames = [r for r in recs if r.rtype == "CNAME"]
        if len(cnames) > 1:
            raise CNAMEConflictError(
                "multiple CNAME records at %s" % owner)
        if cnames and len(recs) > 1:
            others = sorted({r.rtype for r in recs if r.rtype != "CNAME"})
            raise CNAMEConflictError(
                "CNAME at %s coexists with other data (%s)" %
                (owner, ", ".join(others)))

    cmap = {r.owner: r.rdata for r in records if r.rtype == "CNAME"}
    for start in cmap:
        visited = set()
        current = start
        while current in cmap:
            if current in visited:
                raise CNAMELoopError(
                    "CNAME loop detected at %s" % current)
            visited.add(current)
            current = cmap[current]

    return soa_serial
