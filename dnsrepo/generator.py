"""Zone file generation: render a version as a master file and write it
to disk atomically (temp file + rename, so readers never see a partial
file)."""

import os

from .errors import ZoneError
from .names import canon_zone, relative
from .records import soa_fields


def render_zone(zone, serial, records, default_ttl=None):
    """Render *records* as a canonical master zone file for *zone*."""
    zone = canon_zone(zone)
    soas = [r for r in records if r.rtype == "SOA"]
    if len(soas) != 1:
        raise ZoneError("cannot render zone %s: expected exactly one SOA, "
                        "found %d" % (zone, len(soas)))
    soa = soas[0]
    mname, rname, soa_serial, refresh, retry, expire, minimum = \
        soa_fields(soa.rdata)
    if soa_serial != serial:
        raise ZoneError("cannot render zone %s: SOA serial %d does not "
                        "match version serial %d" % (zone, soa_serial, serial))
    if default_ttl is None:
        default_ttl = minimum

    lines = [
        "$ORIGIN %s" % zone,
        "$TTL %d" % default_ttl,
        "",
        "@ %d IN SOA %s %s (" % (soa.ttl, mname, rname),
        "\t%d ; serial" % soa_serial,
        "\t%d ; refresh" % refresh,
        "\t%d ; retry" % retry,
        "\t%d ; expire" % expire,
        "\t%d ; minimum" % minimum,
        ")",
    ]
    rest = sorted((r for r in records if r.rtype != "SOA"),
                  key=lambda r: (r.owner, r.rtype, r.rdata))
    for rec in rest:
        lines.append("%s %d IN %s %s" % (
            relative(rec.owner, zone), rec.ttl, rec.rtype, rec.rdata))
    return "\n".join(lines) + "\n"


def write_zone_file(path, text):
    """Write *text* to *path* atomically."""
    tmp = "%s.tmp.%d" % (path, os.getpid())
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path
