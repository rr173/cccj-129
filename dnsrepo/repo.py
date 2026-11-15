"""Repository facade: publishing, queries, diffs and export."""

from .errors import PrereqError, SerialError, ZoneError
from .generator import render_zone, write_zone_file
from .increment import apply_increment, parse_increment
from .names import absolutize, canon_zone, in_zone
from .records import serial_gt
from .store import Store
from .validate import validate_zone
from .zonefile import parse_master


class VersionInfo:
    def __init__(self, zone, serial, kind, source_file, published_at,
                 record_count):
        self.zone = zone
        self.serial = serial
        self.kind = kind
        self.source_file = source_file
        self.published_at = published_at
        self.record_count = record_count

    def __repr__(self):
        return "VersionInfo(%s serial=%d kind=%s records=%d)" % (
            self.zone, self.serial, self.kind, self.record_count)


class Answer:
    """Result of resolve(): status plus the CNAME chain and records."""

    def __init__(self, status, chain, records):
        self.status = status          # ok | nodata | nxname | external | loop
        self.chain = chain            # list of (owner, cname target)
        self.records = records

    def __repr__(self):
        return "Answer(%s, chain=%r, records=%r)" % (
            self.status, self.chain, self.records)


class Diff:
    def __init__(self, zone, from_serial, to_serial, added, removed):
        self.zone = zone
        self.from_serial = from_serial
        self.to_serial = to_serial
        self.added = added
        self.removed = removed

    def format(self):
        lines = ["--- %s serial %d" % (self.zone, self.from_serial),
                 "+++ %s serial %d" % (self.zone, self.to_serial)]
        for rec in self.removed:
            lines.append("- " + rec.to_line(self.zone))
        for rec in self.added:
            lines.append("+ " + rec.to_line(self.zone))
        return "\n".join(lines)


def _sort_key(rec):
    return (rec.owner, rec.rtype, rec.rdata, rec.ttl)


class Repository:
    """A versioned repository of DNS zones backed by SQLite."""

    def __init__(self, db_path, preserve_unknown=False):
        self.store = Store(db_path)
        self.preserve_unknown = preserve_unknown

    def close(self):
        self.store.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # --------------------------------------------------------------
    # publishing
    # --------------------------------------------------------------
    def publish_master(self, zone, text, source_file=None):
        """Parse, validate and publish a master zone file."""
        zone = canon_zone(zone)
        parsed = parse_master(text, zone,
                              preserve_unknown=self.preserve_unknown)
        serial = validate_zone(parsed.records, zone)
        zrow = self.store.ensure_zone(zone)
        current = self.store.current_version(zrow["id"])
        if current is not None and not serial_gt(serial, current["serial"]):
            raise SerialError(
                "master file serial %d does not increase over current "
                "serial %d" % (serial, current["serial"]))
        version_id = self.store.publish(zrow["id"], serial, "master",
                                        source_file, parsed.records)
        return self._version_info(zrow["id"], version_id)

    def publish_increment(self, text, source_file=None):
        """Parse, check and publish an increment against its baseline."""
        inc = parse_increment(text, preserve_unknown=self.preserve_unknown)
        zrow = self.store.get_zone(inc.zone)
        current = (self.store.current_version(zrow["id"])
                   if zrow is not None else None)
        if current is None:
            raise PrereqError("no baseline published for zone %s" % inc.zone)
        if current["serial"] != inc.prereq:
            raise PrereqError(
                "increment requires baseline serial %d but current serial "
                "is %d" % (inc.prereq, current["serial"]))
        if not serial_gt(inc.serial, inc.prereq):
            raise SerialError(
                "increment serial %d does not increase over prerequisite "
                "%d" % (inc.serial, inc.prereq))
        base = self.store.version_records(current["id"])
        new_records = apply_increment(base, inc, inc.zone)
        validate_zone(new_records, inc.zone, inc.serial)
        version_id = self.store.publish(zrow["id"], inc.serial, "increment",
                                        source_file, new_records)
        return self._version_info(zrow["id"], version_id)

    # --------------------------------------------------------------
    # queries
    # --------------------------------------------------------------
    def zones(self):
        """All zones with their current serial (None if unpublished)."""
        return [(row["name"], row["current_serial"])
                for row in self.store.list_zones()]

    def current(self, zone):
        """VersionInfo of the current published version, or None."""
        row = self.store.get_zone(canon_zone(zone))
        if row is None:
            return None
        ver = self.store.current_version(row["id"])
        if ver is None:
            return None
        return self._version_info(row["id"], ver["id"])

    def versions(self, zone):
        """All published versions of *zone*, oldest first."""
        row = self._zone_row(zone)
        return [self._version_info(row["id"], ver["id"])
                for ver in self.store.list_versions(row["id"])]

    def records(self, zone, serial=None):
        """Records of a version (current when *serial* is None)."""
        ver = self._version_row(zone, serial)
        return self.store.version_records(ver["id"])

    def lookup(self, zone, name, rtype=None):
        """Records at *name* in the current version of *zone*."""
        zone = canon_zone(zone)
        owner = absolutize(name, zone)
        recs = [r for r in self.records(zone) if r.owner == owner]
        if rtype is not None:
            rtype = rtype.upper()
            recs = [r for r in recs if r.rtype == rtype]
        return recs

    def resolve(self, zone, name, rtype="A"):
        """Resolve *name* inside the zone, following in-zone CNAMEs."""
        zone = canon_zone(zone)
        rtype = rtype.upper()
        current_name = absolutize(name, zone)
        chain = []
        for _ in range(64):
            recs = self.lookup(zone, current_name)
            exact = [r for r in recs if r.rtype == rtype]
            if exact:
                return Answer("ok", chain, exact)
            cnames = [r for r in recs if r.rtype == "CNAME"]
            if cnames:
                target = cnames[0].rdata
                chain.append((current_name, target))
                if not in_zone(target, zone):
                    return Answer("external", chain, [])
                current_name = target
                continue
            return Answer("nodata" if recs else "nxname", chain, [])
        return Answer("loop", chain, [])  # unreachable after validation

    def diff(self, zone, from_serial, to_serial):
        """Record-level diff between two published versions."""
        zone = canon_zone(zone)
        old = self.records(zone, from_serial)
        new = self.records(zone, to_serial)
        old_keys = {r.key() for r in old}
        new_keys = {r.key() for r in new}
        added = sorted((r for r in new if r.key() not in old_keys),
                       key=_sort_key)
        removed = sorted((r for r in old if r.key() not in new_keys),
                         key=_sort_key)
        return Diff(zone, from_serial, to_serial, added, removed)

    # --------------------------------------------------------------
    # export
    # --------------------------------------------------------------
    def export_text(self, zone, serial=None):
        """Render a version as a master zone file."""
        zone = canon_zone(zone)
        ver = self._version_row(zone, serial)
        recs = self.store.version_records(ver["id"])
        return render_zone(zone, ver["serial"], recs)

    def export_file(self, zone, path=None, serial=None):
        """Write a version to *path* atomically; returns the path."""
        zone = canon_zone(zone)
        text = self.export_text(zone, serial)
        if path is None:
            path = zone.rstrip(".") + ".zone"
        write_zone_file(path, text)
        return path

    # --------------------------------------------------------------
    # internals
    # --------------------------------------------------------------
    def _zone_row(self, zone):
        row = self.store.get_zone(canon_zone(zone))
        if row is None:
            raise ZoneError("unknown zone %s" % canon_zone(zone))
        return row

    def _version_row(self, zone, serial):
        row = self._zone_row(zone)
        if serial is None:
            ver = self.store.current_version(row["id"])
            if ver is None:
                raise ZoneError("zone %s has no published version"
                                % row["name"])
        else:
            ver = self.store.version_by_serial(row["id"], serial)
            if ver is None:
                raise ZoneError("zone %s has no published version with "
                                "serial %d" % (row["name"], serial))
        return ver

    def _version_info(self, zone_id, version_id):
        ver = self.store.get_version(version_id)
        zone = self.store.conn.execute(
            "SELECT name FROM zones WHERE id = ?", (zone_id,)).fetchone()
        return VersionInfo(
            zone=zone["name"],
            serial=ver["serial"],
            kind=ver["kind"],
            source_file=ver["source_file"],
            published_at=ver["created_at"],
            record_count=self.store.record_count(version_id),
        )
