"""Offline history handoff between repositories.

A handoff moves selected zone history out of one repository ("the old
library") and splices it into another, already populated one, without
flattening the history into a freshly imported zone file:

* :func:`pack_handoff` reads the source repository through **one
  consistent read view** (a single SQLite read transaction in WAL mode;
  writers are never blocked and no schema/recovery write is issued) and
  writes a self-contained package: every published snapshot of each
  selected zone from its first publication up to the chosen cutoff
  serial.  Snapshot *positions* are defined by insertion order; serial
  wraparound does not change positions.
* :func:`inspect_handoff` verifies a package standalone (integrity and
  semantics) and lists its zones, snapshot positions and record counts.
* :func:`receive_handoff` splices the package into the receiving
  repository.  For each zone with package history ``P1..Pn`` and
  receiver history ``T1..Tm`` the only decisions are *spliceable*
  (``m <= n`` and every ``Ti`` identical to ``Pi``) or *conflict*.
  Identical covers snapshot metadata, entries and origin coordinates;
  entry ordering and database row ids are ignored.  On success the
  first ``m`` snapshots are reused and only the tail is appended; the
  zone head lands on ``Pn``.  The whole package is one commit boundary.

Package format (UTF-8 JSON Lines, one object per line)::

    {"type":"header","format":"dnsrepo-handoff","format_version":1,...}
    {"type":"zone","name":"example.com.","snapshots":2}
    {"type":"snapshot","zone":"example.com.","position":1,"serial":100,
     "kind":"master","source_file":"zones/v1.zone","created_at":"...",
     "records":15}
    {"type":"record","owner":"www.example.com.","rtype":"A","ttl":300,
     "rdata":"192.0.2.80","known":true,"line_no":15,
     "origin_zone":"example.com.","origin_position":1,
     "source_file":"zones/v1.zone"}
    ... more records/snapshots/zones ...
    {"type":"trailer","zones":1,"snapshots":2,"records":30,
     "sha256":"<hex of all previous lines>"}

Every line is canonical JSON (sorted keys, compact separators) ending
in ``\\n``; the trailer's ``sha256`` covers the raw bytes of all
preceding lines, so truncation and tampering are detected before any
semantic check runs.  ``source_file``/``line_no`` may be null; null is
distinct from an empty string or any line number.  Origin coordinates
are ``(origin_zone, origin_position)`` — source-library row ids have no
meaning across libraries.  ``source_file`` values are opaque strings:
they are never opened or executed by the receiver.
"""

import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
from collections import Counter, namedtuple
from datetime import datetime, timezone

from .errors import HandoffError, HandoffConflict, ValidationError
from .names import canon_zone, validate_name
from .records import TTL_MAX, TYPE_RE, Record, serial_gt
from .validate import validate_zone

FORMAT_NAME = "dnsrepo-handoff"
FORMAT_VERSION = 1

SERIAL_MAX = 2 ** 32 - 1

__all__ = [
    "FORMAT_NAME", "FORMAT_VERSION",
    "SnapshotInfo", "ZoneInspection", "InspectionReport",
    "PackReport", "ZoneOutcome", "ReceiveReport", "Conflict",
    "pack_handoff", "inspect_handoff", "receive_handoff",
]


def _now():
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------
# reports
# --------------------------------------------------------------------------

class SnapshotInfo:
    """One snapshot inside a package: position, metadata, record count."""

    __slots__ = ("position", "serial", "kind", "source_file",
                 "created_at", "record_count")

    def __init__(self, position, serial, kind, source_file, created_at,
                 record_count):
        self.position = position
        self.serial = serial
        self.kind = kind
        self.source_file = source_file
        self.created_at = created_at
        self.record_count = record_count

    def __repr__(self):
        return ("SnapshotInfo(#%d serial=%d kind=%s records=%d)"
                % (self.position, self.serial, self.kind,
                   self.record_count))


class ZoneInspection:
    """Inspection result for one zone: name plus its snapshots."""

    def __init__(self, name, snapshots):
        self.name = name
        self.snapshots = snapshots

    @property
    def record_count(self):
        return sum(s.record_count for s in self.snapshots)

    def __repr__(self):
        return "ZoneInspection(%s, %d snapshots)" % (
            self.name, len(self.snapshots))


class InspectionReport:
    """Result of :func:`inspect_handoff`: zones, positions, counts."""

    def __init__(self, path, zones, sha256):
        self.path = path
        self.zones = zones
        self.sha256 = sha256

    @property
    def snapshot_count(self):
        return sum(len(z.snapshots) for z in self.zones)

    @property
    def record_count(self):
        return sum(z.record_count for z in self.zones)


class PackReport:
    """Result of :func:`pack_handoff`."""

    def __init__(self, path, zones, sha256):
        self.path = path
        self.zones = zones          # list of ZoneInspection
        self.sha256 = sha256

    @property
    def snapshot_count(self):
        return sum(len(z.snapshots) for z in self.zones)

    @property
    def record_count(self):
        return sum(z.record_count for z in self.zones)


class Conflict(namedtuple("Conflict", ["zone", "serial", "category",
                                       "detail"])):
    """One splice divergence: zone, serial and mismatch category."""
    __slots__ = ()


class ZoneOutcome:
    """Per-zone receive outcome: how many snapshots were reused and how
    many appended, and where the zone head landed."""

    __slots__ = ("zone", "reused", "appended", "head_serial")

    def __init__(self, zone, reused, appended, head_serial):
        self.zone = zone
        self.reused = reused
        self.appended = appended
        self.head_serial = head_serial

    def __repr__(self):
        return ("ZoneOutcome(%s reused=%d appended=%d head=%s)"
                % (self.zone, self.reused, self.appended,
                   self.head_serial))


class ReceiveReport:
    """Result of :func:`receive_handoff` (returned only on success)."""

    def __init__(self, path, outcomes):
        self.path = path
        self.outcomes = outcomes

    @property
    def reused(self):
        return sum(o.reused for o in self.outcomes)

    @property
    def appended(self):
        return sum(o.appended for o in self.outcomes)


# --------------------------------------------------------------------------
# canonical JSON lines + integrity
# --------------------------------------------------------------------------

def _dumps(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8") + b"\n"


class _PackageWriter:
    """Writes package lines to a temp file and hashes everything but the
    trailer.  The file only becomes visible through :func:`_install`."""

    def __init__(self, tmp_path):
        self.fh = open(tmp_path, "wb")
        self.hasher = hashlib.sha256()
        self.counts = {"zones": 0, "snapshots": 0, "records": 0}

    def line(self, obj):
        data = _dumps(obj)
        self.hasher.update(data)
        self.fh.write(data)
        key = {"zone": "zones", "snapshot": "snapshots",
               "record": "records"}.get(obj["type"])
        if key is not None:
            self.counts[key] += 1

    def finish(self):
        trailer = {"type": "trailer",
                   "zones": self.counts["zones"],
                   "snapshots": self.counts["snapshots"],
                   "records": self.counts["records"],
                   "sha256": self.hasher.hexdigest()}
        self.fh.write(_dumps(trailer))
        self.fh.flush()
        os.fsync(self.fh.fileno())
        self.fh.close()
        return trailer["sha256"]

    def abort(self):
        try:
            self.fh.close()
        except OSError:
            pass


def _install(tmp_path, out_path):
    """Move the finished package into place without ever overwriting."""
    try:
        os.link(tmp_path, out_path)
    except FileExistsError:
        raise HandoffError("output package %s already exists "
                           "(refusing to overwrite)" % out_path)
    except OSError as exc:
        raise HandoffError("cannot install package %s: %s"
                           % (out_path, exc))
    os.unlink(tmp_path)


# --------------------------------------------------------------------------
# packing (source side)
# --------------------------------------------------------------------------

def _normalize_selections(selections):
    """Validate the handoff manifest: each zone at most once, cutoff
    serials in range.  Returns {canonical zone: serial}."""
    if hasattr(selections, "items"):
        items = list(selections.items())
    else:
        items = list(selections)
    if not items:
        raise HandoffError("handoff selection is empty")
    chosen = {}
    for zone, serial in items:
        try:
            zname = canon_zone(zone)
        except Exception as exc:
            raise HandoffError("bad zone name %r: %s" % (zone, exc))
        if zname in chosen:
            raise HandoffError("zone %s selected more than once" % zname)
        if not isinstance(serial, int) or isinstance(serial, bool) \
                or not 0 <= serial <= SERIAL_MAX:
            raise HandoffError("bad cutoff serial %r for zone %s"
                               % (serial, zname))
        chosen[zname] = serial
    return chosen


def pack_handoff(db_path, selections, out_path, after_begin=None):
    """Pack the selected zone histories from *db_path* into *out_path*.

    *selections* maps zone names to cutoff serials (or is an iterable of
    ``(zone, serial)`` pairs); each zone may be selected only once and
    the cutoff must be a published serial.  The package contains every
    published snapshot of each selected zone from its first publication
    up to the cutoff, in insertion order.

    All reads happen inside one SQLite read transaction, so the package
    is a consistent view of the source repository even while other
    processes keep writing to it.  The source is opened with a bare
    connection (``query_only``): no schema or recovery write is ever
    issued, and WAL content committed before the snapshot is fully
    visible.  *out_path* must not exist; the package appears there
    atomically (temp file + hard link) or not at all.

    *after_begin* is an optional hook invoked right after the read
    transaction opens (used by tests to interleave a concurrent
    writer).
    """
    chosen = _normalize_selections(selections)
    if not os.path.isfile(db_path):
        raise HandoffError("source repository %s does not exist" % db_path)
    if os.path.exists(out_path):
        raise HandoffError("output package %s already exists "
                           "(refusing to overwrite)" % out_path)

    tmp = "%s.tmp.%d" % (out_path, os.getpid())
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.isolation_level = None  # manual transaction control
    try:
        try:
            conn.execute("PRAGMA query_only = ON")
            conn.execute("BEGIN")  # one consistent read view
            # Pin the snapshot: in WAL mode the read view starts at the
            # first SELECT, so make that moment explicit — everything
            # below reads this one committed view, no matter what other
            # processes commit afterwards.
            conn.execute("SELECT COUNT(*) FROM zones").fetchone()
            if after_begin is not None:
                after_begin()
            try:
                writer = _PackageWriter(tmp)
            except OSError as exc:
                raise HandoffError("cannot create package file %s: %s"
                                   % (tmp, exc))
            try:
                from . import __version__
                writer.line({"type": "header",
                             "format": FORMAT_NAME,
                             "format_version": FORMAT_VERSION,
                             "created_at": _now(),
                             "generator": "dnsrepo %s" % __version__})
                zones_out = []
                for zone in sorted(chosen):
                    zones_out.append(
                        _pack_zone(conn, zone, chosen[zone], writer))
                sha256 = writer.finish()
            except BaseException:
                writer.abort()
                raise
        except sqlite3.Error as exc:
            raise HandoffError("cannot read source repository %s: %s"
                               % (db_path, exc))
        finally:
            conn.rollback()
        _install(tmp, out_path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    finally:
        conn.close()
    return PackReport(out_path, zones_out, sha256)


def _pack_zone(conn, zone, cutoff, writer):
    """Write one zone section; returns its ZoneInspection."""
    zrow = conn.execute("SELECT * FROM zones WHERE name = ?",
                        (zone,)).fetchone()
    if zrow is None:
        raise HandoffError("zone %s not found in source repository"
                           % zone)
    versions = conn.execute(
        "SELECT * FROM versions WHERE zone_id = ? AND status = 'published' "
        "ORDER BY id", (zrow["id"],)).fetchall()
    cut_index = None
    for index, ver in enumerate(versions):
        if ver["serial"] == cutoff:
            cut_index = index
            break
    if cut_index is None:
        raise HandoffError("zone %s has no published version with serial "
                           "%d" % (zone, cutoff))
    included = versions[:cut_index + 1]
    position_of = {ver["id"]: pos for pos, ver in enumerate(included, 1)}
    writer.line({"type": "zone", "name": zone, "snapshots": len(included)})
    snapshots = []
    for position, ver in enumerate(included, 1):
        count = conn.execute(
            "SELECT COUNT(*) AS n FROM records WHERE version_id = ?",
            (ver["id"],)).fetchone()["n"]
        writer.line({"type": "snapshot", "zone": zone,
                     "position": position, "serial": ver["serial"],
                     "kind": ver["kind"], "source_file": ver["source_file"],
                     "created_at": ver["created_at"], "records": count})
        snapshots.append(SnapshotInfo(position, ver["serial"], ver["kind"],
                                      ver["source_file"], ver["created_at"],
                                      count))
        for rec in conn.execute(
                "SELECT owner, rtype, ttl, rdata, known, line_no, "
                "introduced_in FROM records WHERE version_id = ? "
                "ORDER BY id", (ver["id"],)):
            origin = position_of.get(rec["introduced_in"])
            if origin is None:
                raise HandoffError(
                    "source repository is inconsistent: a record of zone "
                    "%s refers to version id %d which is not published"
                    % (zone, rec["introduced_in"]))
            writer.line({"type": "record", "owner": rec["owner"],
                         "rtype": rec["rtype"], "ttl": rec["ttl"],
                         "rdata": rec["rdata"],
                         "known": bool(rec["known"]),
                         "line_no": rec["line_no"],
                         "origin_zone": zone,
                         "origin_position": origin,
                         "source_file": included[origin - 1]["source_file"]})
    return ZoneInspection(zone, snapshots)


# --------------------------------------------------------------------------
# streaming package reader (integrity + semantics)
# --------------------------------------------------------------------------

class _OriginIndex:
    """On-disk index of self-introduced records, used to validate origin
    coordinates without holding the package in memory."""

    def __init__(self, db_path):
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA journal_mode = OFF")
        self.conn.execute("PRAGMA synchronous = OFF")
        self.conn.execute("PRAGMA cache_size = -16000")
        self.conn.executescript(
            "CREATE TABLE introduced ("
            " zone TEXT NOT NULL, position INTEGER NOT NULL,"
            " owner TEXT NOT NULL, rtype TEXT NOT NULL,"
            " ttl INTEGER NOT NULL, rdata TEXT NOT NULL,"
            " known INTEGER NOT NULL, line_no INTEGER);"
            "CREATE INDEX idx_introduced"
            " ON introduced(zone, position, owner, rtype);")

    def add(self, zone, position, rec):
        self.conn.execute(
            "INSERT INTO introduced (zone, position, owner, rtype, ttl, "
            "rdata, known, line_no) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (zone, position, rec.owner, rec.rtype, rec.ttl, rec.rdata,
             1 if rec.known else 0, rec.line_no))

    def contains(self, zone, position, rec):
        row = self.conn.execute(
            "SELECT 1 FROM introduced WHERE zone = ? AND position = ? "
            "AND owner = ? AND rtype = ? AND ttl = ? AND rdata = ? "
            "AND known = ? AND line_no IS ? LIMIT 1",
            (zone, position, rec.owner, rec.rtype, rec.ttl, rec.rdata,
             1 if rec.known else 0, rec.line_no)).fetchone()
        return row is not None

    def close(self):
        self.conn.close()


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


class _PackageReader:
    """Streams a package as validated events.

    Events (generated in file order)::

        ("header", dict)              format identification
        ("zone", dict)                zone section starts
        ("snapshot", SnapshotInfo, [Record, ...])
                                      one complete, validated snapshot;
                                      Record.introduced_in is the package
                                      position of the introducing
                                      snapshot, Record.source_file that
                                      snapshot's source_file
        ("trailer", dict)             counts and digest verified

    Every structural, integrity and semantic rule is enforced while
    streaming; anything fishy raises HandoffError.  Memory use is
    bounded by one snapshot plus the on-disk origin index.
    """

    def __init__(self, path):
        self.path = path

    def events(self):
        workdir = tempfile.mkdtemp(prefix=".dnsrepo-handoff-")
        try:
            index = _OriginIndex(os.path.join(workdir, "origins.db"))
            try:
                for event in self._run(index):
                    yield event
            finally:
                index.close()
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    # -- state machine ------------------------------------------------
    def _run(self, index):
        state = _ReaderState()
        try:
            fh = open(self.path, "rb")
        except OSError as exc:
            raise HandoffError("cannot open package %s: %s"
                               % (self.path, exc))
        with fh:
            for raw in fh:
                state.line_no += 1
                if not raw.endswith(b"\n"):
                    raise HandoffError("truncated line (package is "
                                       "truncated or corrupt)",
                                       state.line_no)
                for event in self._feed(raw, state, index):
                    yield event
                if state.done:
                    break
            if not state.done:
                if state.line_no == 0:
                    raise HandoffError("package is empty")
                raise HandoffError("package is truncated (no trailer)")
            if fh.read(1):
                raise HandoffError("unexpected content after the trailer",
                                   state.line_no)

    def _feed(self, raw, state, index):
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise HandoffError("invalid JSON: %s" % exc, state.line_no)
        if not isinstance(obj, dict) or not isinstance(obj.get("type"), str):
            raise HandoffError("line is not a typed package object",
                               state.line_no)
        ltype = obj["type"]
        if ltype == "trailer":
            events = list(self._close_snapshot(state))
            events.extend(self._trailer(obj, state))
            return events
        state.hasher.update(raw)
        if ltype == "header":
            return self._header(obj, state)
        if ltype == "zone":
            events = list(self._close_snapshot(state))
            events.extend(self._zone(obj, state))
            return events
        if ltype == "snapshot":
            events = list(self._close_snapshot(state))
            events.extend(self._snapshot(obj, state))
            return events
        if ltype == "record":
            return self._record(obj, state, index)
        raise HandoffError("unknown object type %r" % ltype, state.line_no)

    # -- line handlers --------------------------------------------------
    def _header(self, obj, state):
        if state.line_no != 1:
            raise HandoffError("the header must be the first line",
                               state.line_no)
        if obj.get("format") != FORMAT_NAME:
            raise HandoffError("unrecognized package format %r"
                               % obj.get("format"), state.line_no)
        if obj.get("format_version") != FORMAT_VERSION:
            raise HandoffError("unsupported format version %r"
                               % obj.get("format_version"), state.line_no)
        state.header_seen = True
        return [("header", obj)]

    def _zone(self, obj, state):
        self._require_header(state)
        if state.zone is not None:
            self._check_zone_complete(state)
        name = self._str(obj, "name", state)
        try:
            if canon_zone(name) != name:
                raise HandoffError("zone name %r is not in canonical "
                                   "form" % name, state.line_no)
        except HandoffError:
            raise
        except Exception as exc:
            raise HandoffError("bad zone name %r: %s" % (name, exc),
                               state.line_no)
        if name in state.zone_names:
            raise HandoffError("duplicate zone %s" % name, state.line_no)
        declared = self._int(obj, "snapshots", state, lo=1)
        state.zone_names.add(name)
        state.zone = name
        state.zone_declared = declared
        state.zone_seen = 0
        state.position = 0
        state.prev_serial = None
        state.source_files = {}
        return [("zone", {"name": name, "snapshots": declared})]

    def _snapshot(self, obj, state):
        self._require_header(state)
        if state.zone is None:
            raise HandoffError("snapshot outside any zone", state.line_no)
        state.position += 1
        if state.position > state.zone_declared:
            raise HandoffError("zone %s has more snapshots than the "
                               "declared %d" % (state.zone,
                                                state.zone_declared),
                               state.line_no)
        if obj.get("zone") != state.zone:
            raise HandoffError("snapshot belongs to zone %r but appears "
                               "inside %s" % (obj.get("zone"), state.zone),
                               state.line_no)
        position = self._int(obj, "position", state, lo=1)
        if position != state.position:
            raise HandoffError("snapshot position %d does not follow "
                               "position %d" % (position, state.position - 1),
                               state.line_no)
        serial = self._int(obj, "serial", state, lo=0, hi=SERIAL_MAX)
        if state.prev_serial is not None \
                and not serial_gt(serial, state.prev_serial):
            raise HandoffError("snapshot serial %d does not increase over "
                               "previous serial %d (bad publish order)"
                               % (serial, state.prev_serial), state.line_no)
        kind = obj.get("kind")
        if kind not in ("master", "increment"):
            raise HandoffError("bad snapshot kind %r" % (kind,),
                               state.line_no)
        source_file = self._str_or_null(obj, "source_file", state)
        created_at = self._str(obj, "created_at", state)
        try:
            datetime.fromisoformat(created_at)
        except ValueError:
            raise HandoffError("bad created_at timestamp %r" % created_at,
                               state.line_no)
        records = self._int(obj, "records", state, lo=0)
        state.prev_serial = serial
        state.source_files[state.position] = source_file
        state.zone_seen += 1
        state.snapshots += 1
        state.pending = SnapshotInfo(position, serial, kind, source_file,
                                     created_at, records)
        state.pending_records = []
        return []

    def _record(self, obj, state, index):
        self._require_header(state)
        if state.pending is None:
            raise HandoffError("record outside any snapshot", state.line_no)
        if len(state.pending_records) >= state.pending.record_count:
            raise HandoffError("snapshot #%d of zone %s declares %d "
                               "records but more follow"
                               % (state.pending.position, state.zone,
                                  state.pending.record_count),
                               state.line_no)
        owner = self._str(obj, "owner", state)
        try:
            validate_name(owner)
        except Exception as exc:
            raise HandoffError("bad owner name %r: %s" % (owner, exc),
                               state.line_no)
        rtype = self._str(obj, "rtype", state)
        if not TYPE_RE.match(rtype):
            raise HandoffError("bad record type %r" % rtype, state.line_no)
        ttl = self._int(obj, "ttl", state, lo=0, hi=TTL_MAX)
        rdata = self._str(obj, "rdata", state)
        known = obj.get("known")
        if not isinstance(known, bool):
            raise HandoffError("known must be true or false", state.line_no)
        line_no = obj.get("line_no")
        if line_no is not None and (not _is_int(line_no) or line_no < 1):
            raise HandoffError("line_no must be null or a positive "
                               "integer", state.line_no)
        origin_zone = self._str(obj, "origin_zone", state)
        if origin_zone != state.zone:
            raise HandoffError("record origin points to zone %r, not the "
                               "current zone %s (cross-zone origins are "
                               "invalid)" % (origin_zone, state.zone),
                               state.line_no)
        origin = self._int(obj, "origin_position", state, lo=1)
        if origin > state.position:
            raise HandoffError("record origin position %d points into the "
                               "future (current position is %d)"
                               % (origin, state.position), state.line_no)
        source_file = self._str_or_null(obj, "source_file", state)
        if source_file != state.source_files[origin]:
            raise HandoffError(
                "record claims source_file %r but its origin snapshot #%d "
                "has source_file %r"
                % (source_file, origin, state.source_files[origin]),
                state.line_no)
        rec = Record(owner, rtype, ttl, rdata, known=known, line_no=line_no,
                     introduced_in=origin, source_file=source_file)
        if origin == state.position:
            index.add(state.zone, origin, rec)
        elif not index.contains(state.zone, origin, rec):
            raise HandoffError(
                "record origin snapshot #%d of zone %s has no matching "
                "self-introduced record for %s %s"
                % (origin, state.zone, owner, rtype), state.line_no)
        state.pending_records.append(rec)
        state.records += 1
        if len(state.pending_records) == state.pending.record_count:
            return list(self._close_snapshot(state))
        return []

    def _close_snapshot(self, state):
        """Finish the pending snapshot (if any): count, zone semantics."""
        if state.pending is None:
            return
        info = state.pending
        records = state.pending_records
        if len(records) != info.record_count:
            raise HandoffError("snapshot #%d of zone %s declares %d "
                               "records but %d were found"
                               % (info.position, state.zone,
                                  info.record_count, len(records)),
                               state.line_no)
        try:
            validate_zone(records, state.zone, info.serial)
        except ValidationError as exc:
            raise HandoffError("snapshot #%d of zone %s is not a valid "
                               "zone: %s" % (info.position, state.zone,
                                             exc), state.line_no)
        state.pending = None
        state.pending_records = []
        yield ("snapshot", info, records)

    def _trailer(self, obj, state):
        self._require_header(state)
        if state.zone is None:
            raise HandoffError("package contains no zones", state.line_no)
        self._check_zone_complete(state)
        for key, actual in (("zones", len(state.zone_names)),
                            ("snapshots", state.snapshots),
                            ("records", state.records)):
            declared = self._int(obj, key, state, lo=0)
            if declared != actual:
                raise HandoffError("trailer declares %d %s but the "
                                   "package contains %d"
                                   % (declared, key, actual),
                                   state.line_no)
        digest = obj.get("sha256")
        if not isinstance(digest, str) or len(digest) != 64:
            raise HandoffError("trailer has no valid sha256 digest",
                               state.line_no)
        actual = state.hasher.hexdigest()
        if digest != actual:
            raise HandoffError("integrity check failed: trailer sha256 "
                               "does not match the package content",
                               state.line_no)
        state.done = True
        return [("trailer", obj)]

    # -- helpers --------------------------------------------------------
    def _require_header(self, state):
        if not state.header_seen:
            raise HandoffError("the first line must be the package "
                               "header", state.line_no)

    def _check_zone_complete(self, state):
        if state.zone_seen != state.zone_declared:
            raise HandoffError("zone %s declares %d snapshots but %d "
                               "were found" % (state.zone,
                                               state.zone_declared,
                                               state.zone_seen),
                               state.line_no)

    @staticmethod
    def _str(obj, key, state):
        value = obj.get(key)
        if not isinstance(value, str):
            raise HandoffError("field %r must be a string" % key,
                               state.line_no)
        return value

    @staticmethod
    def _str_or_null(obj, key, state):
        value = obj.get(key)
        if value is not None and not isinstance(value, str):
            raise HandoffError("field %r must be a string or null" % key,
                               state.line_no)
        return value

    @staticmethod
    def _int(obj, key, state, lo=None, hi=None):
        value = obj.get(key)
        if not _is_int(value):
            raise HandoffError("field %r must be an integer" % key,
                               state.line_no)
        if lo is not None and value < lo:
            raise HandoffError("field %r must be >= %d" % (key, lo),
                               state.line_no)
        if hi is not None and value > hi:
            raise HandoffError("field %r must be <= %d" % (key, hi),
                               state.line_no)
        return value


class _ReaderState:
    def __init__(self):
        self.line_no = 0
        self.hasher = hashlib.sha256()
        self.header_seen = False
        self.done = False
        self.zone = None
        self.zone_names = set()
        self.zone_declared = 0
        self.zone_seen = 0
        self.position = 0
        self.prev_serial = None
        self.source_files = {}
        self.pending = None
        self.pending_records = []
        self.snapshots = 0
        self.records = 0


# --------------------------------------------------------------------------
# inspection (standalone verification)
# --------------------------------------------------------------------------

def inspect_handoff(package_path):
    """Verify a handoff package and list its contents.

    Checks integrity (structure, counts, sha256) and semantics (field
    validity, publish order, zone semantics per snapshot, origin
    coordinates).  Returns an InspectionReport; raises HandoffError on
    the first problem found.
    """
    zones = []
    digest = None
    current = None
    reader = _PackageReader(package_path)
    events = reader.events()
    try:
        for kind, *payload in events:
            if kind == "zone":
                current = ZoneInspection(payload[0]["name"], [])
                zones.append(current)
            elif kind == "snapshot":
                current.snapshots.append(payload[0])
            elif kind == "trailer":
                digest = payload[0]["sha256"]
    finally:
        events.close()
    return InspectionReport(package_path, zones, digest)


# --------------------------------------------------------------------------
# receiving (splice into the target repository)
# --------------------------------------------------------------------------

def receive_handoff(repo, package_path):
    """Splice the package into *repo*'s repository.

    For every package zone the receiver's published history ``T1..Tm``
    is compared with the package history ``P1..Pn`` (m = 0 for zones the
    receiver does not have).  Spliceable means ``m <= n`` and each
    ``Ti`` identical to ``Pi`` — snapshot metadata, entries and origin
    coordinates all compare, entry order and row ids do not.  A
    spliceable zone keeps its first ``m`` versions and only the tail
    ``P(m+1)..Pn`` is appended, with fresh target-side ids; origin
    references are mapped through those ids, reused prefix included.
    Receiving the same package twice changes nothing.

    Checking and writing share one write transaction (the whole package
    is a single commit boundary): any conflict, package defect or
    database error rolls back everything, and decisions are only made
    on state read after the write lock was acquired.
    """
    store = repo.store
    outcomes = []
    conflicts = []
    with store.write_txn():
        reader = _PackageReader(package_path)
        events = reader.events()
        ctx = None
        try:
            for kind, *payload in events:
                if kind == "zone":
                    if ctx is not None:
                        outcomes.append(ctx.outcome())
                    ctx = _ZoneReceive(store, payload[0]["name"],
                                       payload[0]["snapshots"], conflicts)
                elif kind == "snapshot":
                    ctx.handle_snapshot(payload[0], payload[1])
                elif kind == "trailer":
                    if ctx is not None:
                        outcomes.append(ctx.outcome())
                        ctx = None
        finally:
            events.close()
        if conflicts:
            raise HandoffConflict(conflicts)
    return ReceiveReport(package_path, outcomes)


class _ZoneReceive:
    """Compare-and-splice state for one package zone."""

    def __init__(self, store, zone, n_snapshots, conflicts):
        self.store = store
        self.zone = zone
        self.n = n_snapshots
        self.conflicts = conflicts
        self.zrow = store.get_zone(zone)
        if self.zrow is None:
            self.zrow = store.ensure_zone(zone)
        self.targets = store.conn.execute(
            "SELECT * FROM versions WHERE zone_id = ? "
            "AND status = 'published' ORDER BY id",
            (self.zrow["id"],)).fetchall()
        self.m = len(self.targets)
        # position -> target version id, reused prefix included
        self.pos_map = {i + 1: row["id"] for i, row in
                        enumerate(self.targets)}
        self.target_pos = {row["id"]: i + 1 for i, row in
                           enumerate(self.targets)}
        self.ok = True
        self.head_serial = None
        if self.m > self.n:
            self.ok = False
            conflicts.append(Conflict(
                zone, self.targets[self.n]["serial"], "target-longer",
                "receiver already has %d published versions but the "
                "package carries only %d (refusing to drop history)"
                % (self.m, self.n)))

    def handle_snapshot(self, info, records):
        if not self.ok:
            return
        self.head_serial = info.serial
        if info.position <= self.m:
            problem = self._compare(self.targets[info.position - 1],
                                    info, records)
            if problem is not None:
                category, detail = problem
                self.conflicts.append(Conflict(self.zone, info.serial,
                                               category, detail))
                self.ok = False
            return
        version_id = self.store._insert_version(
            self.zrow["id"], info.serial, info.kind, info.source_file,
            created_at=info.created_at)
        self.pos_map[info.position] = version_id
        mapped = [Record(r.owner, r.rtype, r.ttl, r.rdata, known=r.known,
                         line_no=r.line_no,
                         introduced_in=self.pos_map[r.introduced_in])
                  for r in records]
        self.store._insert_records(version_id, mapped)
        self.store._finalize(self.zrow["id"], version_id)

    def outcome(self):
        return ZoneOutcome(self.zone, self.m if self.ok else 0,
                           self.n - self.m if self.ok else 0,
                           self.head_serial)

    def _compare(self, trow, info, records):
        """None when the receiver version equals the package snapshot."""
        if trow["serial"] != info.serial:
            return ("serial", "receiver has serial %d, package has "
                    "serial %d" % (trow["serial"], info.serial))
        if trow["kind"] != info.kind:
            return ("metadata", "kind: receiver has %r, package has %r"
                    % (trow["kind"], info.kind))
        if trow["source_file"] != info.source_file:
            return ("metadata", "source_file: receiver has %r, package "
                    "has %r" % (trow["source_file"], info.source_file))
        if trow["created_at"] != info.created_at:
            return ("metadata", "created_at: receiver has %r, package "
                    "has %r" % (trow["created_at"], info.created_at))
        db_records = Counter()
        for row in self.store.conn.execute(
                "SELECT owner, rtype, ttl, rdata, known, line_no, "
                "introduced_in FROM records WHERE version_id = ?",
                (trow["id"],)):
            origin = self.target_pos.get(row["introduced_in"])
            if origin is None:
                raise HandoffError(
                    "receiver database is inconsistent: a record of zone "
                    "%s refers to version id %d which is not published"
                    % (self.zone, row["introduced_in"]))
            db_records[(row["owner"], row["rtype"], row["ttl"],
                        row["rdata"], bool(row["known"]), row["line_no"],
                        origin)] += 1
        pkg_records = Counter(
            (r.owner, r.rtype, r.ttl, r.rdata, r.known, r.line_no,
             r.introduced_in) for r in records)
        if db_records != pkg_records:
            only_db = next(iter(db_records - pkg_records), None)
            only_pkg = next(iter(pkg_records - db_records), None)
            return ("records", "record sets differ: only in receiver: "
                    "%r; only in package: %r" % (only_db, only_pkg))
        return None
