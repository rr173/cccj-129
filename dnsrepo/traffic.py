"""Offline flow-to-ownership attribution.

The batch reads two UTF-8 JSONL files:

* connection summaries: ``flow_id``, ``dst_ip``, ``start_ms``, ``end_ms``,
  ``bytes``
* ownership facts: ``cidr``, ``owner``, ``valid_from_ms``, ``valid_to_ms``

For every destination address and every instant of a connection it picks
the *longest* ownership prefix valid at that instant.  A tie between two
different owners at the same longest prefix is ``ambiguous``; no owner is
chosen and no wider prefix is used.  The connection is then cut into
maximal runs with an identical status/owner set, and the connection's
integer byte count is apportioned over those final runs with an exact
largest-remainder computation.

Everything that can grow with the input lives in temporary SQLite files
or is streamed: flows and ownership rows are loaded into disk tables in
bounded chunks, ownership is looked up through the
``(family, prefix_key, prefix_len)`` index (one equality probe per
connection for each prefix length that occurs in the data, never a scan),
and only one connection's candidate rows and merged fragments are held in
memory at a time.  Detail rows are streamed to a spool file, DNS labels
and per-owner totals live in disk tables, and each SQLite cache is capped
at 16 MB.

The finished directory is only moved into place after validation,
attribution and accounting have all succeeded.  An existing target is
never overwritten.
"""

import ipaddress
import json
import os
import shutil
import sqlite3
import tempfile
from urllib.parse import quote

from .errors import BatchError
from .names import canon_zone

INT64_MIN = -(2 ** 63)
INT64_MAX = 2 ** 63 - 1

STATUSES = ("assigned", "ambiguous", "unassigned")

DETAIL_FILE = "details.jsonl"
SUMMARY_FILE = "summary.json"

INDEX_SCHEMA = """
CREATE TABLE flows (
    line_no     INTEGER PRIMARY KEY,
    flow_id     TEXT NOT NULL UNIQUE,
    dst_ip      TEXT NOT NULL,
    family      INTEGER NOT NULL,       -- 4 or 6
    ip_key      TEXT NOT NULL,
    start_ms    INTEGER NOT NULL,
    end_ms      INTEGER NOT NULL,
    bytes       INTEGER NOT NULL
);
CREATE TABLE labels (
    family  INTEGER NOT NULL,
    ip_key  TEXT NOT NULL,
    owner   TEXT NOT NULL,
    PRIMARY KEY (family, ip_key, owner)
) WITHOUT ROWID;
CREATE TABLE ranges (
    id          INTEGER PRIMARY KEY,
    line_no     INTEGER NOT NULL UNIQUE,
    cidr        TEXT NOT NULL,
    owner       TEXT NOT NULL,
    family      INTEGER NOT NULL,       -- 4 or 6
    prefix_key  TEXT NOT NULL,          -- network address, fixed-width hex
    prefix_len  INTEGER NOT NULL,
    valid_from  INTEGER NOT NULL,
    valid_to    INTEGER NOT NULL
);
CREATE INDEX ranges_lookup ON ranges(family, prefix_key, prefix_len);
CREATE INDEX ranges_family ON ranges(family);
CREATE TABLE prefix_keys (
    family     INTEGER NOT NULL,
    prefix_len INTEGER NOT NULL,
    PRIMARY KEY (family, prefix_len)
);
"""

SUMMARY_SCHEMA = """
CREATE TABLE status_totals (
    status TEXT PRIMARY KEY,
    bytes  INTEGER NOT NULL
);
CREATE TABLE owner_totals (
    owner TEXT PRIMARY KEY,
    bytes INTEGER NOT NULL
);
"""


# --------------------------------------------------------------------------
# validation helpers
# --------------------------------------------------------------------------

def _json_line(raw, source, line_no):
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BatchError("not valid UTF-8 (%s)" % exc.reason, source, line_no)
    if not text.strip():
        # Blank separators are tolerated; they carry no record.
        return None
    if text.startswith("\ufeff"):
        # A UTF-8 BOM is not JSON.  It is tolerated once, at the very
        # start of the file, as an encoding marker; anywhere else it is a
        # malformed line.
        if line_no != 1:
            raise BatchError("unexpected UTF-8 BOM", source, line_no)
        text = text[1:]
        if not text.strip():
            return None
    try:
        value = json.loads(text)
    except ValueError as exc:
        raise BatchError("invalid JSON: %s" % exc, source, line_no)
    if not isinstance(value, dict):
        raise BatchError("expected a JSON object, got %s"
                         % type(value).__name__, source, line_no)
    return value


def _require(obj, field, source, line_no):
    if field not in obj:
        raise BatchError("missing field %r" % field, source, line_no)
    return obj[field]


def _integer(value, field, source, line_no):
    if isinstance(value, bool) or not isinstance(value, int):
        raise BatchError("%s must be an integer, got %s"
                         % (field, _field_str(value)), source, line_no)
    if not INT64_MIN <= value <= INT64_MAX:
        raise BatchError("%s does not fit in a signed 64-bit integer"
                         % field, source, line_no)
    return value


def _nonempty_string(value, field, source, line_no):
    if not isinstance(value, str) or value == "":
        raise BatchError("%s must be a non-empty string, got %s"
                         % (field, _field_str(value)), source, line_no)
    return value


def _field_str(value):
    """Canonical text for a JSON field value (used in error messages)."""
    try:
        text = json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        text = repr(value)
    return text if len(text) <= 80 else text[:77] + "..."


def ip_key(address):
    """Fixed-width lowercase hex key for an address integer (sortable).

    IPv4 keys are 8 hex digits and IPv6 keys 32, and they are only ever
    compared within one address family.
    """
    width = 8 if address.version == 4 else 32
    return format(int(address), "0%dx" % width)


def _prefix_of_key(key, prefix_len):
    """First *prefix_len* bits of a hex address key.

    ``prefix_len // 4`` whole hex digits plus, for lengths not divisible by
    four, the enclosing hex digit with its low bits cleared.  Using only
    ``prefix_len // 4`` digits would make e.g. ``/25`` networks share a key
    with the opposite half of the same ``/24``.
    """
    whole, remainder = divmod(prefix_len, 4)
    if not remainder:
        return key[:whole]
    nibble = int(key[whole], 16) & (0xF << (4 - remainder) & 0xF)
    return key[:whole] + format(nibble, "x")


def prefix_key(address, prefix_len):
    """Hex key of the first *prefix_len* bits of *address*."""
    width = 8 if address.version == 4 else 32
    return _prefix_of_key(format(int(address), "0%dx" % width), prefix_len)


def parse_dst_ip(text, source, line_no):
    """Parse a destination address, preserving its address family.

    An IPv4-mapped IPv6 address such as ``::ffff:192.0.2.1`` stays an
    IPv6 address; it is never reinterpreted as IPv4.
    """
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        raise BatchError("dst_ip %r is not a valid IP address"
                         % text, source, line_no)
    return address


def parse_cidr(text, source, line_no):
    """Parse a canonical CIDR: no host bits, valid IPv4 or IPv6.

    ``strict=True`` rejects any host bits and any malformed prefix; a
    mapped IPv6 network such as ``::ffff:192.0.2.0/120`` stays IPv6.
    """
    try:
        return ipaddress.ip_network(text, strict=True)
    except ValueError as exc:
        raise BatchError("cidr %r is not a canonical network (%s)"
                         % (text, exc), source, line_no)


# --------------------------------------------------------------------------
# input loading (streams the files, writes only to disk tables)
# --------------------------------------------------------------------------

def _read_lines(path, source, on_record):
    """Stream *path* as JSONL, decoding one line at a time.

    ``on_record(obj, line_no)`` is called for every non-blank line.  The
    file is opened in binary and decoded per line so a malformed byte is
    reported with its line number instead of aborting the whole decode.
    """
    with open(path, "rb") as fh:
        for line_no, raw in enumerate(fh, 1):
            record = _json_line(raw, source, line_no)
            if record is not None:
                on_record(record, line_no)


class _Loader:
    """Validates JSONL inputs into a temporary SQLite index."""

    def __init__(self, db_path):
        self.conn = sqlite3.connect(db_path)
        # One bounded page cache per temporary database (16 MB) so memory
        # does not grow with the number of connections or ownership rows.
        self.conn.execute("PRAGMA journal_mode = OFF")
        self.conn.execute("PRAGMA synchronous = OFF")
        self.conn.execute("PRAGMA cache_size = -16000")
        self.prefix_lengths = {4: [], 6: []}
        self.total_bytes = 0
        self.conn.executescript(INDEX_SCHEMA)

    def close(self):
        self.conn.close()

    # -- connections ---------------------------------------------------
    CHUNK = 1000

    def load_flows(self, path, source):
        # Duplicate detection probes the UNIQUE index on the disk table,
        # so neither ids nor rows have to be held in memory.
        rows = []
        n = 0
        self.total_bytes = 0

        def add(obj, line_no):
            nonlocal n
            flow_id = _require(obj, "flow_id", source, line_no)
            _nonempty_string(flow_id, "flow_id", source, line_no)
            dst_ip = _require(obj, "dst_ip", source, line_no)
            if not isinstance(dst_ip, str):
                raise BatchError("dst_ip must be a string, got %s"
                                 % _field_str(dst_ip), source, line_no)
            address = parse_dst_ip(dst_ip, source, line_no)
            start = _integer(_require(obj, "start_ms", source, line_no),
                             "start_ms", source, line_no)
            end = _integer(_require(obj, "end_ms", source, line_no),
                           "end_ms", source, line_no)
            count = _integer(_require(obj, "bytes", source, line_no),
                             "bytes", source, line_no)
            if start >= end:
                raise BatchError("start_ms must be less than end_ms",
                                 source, line_no)
            if count < 0:
                raise BatchError("bytes must be >= 0, got %d"
                                 % count, source, line_no)
            # Keep the grand total exact: SQLite silently turns an
            # overflowing INTEGER sum into a float, so the batch refuses
            # totals that do not fit in a signed 64-bit integer.
            self.total_bytes += count
            if self.total_bytes > INT64_MAX:
                raise BatchError(
                    "total bytes exceed the exact 64-bit accounting range",
                    source, line_no)
            rows.append((line_no, flow_id, str(address), address.version,
                         ip_key(address), start, end, count))
            n += 1
            if len(rows) >= self.CHUNK:
                self._flush_flows(rows, source)

        _read_lines(path, source, add)
        self._flush_flows(rows, source)
        self.conn.commit()
        return n

    FLOW_INSERT = ("INSERT INTO flows (line_no, flow_id, dst_ip, family,"
                   " ip_key, start_ms, end_ms, bytes)"
                   " VALUES (?, ?, ?, ?, ?, ?, ?, ?)")

    def _flush_flows(self, rows, source):
        """Insert one bounded chunk, checking ids on disk first.

        The duplicate check is an indexed ``IN`` probe against the disk
        table plus a set of the current chunk only, so neither the id set
        nor the rows grow with the input.  A duplicate rejects the batch
        with the 1-based line of the *second* occurrence.
        """
        if not rows:
            return
        ids = [row[1] for row in rows]
        existing = {row[0] for row in self.conn.execute(
            "SELECT flow_id FROM flows WHERE flow_id IN (%s)"
            % ",".join("?" * len(ids)), ids)}
        accepted = set()
        for row in rows:
            if row[1] in existing or row[1] in accepted:
                raise BatchError("duplicate flow_id %s"
                                 % _field_str(row[1]), source, row[0])
            accepted.add(row[1])
        self.conn.executemany(self.FLOW_INSERT, rows)
        del rows[:]

    # -- ownership -----------------------------------------------------
    def load_ranges(self, path, source):
        rows = []
        n = 0

        def add(obj, line_no):
            nonlocal n
            cidr = _require(obj, "cidr", source, line_no)
            if not isinstance(cidr, str):
                raise BatchError("cidr must be a string, got %s"
                                 % _field_str(cidr), source, line_no)
            network = parse_cidr(cidr, source, line_no)
            owner = _require(obj, "owner", source, line_no)
            _nonempty_string(owner, "owner", source, line_no)
            low = _integer(_require(obj, "valid_from_ms", source, line_no),
                           "valid_from_ms", source, line_no)
            high = _integer(_require(obj, "valid_to_ms", source, line_no),
                            "valid_to_ms", source, line_no)
            if low >= high:
                raise BatchError("valid_from_ms must be less than "
                                 "valid_to_ms", source, line_no)
            ints = network.network_address.version == 4
            rows.append((line_no, str(network), owner,
                         4 if ints else 6,
                         prefix_key(network.network_address,
                                    network.prefixlen),
                         network.prefixlen, low, high))
            n += 1
            if len(rows) >= self.CHUNK:
                self._flush_ranges(rows)

        _read_lines(path, source, add)
        self._flush_ranges(rows)
        self.conn.execute(
            "INSERT INTO prefix_keys (family, prefix_len)"
            " SELECT DISTINCT family, prefix_len FROM ranges")
        self.conn.commit()
        # A tiny in-memory map (at most 33 IPv4 + 129 IPv6 entries) of the
        # prefix lengths to probe; it does not grow with the input.
        self.prefix_lengths = {
            family: [row[0] for row in self.conn.execute(
                "SELECT prefix_len FROM prefix_keys WHERE family = ?"
                " ORDER BY prefix_len", (family,))]
            for family in (4, 6)}
        return n

    def _flush_ranges(self, rows):
        self.conn.executemany(
            "INSERT INTO ranges (line_no, cidr, owner, family, prefix_key,"
            "                    prefix_len, valid_from, valid_to)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)", rows)
        del rows[:]


# --------------------------------------------------------------------------
# attribution
# --------------------------------------------------------------------------

def _candidates(conn, lengths, family, key, start, end):
    """Ownership rows whose prefix contains *key*.

    Only *lengths*, the prefix lengths that actually occur for this
    family, are probed, each by one equality on the
    ``(family, prefix_key, prefix_len)`` index, so a connection never scans
    the ownership table.  Rows whose validity does
    not touch [start, end) are dropped here; they cannot influence any
    instant of this connection (validity is half-open).
    """
    found = []
    for length in lengths:
        prefix = _prefix_of_key(key, length)
        for row in conn.execute(
                "SELECT id, owner, valid_from, valid_to, prefix_len FROM"
                " ranges WHERE family = ? AND prefix_key = ?"
                " AND prefix_len = ?", (family, prefix, length)):
            if row[2] < end and row[3] > start:
                found.append(row)
    return found


def _state_at(candidates):
    """Classify one instant.

    The longest containing prefix wins.  Among rows sharing that prefix a
    single distinct owner means ``assigned``; several distinct owners mean
    ``ambiguous`` (no owner is picked and no wider prefix is used).  No
    containing row at all means ``unassigned``.
    """
    if not candidates:
        return ("unassigned", ())
    best_len = max(row[4] for row in candidates)
    owners = tuple(sorted({row[1] for row in candidates
                           if row[4] == best_len}))
    return ("assigned" if len(owners) == 1 else "ambiguous", owners)


def _breakpoints(candidates, start, end):
    """Instants inside (start, end) where the winning state can change.

    Every candidate row contributes its validity endpoints: a wide prefix
    can become the winner again once a narrower one expires.  The list is
    deduplicated and clipped.  Hidden wide prefixes *are* included: they
    may become the winner after a narrower prefix expires, and when they
    do not, their marks fall inside an unchanged run and are merged away
    afterwards, so they never leave a cut.
    """
    points = set()
    for row in candidates:
        if start < row[2] < end:
            points.add(row[2])
        if start < row[3] < end:
            points.add(row[3])
    return sorted(points)


def _within(candidates, lo, hi):
    """Subset of *candidates* valid at every instant in [lo, hi)."""
    return [row for row in candidates if row[2] <= lo and row[3] >= hi]


def _fragments(start, end, candidates):
    """Cut one connection into maximal uniform fragments."""
    if _state_at(candidates)[0] == "unassigned":
        # Nothing is valid anywhere in this connection; no breakpoint can
        # change that, so the whole span is one fragment.
        return [(start, end, "unassigned", ())]
    bounds = [start]
    for point in _breakpoints(candidates, start, end):
        if point > bounds[-1]:
            bounds.append(point)
    bounds.append(end)

    fragments = []
    for lo, hi in zip(bounds, bounds[1:]):
        here = _state_at(_within(candidates, lo, hi))
        if fragments and fragments[-1][2] == here[0] \
                and fragments[-1][3] == here[1]:
            # Identical status and owner set: merge, no empty cut.
            fragments[-1] = (fragments[-1][0], hi, here[0], here[1])
        else:
            fragments.append((lo, hi, here[0], here[1]))
    return fragments


def allocate(total, fragments):
    """Apportion *total* integer bytes over *fragments* exactly.

    Each fragment gets the floor of ``total * length / span``; the
    remaining bytes go one at a time to the largest remainders, ties
    resolved by the earlier fragment start.  No floating point is used and
    the result sums to *total*.
    """
    lengths = [hi - lo for lo, hi, _, _ in fragments]
    span = sum(lengths)
    amounts = [total * length // span for length in lengths]
    leftover = total - sum(amounts)
    order = sorted(range(len(fragments)),
                   key=lambda i: (-(total * lengths[i] % span),
                                  fragments[i][0], i))
    for i in order[:leftover]:
        amounts[i] += 1
    return amounts


# --------------------------------------------------------------------------
# DNS version labels (read-only)
# --------------------------------------------------------------------------

def _readonly_uri(path):
    return "file:%s?mode=ro" % quote(os.path.abspath(path))


def load_version_labels(repo_path, zone, serial, conn):
    """Attach direct A/AAAA owners from one published version.

    Opens the repository strictly read-only (``mode=ro``) and writes the
    labels into the temporary *conn* index.  Mirrors are not resolved: the
    label set for an address is exactly the sorted owners of direct A and
    AAAA records pointing at it in the requested version, so later
    publishes and head-pointer moves cannot influence it.
    """
    if not os.path.isfile(repo_path):
        raise BatchError("repository %s does not exist" % repo_path)
    try:
        source = sqlite3.connect(_readonly_uri(repo_path), uri=True)
    except sqlite3.Error as exc:
        raise BatchError("cannot open repository %s read-only: %s"
                         % (repo_path, exc))
    try:
        source.row_factory = sqlite3.Row
        row = source.execute("SELECT id FROM zones WHERE name = ?",
                             (zone,)).fetchone()
        if row is None:
            raise BatchError("zone %s not found in repository" % zone)
        version = source.execute(
            "SELECT id, status FROM versions WHERE zone_id = ? AND serial = ?",
            (row["id"], serial)).fetchone()
        if version is None or version["status"] != "published":
            raise BatchError(
                "zone %s has no published version with serial %d"
                % (zone, serial))
        records = source.execute(
            "SELECT owner, rdata FROM records"
            " WHERE version_id = ? AND rtype IN ('A', 'AAAA')",
            (version["id"],))
        batch = []
        for rec in records:
            try:
                address = ipaddress.ip_address(rec["rdata"])
            except ValueError:
                # dnsrepo only stores canonical addresses; skip anything
                # that somehow is not one rather than failing the batch.
                continue
            batch.append((address.version, ip_key(address), rec["owner"]))
            if len(batch) >= _Loader.CHUNK:
                conn.executemany("INSERT OR IGNORE INTO labels (family,"
                                 " ip_key, owner) VALUES (?, ?, ?)", batch)
                batch.clear()
        conn.executemany("INSERT OR IGNORE INTO labels (family, ip_key,"
                         " owner) VALUES (?, ?, ?)", batch)
        conn.commit()
    except sqlite3.Error as exc:
        raise BatchError("cannot read version %d of %s: %s"
                         % (serial, zone, exc))
    finally:
        source.close()


def labels_at(conn, family, key):
    """Sorted owners of direct A/AAAA records for one address."""
    return [row[0] for row in conn.execute(
        "SELECT owner FROM labels WHERE family = ? AND ip_key = ?"
        " ORDER BY owner", (family, key))]


# --------------------------------------------------------------------------
# batch driver
# --------------------------------------------------------------------------

class BatchResult:
    """What a completed batch delivered."""

    def __init__(self, output, flows, ownership_rows, fragments, bytes_total,
                 statuses, owner_bytes):
        self.output = output
        self.flows = flows
        self.ownership_rows = ownership_rows
        self.fragments = fragments
        self.bytes_total = bytes_total
        self.statuses = statuses
        self.owner_bytes = owner_bytes

    @property
    def detail_path(self):
        return os.path.join(self.output, DETAIL_FILE)

    @property
    def summary_path(self):
        return os.path.join(self.output, SUMMARY_FILE)

    def __repr__(self):
        return ("BatchResult(flows=%d fragments=%d bytes=%d statuses=%r "
                "output=%s)" % (self.flows, self.fragments, self.bytes_total,
                                self.statuses, self.output))


class _Spool:
    """Append-only detail writer; a crash leaves an unlinked temp file."""

    def __init__(self, directory):
        self.path = os.path.join(directory, "details.spool")
        self.fh = open(self.path, "w", encoding="utf-8")
        self.count = 0

    def write(self, row):
        self.fh.write(json.dumps(row, ensure_ascii=False,
                                 separators=(",", ":")))
        self.fh.write("\n")
        self.count += 1

    def finish(self, destination):
        self.fh.flush()
        os.fsync(self.fh.fileno())
        self.fh.close()
        os.replace(self.path, destination)

    def abort(self):
        try:
            self.fh.close()
        except OSError:
            pass
        try:
            os.unlink(self.path)
        except OSError:
            pass


class _Totals:
    """Status and owner byte totals in their own temporary database."""

    def __init__(self, db_path):
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA journal_mode = OFF")
        self.conn.execute("PRAGMA synchronous = OFF")
        self.conn.executescript(SUMMARY_SCHEMA)
        self.conn.executemany(
            "INSERT INTO status_totals (status, bytes) VALUES (?, 0)",
            [(status,) for status in STATUSES])

    def add(self, status, owners, count):
        # Zero-byte fragments still count rows but never change a total.
        self.conn.execute(
            "UPDATE status_totals SET bytes = bytes + ? WHERE status = ?",
            (count, status))
        if status == "assigned":
            self.conn.execute(
                "INSERT INTO owner_totals (owner, bytes) VALUES (?, ?)"
                " ON CONFLICT(owner) DO UPDATE SET bytes = bytes + ?",
                (owners[0], count, count))

    def close(self):
        self.conn.close()

    def summary(self):
        statuses = {row[0]: row[1] for row in self.conn.execute(
            "SELECT status, bytes FROM status_totals")}
        owners = {row[0]: row[1] for row in self.conn.execute(
            "SELECT owner, bytes FROM owner_totals ORDER BY owner")}
        return statuses, owners


def _flow_rows(conn):
    """Stream connections ordered by input line (the delivery order)."""
    cursor = conn.execute(
        "SELECT line_no, flow_id, dst_ip, family, ip_key, start_ms, end_ms,"
        "       bytes FROM flows ORDER BY line_no")
    for row in cursor:
        yield row


def _attribute(conn, lengths, spool, totals):
    """One pass over the connections; each is handled independently.

    Memory is bounded by the largest single connection: its candidate
    rows and its merged fragments.  Detail rows are streamed to *spool*
    and totals are incremented in place, never in a growing dict.
    """
    fragments = 0
    for flow in _flow_rows(conn):
        line_no, flow_id, dst_ip, family, key, start, end, count = flow
        candidates = _candidates(conn, lengths[family], family, key,
                                 start, end)
        parts = _fragments(start, end, candidates)
        amounts = allocate(count, parts)
        owners_label = labels_at(conn, family, key)
        for (lo, hi, status, owners), amount in zip(parts, amounts):
            totals.add(status, owners, amount)
            spool.write({
                "flow_id": flow_id,
                "line_no": line_no,
                "dst_ip": dst_ip,
                "start_ms": lo,
                "end_ms": hi,
                "status": status,
                "owners": list(owners),
                "bytes": amount,
                "dns_owners": owners_label,
            })
            fragments += 1
    totals.conn.commit()
    return fragments


def _fsync_dir(path):
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _validate_target(output_dir):
    if os.path.lexists(output_dir):
        raise BatchError("output %s already exists; refusing to overwrite"
                         % output_dir)
    parent = os.path.dirname(os.path.abspath(output_dir))
    if not os.path.isdir(parent):
        raise BatchError("parent directory %s does not exist" % parent)
    return parent


def _check_input(path, what):
    if not os.path.isfile(path):
        raise BatchError("%s file %s does not exist" % (what, path))


def _label_configuration(repo_path, zone, serial):
    supplied = [repo_path is not None, zone is not None, serial is not None]
    if any(supplied) and not all(supplied):
        raise BatchError("--repo, --zone and --serial must be given together")
    if not all(supplied):
        return None
    zone = canon_zone(zone)
    return (repo_path, zone, serial)


def attribute_flows(flows_path, ownership_path, output_dir,
                    repo_path=None, zone=None, serial=None):
    """Run one attribution batch and deliver the output directory.

    The directory is created only when every input line validated, every
    connection was attributed and the totals reconcile.  On any failure no
    directory at *output_dir* is left behind.
    """
    label_config = _label_configuration(repo_path, zone, serial)
    parent = _validate_target(output_dir)
    _check_input(flows_path, "flows")
    _check_input(ownership_path, "ownership")

    workdir = tempfile.mkdtemp(prefix=".dnsrepo-traffic-", dir=parent)
    loader = None
    totals = None
    spool = None
    try:
        index_path = os.path.join(workdir, "index.db")
        totals_path = os.path.join(workdir, "totals.db")
        stage = os.path.join(workdir, "publish")
        os.mkdir(stage)

        loader = _Loader(index_path)
        if label_config is not None:
            load_version_labels(label_config[0], label_config[1],
                                label_config[2], loader.conn)
        flow_count = loader.load_flows(flows_path, flows_path)
        range_count = loader.load_ranges(ownership_path, ownership_path)
        spool = _Spool(workdir)
        totals = _Totals(totals_path)
        fragment_count = _attribute(loader.conn, loader.prefix_lengths,
                                    spool, totals)

        statuses, owners = totals.summary()
        status_total = sum(statuses.values())
        flow_total = loader.total_bytes
        if status_total != flow_total or not isinstance(status_total, int):
            raise BatchError("internal accounting error: %d bytes attributed "
                             "of %d" % (status_total, flow_total))

        spool.finish(os.path.join(stage, DETAIL_FILE))
        spool = None
        summary = {
            "flows": flow_count,
            "fragments": fragment_count,
            "bytes": flow_total,
            "status_bytes": statuses,
            "owner_bytes": owners,
        }
        if label_config is not None:
            summary["dns_version"] = {"zone": label_config[1],
                                      "serial": label_config[2]}
        summary_path = os.path.join(stage, SUMMARY_FILE)
        with open(summary_path, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, ensure_ascii=False, indent=2,
                      sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        _fsync_dir(stage)

        # Deliver only now, and never over an existing target.
        if os.path.lexists(output_dir):
            raise BatchError("output %s appeared while the batch ran; "
                             "refusing to overwrite" % output_dir)
        os.rename(stage, output_dir)
        _fsync_dir(parent)
        return BatchResult(output_dir, flow_count, range_count,
                           fragment_count, flow_total, statuses, owners)
    finally:
        if spool is not None:
            spool.abort()
        if totals is not None:
            totals.close()
        if loader is not None:
            loader.close()
        shutil.rmtree(workdir, ignore_errors=True)
