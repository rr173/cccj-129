"""Offline certificate-transparency (CT) observation import.

A batch reads UTF-8 JSONL observation files.  Each line carries
``source``, ``observed_at_ms``, ``certificate_sha256`` and ``dns_names``.
The batch turns those observations into a *review list* of names that
appeared in public CT exports but are not present in one pinned,
already-published zone version.  It never publishes DNS records and it
never treats a certificate observation as proof of ownership.

Only the requested ``zone``/``serial`` version is read, through a
strictly read-only SQLite connection; the current zone head and the
repository bytes are never touched.  Every DNS name is normalized
(case, trailing root dot, internationalized labels) to its lowercase
ASCII form before comparison.  Names outside the zone label boundary
(``example.net.evil`` is not below ``example.net.``), the zone apex and
names that already exist as direct owners in the pinned version are
dropped.  A legal leftmost ``*.`` label is kept as a wildcard clue and is
never expanded into concrete host names.

Observations are merged per canonical name.  The ``(source,
certificate_sha256, observed_at_ms)`` key may be repeated verbatim (it is
folded), but the same key with a *different* normalized name set rejects
the whole batch with both locations.  One certificate reported by
several sources still counts once; duplicated names inside one
certificate count once.

All merge state lives in temporary SQLite files (each cache capped at
16 MB) and finding rows are streamed to a spool file, so neither the
observations, the certificate set nor the name mapping is held in
memory.  The output directory is created only after the whole input
validated and the totals reconciled, and it is delivered with a single
``rename``; an existing target is never overwritten and a failed batch
leaves no deliverable directory behind.
"""

import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
from urllib.parse import quote

from .errors import BatchError
from .names import canon_zone, in_zone

INT64_MIN = -(2 ** 63)
INT64_MAX = 2 ** 63 - 1

FINDINGS_FILE = "findings.jsonl"
SUMMARY_FILE = "summary.json"
NOTES_FILE = "notes.md"

# Reasons a valid, normalized name occurrence does not become a finding.
EXCLUSION_REASONS = ("out_of_zone", "zone_apex", "existing")

INDEX_SCHEMA = """
CREATE TABLE observations (
    id          INTEGER PRIMARY KEY,
    source      TEXT NOT NULL,
    cert        TEXT NOT NULL,
    observed_at INTEGER NOT NULL,
    names_sha   TEXT NOT NULL,
    path        TEXT NOT NULL,
    line_no     INTEGER NOT NULL,
    UNIQUE (source, cert, observed_at)
);
CREATE TABLE names (
    obs_id INTEGER NOT NULL,
    name   TEXT NOT NULL,
    PRIMARY KEY (obs_id, name)
) WITHOUT ROWID;
CREATE TABLE certs (
    cert TEXT PRIMARY KEY
) WITHOUT ROWID;
CREATE TABLE source_totals (
    source       TEXT PRIMARY KEY,
    observations INTEGER NOT NULL,
    duplicates   INTEGER NOT NULL,
    first_ts     INTEGER,
    last_ts      INTEGER
) WITHOUT ROWID;
CREATE TABLE source_certs (
    source TEXT NOT NULL,
    cert   TEXT NOT NULL,
    PRIMARY KEY (source, cert)
) WITHOUT ROWID;
CREATE TABLE existing_names (
    name TEXT PRIMARY KEY
) WITHOUT ROWID;
CREATE TABLE exclusions (
    reason TEXT PRIMARY KEY,
    count  INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE finding_totals (
    name     TEXT PRIMARY KEY,
    wildcard INTEGER NOT NULL,
    first_ts INTEGER NOT NULL,
    last_ts  INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE finding_evidence (
    name     TEXT NOT NULL,
    source   TEXT NOT NULL,
    cert     TEXT NOT NULL,
    first_ts INTEGER NOT NULL,
    last_ts  INTEGER NOT NULL,
    obs      INTEGER NOT NULL,
    PRIMARY KEY (name, source, cert)
) WITHOUT ROWID;
CREATE TABLE finding_certs (
    name TEXT NOT NULL,
    cert TEXT NOT NULL,
    PRIMARY KEY (name, cert)
) WITHOUT ROWID;
"""

_LABEL_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-_")
_ALABEL_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-")
_HEX_CHARS = set("0123456789abcdefABCDEF")
MAX_NAME_LEN = 253
MAX_LABEL_LEN = 63


def _check_alabel(label, raw_name, path, line_no):
    """Validate an A-label produced by or presented to IDNA.

    A-labels are plain LDH text starting with ``xn--``.  Anything else
    (an underscore, say) is not a name we can compare safely.
    """
    if any(ch not in _ALABEL_CHARS for ch in label):
        raise BatchError("invalid internationalized label %r in name %r"
                         % (label, raw_name), path, line_no)
    if not label.startswith("xn--") or len(label) == 4:
        raise BatchError("invalid internationalized label %r in name %r"
                         % (label, raw_name), path, line_no)
    return label


# --------------------------------------------------------------------------
# JSONL input helpers
# --------------------------------------------------------------------------

def _json_object(raw, path, line_no):
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BatchError("not valid UTF-8 (%s)" % exc.reason, path, line_no)
    if line_no == 1 and text.startswith("\ufeff"):
        # A UTF-8 BOM is tolerated once, as an encoding marker.
        text = text[1:]
    if not text.strip():
        return None
    try:
        value = json.loads(text)
    except ValueError as exc:
        raise BatchError("invalid JSON: %s" % exc, path, line_no)
    if not isinstance(value, dict):
        raise BatchError("expected a JSON object, got %s"
                         % type(value).__name__, path, line_no)
    return value


def _require(obj, field, path, line_no):
    if field not in obj:
        raise BatchError("missing field %r" % field, path, line_no)
    return obj[field]


def _field_str(value):
    try:
        text = json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        text = repr(value)
    return text if len(text) <= 80 else text[:77] + "..."


def _nonempty_string(value, field, path, line_no):
    if not isinstance(value, str) or value == "":
        raise BatchError("%s must be a non-empty string, got %s"
                         % (field, _field_str(value)), path, line_no)
    return value


def _integer(value, field, path, line_no):
    if isinstance(value, bool) or not isinstance(value, int):
        raise BatchError("%s must be an integer, got %s"
                         % (field, _field_str(value)), path, line_no)
    if not INT64_MIN <= value <= INT64_MAX:
        raise BatchError("%s does not fit in a signed 64-bit integer"
                         % field, path, line_no)
    return value


def _digest(value, path, line_no):
    if not isinstance(value, str):
        raise BatchError("certificate_sha256 must be a string, got %s"
                         % _field_str(value), path, line_no)
    if len(value) != 64 or any(ch not in _HEX_CHARS for ch in value):
        raise BatchError("certificate_sha256 must be 64 hexadecimal "
                         "characters, got %s" % _field_str(value),
                         path, line_no)
    return value.lower()


# --------------------------------------------------------------------------
# DNS name normalization
# --------------------------------------------------------------------------

def _ascii_label(label, raw_name, path, line_no):
    """Normalize one already-ASCII label to lowercase ASCII."""
    label = label.lower()
    if len(label) > MAX_LABEL_LEN:
        raise BatchError("label too long (%d octets) in name %r"
                         % (len(label), raw_name), path, line_no)
    if label.startswith("xn--"):
        # An A-label must be a valid punycode encoding that round-trips;
        # otherwise it does not denote a comparable host name.
        _check_alabel(label, raw_name, path, line_no)
        try:
            decoded = label.encode("ascii").decode("idna")
            if decoded.encode("idna").decode("ascii") != label:
                raise UnicodeError("does not round-trip")
        except (UnicodeError, UnicodeDecodeError):
            raise BatchError("invalid internationalized label %r in name %r"
                             % (label, raw_name), path, line_no)
        return label
    for ch in label:
        if ch not in _LABEL_CHARS:
            raise BatchError("bad character %r in name %r"
                             % (ch, raw_name), path, line_no)
    return label


def _unicode_label(label, raw_name, path, line_no):
    """Encode one non-ASCII U-label to its lowercase ASCII A-label.

    Names are DNS names, so an A-label is checked as LDH (letters,
    digits, hyphen, ``xn--`` prefix) rather than as arbitrary IDNA
    output: a label such as ``a_bücher`` would otherwise be encoded to a
    syntactically impossible host label.
    """
    try:
        encoded = label.lower().encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        raise BatchError("invalid internationalized label %r in name %r"
                         % (label, raw_name), path, line_no)
    if not encoded or len(encoded) > MAX_LABEL_LEN:
        raise BatchError("label too long (%d octets) in name %r"
                         % (len(encoded), raw_name), path, line_no)
    if encoded.startswith("xn--"):
        return _check_alabel(encoded, raw_name, path, line_no)
    # Some U-labels (fullwidth forms, for instance) fold to plain ASCII.
    for ch in encoded:
        if ch not in _LABEL_CHARS:
            raise BatchError("bad character %r in name %r"
                             % (ch, raw_name), path, line_no)
    return encoded


def normalize_name(raw_name, path, line_no):
    """Return the canonical lowercase ASCII absolute form of *raw_name*.

    The trailing root dot is optional on input and always present on
    output.  Internationalized labels are encoded with the standard
    library's IDNA (2003) codec, so ``bücher`` and ``xn--bcher-kva``
    normalize alike.  A single leftmost ``*`` label is kept; a wildcard
    anywhere else, or more than one wildcard label, is invalid.  Any
    invalid label rejects the input line.
    """
    if not isinstance(raw_name, str):
        raise BatchError("dns_names entries must be strings, got %s"
                         % _field_str(raw_name), path, line_no)
    if raw_name == "":
        raise BatchError("empty DNS name", path, line_no)
    body = raw_name[:-1] if raw_name.endswith(".") else raw_name
    if body == "":
        # "." is the root, not a host name: it has an empty label set.
        raise BatchError("empty label in name %r" % raw_name, path, line_no)
    labels = body.split(".")
    normalized = []
    wildcards = 0
    for index, label in enumerate(labels):
        if label == "":
            raise BatchError("empty label in name %r" % raw_name,
                             path, line_no)
        if label == "*":
            wildcards += 1
            if index != 0 or wildcards > 1:
                raise BatchError("wildcard must be a single leftmost label "
                                 "in name %r" % raw_name, path, line_no)
            if len(labels) == 1:
                # "*.", i.e. a wildcard with no parent zone, names nothing.
                raise BatchError("wildcard label has no parent in name %r"
                                 % raw_name, path, line_no)
            normalized.append("*")
        elif label.isascii():
            normalized.append(_ascii_label(label, raw_name, path, line_no))
        else:
            normalized.append(_unicode_label(label, raw_name, path, line_no))
    result = ".".join(normalized) + "."
    if len(result) - 1 > MAX_NAME_LEN:
        raise BatchError("domain name too long (%d octets): %r"
                         % (len(result) - 1, raw_name), path, line_no)
    return result


# --------------------------------------------------------------------------
# pinned zone version (read-only)
# --------------------------------------------------------------------------

def _readonly_uri(path):
    """URI that opens *path* strictly read-only.

    ``immutable=1`` is used when there is no write-ahead log next to the
    database.  It makes SQLite skip locking and the shared-memory index
    entirely, so a read leaves no ``-wal``/``-shm`` side files and the
    repository directory is byte-for-byte untouched.  If a ``-wal`` does
    exist (a writer may be active or a checkpoint is pending), plain
    ``mode=ro`` is used: SQLite then needs its shared-memory index, but
    the database content is still never written.
    """
    uri = "file:%s?mode=ro" % quote(os.path.abspath(path))
    if not os.path.exists(path + "-wal"):
        uri += "&immutable=1"
    return uri


def _load_zone(index, repo_path, zone, serial):
    """Copy the pinned version's direct owner names into the disk index.

    Opens the repository with ``mode=ro``, resolves exactly
    ``(zone, serial)`` and reads that version's record owners.  The zone
    head pointer is deliberately not consulted, and no statement that
    could write is issued.  CNAME targets are rdata, never owners, so
    they cannot become "existing" or evidence through this path.
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
        record_count = source.execute(
            "SELECT COUNT(*) FROM records WHERE version_id = ?",
            (version["id"],)).fetchone()[0]
        batch = []
        for rec in source.execute(
                "SELECT owner FROM records WHERE version_id = ?",
                (version["id"],)):
            batch.append((rec["owner"],))
            if len(batch) >= index.CHUNK:
                index.conn.executemany(
                    "INSERT OR IGNORE INTO existing_names (name) VALUES (?)",
                    batch)
                batch.clear()
        if batch:
            index.conn.executemany(
                "INSERT OR IGNORE INTO existing_names (name) VALUES (?)",
                batch)
        index.conn.commit()
        existing = index.conn.execute(
            "SELECT COUNT(*) FROM existing_names").fetchone()[0]
        return record_count, existing
    except sqlite3.Error as exc:
        raise BatchError("cannot read version %d of %s: %s"
                         % (serial, zone, exc))
    finally:
        source.close()


# --------------------------------------------------------------------------
# merge index
# --------------------------------------------------------------------------

class _Index:
    """Temporary on-disk merge index; never holds input-sized state."""

    CHUNK = 1000

    def __init__(self, db_path):
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA journal_mode = OFF")
        self.conn.execute("PRAGMA synchronous = OFF")
        self.conn.execute("PRAGMA cache_size = -16000")
        self.conn.executescript(INDEX_SCHEMA)
        self.conn.executemany(
            "INSERT INTO exclusions (reason, count) VALUES (?, 0)",
            [(reason,) for reason in EXCLUSION_REASONS])
        # Constant-size counters (not name/certificate maps).
        self.lines = 0
        self.observations = 0
        self.duplicates = 0
        self.name_occurrences = 0
        self._pending = 0

    def close(self):
        self.conn.close()

    def commit_chunk(self):
        self._pending += 1
        if self._pending >= 64:
            self.conn.commit()
            self._pending = 0

    def is_existing(self, name):
        return self.conn.execute(
            "SELECT 1 FROM existing_names WHERE name = ?",
            (name,)).fetchone() is not None

    def _exclude(self, reason):
        self.conn.execute(
            "UPDATE exclusions SET count = count + 1 WHERE reason = ?",
            (reason,))

    def add_observation(self, path, line_no, source, observed_at, cert,
                        names):
        """Fold or insert one ``(source, cert, time)`` observation.

        Returns True when the line was an exact duplicate and was folded.
        A repeated key whose normalized name set differs is a batch-wide
        conflict: it raises here, naming both locations.
        """
        names_sha = hashlib.sha256(
            "\n".join(sorted(names)).encode("utf-8")).hexdigest()
        previous = self.conn.execute(
            "SELECT id, path, line_no, names_sha FROM observations"
            " WHERE source = ? AND cert = ? AND observed_at = ?",
            (source, cert, observed_at)).fetchone()
        if previous is not None:
            prev_id, prev_path, prev_line, prev_sha = previous
            if prev_sha == names_sha and self._same_names(prev_id, names):
                self.duplicates += 1
                self.conn.execute(
                    "UPDATE source_totals SET duplicates = duplicates + 1"
                    " WHERE source = ?", (source,))
                return True
            raise BatchError(
                "conflicting duplicate observation key (source=%s, "
                "certificate_sha256=%s, observed_at_ms=%d): first seen at "
                "%s:%d, this line has a different dns_names set"
                % (_field_str(source), cert, observed_at, prev_path,
                   prev_line),
                path, line_no)
        self.observations += 1
        cursor = self.conn.execute(
            "INSERT INTO observations (source, cert, observed_at, names_sha,"
            " path, line_no) VALUES (?, ?, ?, ?, ?, ?)",
            (source, cert, observed_at, names_sha, path, line_no))
        obs_id = cursor.lastrowid
        self.conn.executemany(
            "INSERT INTO names (obs_id, name) VALUES (?, ?)",
            [(obs_id, name) for name in names])
        self.conn.execute(
            "INSERT OR IGNORE INTO certs (cert) VALUES (?)", (cert,))
        self.conn.execute(
            "INSERT INTO source_totals (source, observations, duplicates,"
            " first_ts, last_ts) VALUES (?, 1, 0, ?, ?)"
            " ON CONFLICT(source) DO UPDATE SET"
            " observations = observations + 1,"
            " first_ts = min(first_ts, excluded.first_ts),"
            " last_ts = max(last_ts, excluded.last_ts)",
            (source, observed_at, observed_at))
        self.conn.execute(
            "INSERT OR IGNORE INTO source_certs (source, cert)"
            " VALUES (?, ?)", (source, cert))
        return False

    def _same_names(self, obs_id, names):
        rows = self.conn.execute(
            "SELECT name FROM names WHERE obs_id = ? ORDER BY name",
            (obs_id,)).fetchall()
        return [row[0] for row in rows] == sorted(names)

    def add_finding_occurrence(self, zone, name, source, cert, observed_at):
        """Route one normalized name occurrence to findings or exclusions."""
        self.name_occurrences += 1
        if name == zone:
            self._exclude("zone_apex")
            return
        if not in_zone(name, zone):
            self._exclude("out_of_zone")
            return
        if self.is_existing(name):
            self._exclude("existing")
            return
        wildcard = 1 if name.startswith("*.") else 0
        self.conn.execute(
            "INSERT INTO finding_totals (name, wildcard, first_ts, last_ts)"
            " VALUES (?, ?, ?, ?)"
            " ON CONFLICT(name) DO UPDATE SET"
            " first_ts = min(first_ts, excluded.first_ts),"
            " last_ts = max(last_ts, excluded.last_ts)",
            (name, wildcard, observed_at, observed_at))
        self.conn.execute(
            "INSERT INTO finding_evidence (name, source, cert, first_ts,"
            " last_ts, obs) VALUES (?, ?, ?, ?, ?, 1)"
            " ON CONFLICT(name, source, cert) DO UPDATE SET"
            " first_ts = min(first_ts, excluded.first_ts),"
            " last_ts = max(last_ts, excluded.last_ts), obs = obs + 1",
            (name, source, cert, observed_at, observed_at))
        self.conn.execute(
            "INSERT OR IGNORE INTO finding_certs (name, cert)"
            " VALUES (?, ?)", (name, cert))


def _observation(obj, path, line_no):
    source = _require(obj, "source", path, line_no)
    _nonempty_string(source, "source", path, line_no)
    observed_at = _integer(
        _require(obj, "observed_at_ms", path, line_no),
        "observed_at_ms", path, line_no)
    cert = _digest(_require(obj, "certificate_sha256", path, line_no),
                   path, line_no)
    raw_names = _require(obj, "dns_names", path, line_no)
    if not isinstance(raw_names, list):
        raise BatchError("dns_names must be an array, got %s"
                         % _field_str(raw_names), path, line_no)
    names = set()
    for raw_name in raw_names:
        names.add(normalize_name(raw_name, path, line_no))
    return source, observed_at, cert, names


def _load_input(index, path, zone):
    """Stream one JSONL file, validating every line before merging it."""
    with open(path, "rb") as fh:
        for line_no, raw in enumerate(fh, 1):
            obj = _json_object(raw, path, line_no)
            if obj is None:
                continue
            index.lines += 1
            source, observed_at, cert, names = _observation(obj, path,
                                                            line_no)
            if index.add_observation(path, line_no, source, observed_at,
                                     cert, names):
                index.commit_chunk()
                continue
            for name in sorted(names):
                index.add_finding_occurrence(zone, name, source, cert,
                                             observed_at)
            index.commit_chunk()
    return index.lines


# --------------------------------------------------------------------------
# output
# --------------------------------------------------------------------------

class _Spool:
    """Append-only findings writer; a crash leaves an unlinked temp file."""

    def __init__(self, directory):
        self.path = os.path.join(directory, "findings.spool")
        self.fh = open(self.path, "w", encoding="utf-8")
        self.count = 0

    def write(self, row):
        self.fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True,
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


def _certificate_rows(conn):
    """Stream ``(name, cert)`` pairs sorted by name then certificate."""
    return conn.execute(
        "SELECT name, cert FROM finding_certs ORDER BY name, cert")


def _evidence_rows(conn):
    """Stream evidence rows sorted by name, source, certificate."""
    return conn.execute(
        "SELECT name, source, cert, first_ts, last_ts, obs"
        " FROM finding_evidence ORDER BY name, source, cert")


def _write_findings(conn, spool):
    """Stream one sorted finding row per name.

    Certificates and evidence are read through their own ordered cursors
    and consumed in lockstep with the name cursor, so only one finding's
    lists are ever in memory.  Returns ``(count, wildcards)``.
    """
    certs = _certificate_rows(conn)
    evidence = _evidence_rows(conn)
    next_cert = next(certs, None)
    next_evidence = next(evidence, None)
    wildcards = 0
    for name, wildcard, first_ts, last_ts in conn.execute(
            "SELECT name, wildcard, first_ts, last_ts FROM finding_totals"
            " ORDER BY name"):
        certificate_list = []
        while next_cert is not None and next_cert[0] == name:
            certificate_list.append(next_cert[1])
            next_cert = next(certs, None)
        evidence_list = []
        source_set = set()
        while next_evidence is not None and next_evidence[0] == name:
            _, source, cert, ev_first, ev_last, obs = next_evidence
            evidence_list.append({
                "source": source,
                "certificate_sha256": cert,
                "first_observed_at_ms": ev_first,
                "last_observed_at_ms": ev_last,
                "observations": obs,
            })
            source_set.add(source)
            next_evidence = next(evidence, None)
        wildcards += wildcard
        spool.write({
            "name": name,
            "wildcard": bool(wildcard),
            "first_observed_at_ms": first_ts,
            "last_observed_at_ms": last_ts,
            "certificate_count": len(certificate_list),
            "certificates": certificate_list,
            "sources": sorted(source_set),
            "evidence": evidence_list,
        })
    return spool.count, wildcards


def _source_entry(conn, source):
    observations, duplicates, first_ts, last_ts = conn.execute(
        "SELECT observations, duplicates, first_ts, last_ts"
        " FROM source_totals WHERE source = ?", (source,)).fetchone()
    certificates = conn.execute(
        "SELECT COUNT(*) FROM source_certs WHERE source = ?",
        (source,)).fetchone()[0]
    findings = conn.execute(
        "SELECT COUNT(DISTINCT name) FROM finding_evidence"
        " WHERE source = ?", (source,)).fetchone()[0]
    return {
        "observations": observations,
        "duplicate_observations": duplicates,
        "certificates": certificates,
        "findings": findings,
        "first_observed_at_ms": first_ts,
        "last_observed_at_ms": last_ts,
    }


def _summary_parts(conn, index, files, zone, serial, record_count,
                   existing_count):
    names = conn.execute("SELECT COUNT(*) FROM finding_totals").fetchone()[0]
    wildcards = conn.execute(
        "SELECT COALESCE(SUM(wildcard), 0) FROM finding_totals").fetchone()[0]
    finding_certs = conn.execute(
        "SELECT COUNT(DISTINCT cert) FROM finding_certs").fetchone()[0]
    finding_obs = conn.execute(
        "SELECT COALESCE(SUM(obs), 0) FROM finding_evidence").fetchone()[0]
    distinct_names = conn.execute(
        "SELECT COUNT(DISTINCT name) FROM names").fetchone()[0]
    observed_certs = conn.execute("SELECT COUNT(*) FROM certs").fetchone()[0]
    min_ts, max_ts = conn.execute(
        "SELECT MIN(first_ts), MAX(last_ts) FROM source_totals").fetchone()
    excluded = {row[0]: row[1] for row in conn.execute(
        "SELECT reason, count FROM exclusions")}
    return {
        "input": {
            "files": files,
            "lines": index.lines,
            "observations": index.observations,
            "name_occurrences": index.name_occurrences,
            "duplicate_observations": index.duplicates,
            "names": distinct_names,
        },
        "certificates": {
            "observed": observed_certs,
            "in_findings": finding_certs,
        },
        "findings": {
            "names": names,
            "wildcard": wildcards,
            "plain": names - wildcards,
            "observations": finding_obs,
            "certificates": finding_certs,
        },
        "excluded": excluded,
        "observed_at_ms": {"min": min_ts, "max": max_ts},
        "zone": {
            "zone": zone,
            "serial": serial,
            "records": record_count,
            "existing_names": existing_count,
        },
    }


def _write_summary(path, conn, index, files, zone, serial, record_count,
                   existing_count):
    """Write summary.json, streaming the per-source object from disk."""
    parts = _summary_parts(conn, index, files, zone, serial, record_count,
                           existing_count)
    # Top-level keys are written in a fixed order; nested objects sorted.
    order = ["certificates", "excluded", "findings", "input",
             "observed_at_ms", "zone"]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("{\n")
        for key in order:
            fh.write('  %s: %s,\n'
                     % (json.dumps(key), json.dumps(parts[key],
                                                    ensure_ascii=False,
                                                    sort_keys=True)))
        fh.write('  "sources": {')
        first = True
        for (source,) in conn.execute(
                "SELECT source FROM source_totals ORDER BY source"):
            if not first:
                fh.write(",")
            first = False
            fh.write("\n    %s: %s"
                     % (json.dumps(source, ensure_ascii=False),
                        json.dumps(_source_entry(conn, source),
                                   ensure_ascii=False, sort_keys=True)))
        if not first:
            fh.write("\n  ")
        fh.write("}\n}\n")
        fh.flush()
        os.fsync(fh.fileno())


NOTES = """\
# 证书透明度观测导入说明

本目录只列出**待核查**的主机名线索，不发布任何 DNS 记录，也不把证书
出现解释为域名所有权证明。

## 输入与校验

- 一次可给一个或多个 UTF-8 JSONL 文件，一行一个 JSON 对象，字段为
  `source`、`observed_at_ms`、`certificate_sha256`、`dns_names`。
- `source` 非空字符串；`observed_at_ms` 为有符号 64 位整数；
  `certificate_sha256` 为 64 位十六进制（输出统一小写）；`dns_names`
  为字符串数组。
- 字段缺失、类型错误、无效摘要、无效主机名都会以
  `文件:1起始行号` 报告并拒绝整批。空行忽略，文件首字节的 UTF-8 BOM
  作为编码标记忽略。
- 同一 `(source, certificate_sha256, observed_at_ms)` 键可重复；完全相同的
  重复行折叠，但键相同而规范化名称集合不同则整批拒绝并指出冲突位置。

## 名称规范化

1. 去掉可选的末尾根点，统一转为小写。
2. 国际化标签按标准库 IDNA(2003) 编码为小写 A-label（例如
   `bücher` 与 `xn--bcher-kva` 归一为同一形式）。
3. 空标签、非法字符、超长标签/名称、非最左侧通配符、多个通配符均拒绝
   该行。
4. 合法的单个最左侧 `*.` 保留为通配符线索，绝不扩展成具体主机名。

## 区域边界与抑制

- 只读打开仓库，读取调用者指定的 `zone`/`serial` 版本；不跟随当前区头，
  不写入仓库。
- 名称必须位于 zone 的**标签边界**内；`example.net.evil` 不属于
  `example.net`。
- 区域顶点本身、以及该版本中已直接存在的属主名不作为新发现输出。
- 区域记录与 CNAME 目标不会混入 CT 观测证据；CNAME 目标既不会因此
  变成“已存在名称”，也不会被当作观测。

## 合并与输出

- 按规范化名称合并；`findings.jsonl` 按名称排序，每个名称给出首次/末次
  观测时间、去重后的证书数、排序后的证书摘要、排序后的来源列表，以及
  按 `(source, certificate_sha256)` 聚合的证据（含观测次数与时间范围）。
- 同一证书跨多个来源仍只计一张证书；同一证书内重复名称只计一次。
- 通配符线索与普通名称线索分别成行，通配符不生成其覆盖的具体名称。
- `summary.json` 给出总体与按来源的计数；重复输入或行重排不改变汇总
  数值与证据集合。
- 输出目录在整批校验和汇总完成后才原子改名到位；目标已存在则拒绝覆盖，
  失败不留下正式结果目录。

## 本次运行

- 仓库：`{repo}`
- 区域：`{zone}`
- serial：`{serial}`
- 观测文件：{files}
"""


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


class CtResult:
    """What a completed CT import delivered."""

    def __init__(self, output, zone, serial, observations, duplicates,
                 findings, wildcards, certificates, sources, excluded):
        self.output = output
        self.zone = zone
        self.serial = serial
        self.observations = observations
        self.duplicates = duplicates
        self.findings = findings
        self.wildcards = wildcards
        self.certificates = certificates
        self.sources = sources
        self.excluded = excluded

    @property
    def findings_path(self):
        return os.path.join(self.output, FINDINGS_FILE)

    @property
    def summary_path(self):
        return os.path.join(self.output, SUMMARY_FILE)

    @property
    def notes_path(self):
        return os.path.join(self.output, NOTES_FILE)

    def __repr__(self):
        return ("CtResult(zone=%s serial=%d findings=%d wildcards=%d "
                "observations=%d output=%s)"
                % (self.zone, self.serial, self.findings, self.wildcards,
                   self.observations, self.output))


def import_ct_observations(observations_paths, output_dir, repo_path, zone,
                           serial):
    """Run one CT observation import and deliver the output directory.

    ``repo_path`` must point at an existing dnsrepo database and
    ``zone``/``serial`` at one already-published version.  The function
    never writes to the repository.  On any failure no directory at
    ``output_dir`` is left behind; an existing target is never touched.
    """
    if isinstance(observations_paths, (str, bytes, os.PathLike)):
        observations_paths = [observations_paths]
    observations_paths = [os.fspath(path) for path in observations_paths]
    if not observations_paths:
        raise BatchError("at least one observations file is required")
    if repo_path is None or zone is None or serial is None:
        raise BatchError("--repo, --zone and --serial must be given together")
    zone = canon_zone(zone)
    parent = _validate_target(output_dir)
    for path in observations_paths:
        if not os.path.isfile(path):
            raise BatchError("observations file %s does not exist" % path)

    workdir = tempfile.mkdtemp(prefix=".dnsrepo-ct-", dir=parent)
    index = None
    spool = None
    try:
        index_path = os.path.join(workdir, "index.db")
        stage = os.path.join(workdir, "publish")
        os.mkdir(stage)

        index = _Index(index_path)
        record_count, existing_count = _load_zone(index, repo_path, zone,
                                                  serial)
        for path in observations_paths:
            _load_input(index, path, zone)
        index.conn.commit()

        # Every accepted name occurrence was either routed to findings or
        # counted as an exclusion.  This must reconcile exactly: a finding
        # evidence row counts one observation of one (name, source, cert).
        finding_obs = index.conn.execute(
            "SELECT COALESCE(SUM(obs), 0) FROM finding_evidence").fetchone()[0]
        excluded_total = index.conn.execute(
            "SELECT COALESCE(SUM(count), 0) FROM exclusions").fetchone()[0]
        if finding_obs + excluded_total != index.name_occurrences:
            raise BatchError(
                "internal accounting error: %d finding observations + %d "
                "excluded occurrences != %d accepted occurrences"
                % (finding_obs, excluded_total, index.name_occurrences))

        spool = _Spool(workdir)
        finding_count, wildcards = _write_findings(index.conn, spool)
        names_count = index.conn.execute(
            "SELECT COUNT(*) FROM finding_totals").fetchone()[0]
        if finding_count != names_count:
            raise BatchError("internal error: finding rows did not reconcile")
        spool.finish(os.path.join(stage, FINDINGS_FILE))
        spool = None

        _write_summary(os.path.join(stage, SUMMARY_FILE), index.conn, index,
                       observations_paths, zone, serial, record_count,
                       existing_count)
        excluded = {row[0]: row[1] for row in index.conn.execute(
            "SELECT reason, count FROM exclusions")}
        certificates = index.conn.execute(
            "SELECT COUNT(*) FROM certs").fetchone()[0]
        sources = index.conn.execute(
            "SELECT COUNT(*) FROM source_totals").fetchone()[0]
        with open(os.path.join(stage, NOTES_FILE), "w",
                  encoding="utf-8") as fh:
            fh.write(NOTES.format(
                repo=repo_path, zone=zone, serial=serial,
                files=", ".join("`%s`" % path
                                for path in observations_paths)))
            fh.flush()
            os.fsync(fh.fileno())
        _fsync_dir(stage)

        if os.path.lexists(output_dir):
            raise BatchError("output %s appeared while the batch ran; "
                             "refusing to overwrite" % output_dir)
        os.rename(stage, output_dir)
        _fsync_dir(parent)
        return CtResult(output_dir, zone, serial, index.observations,
                        index.duplicates, finding_count, wildcards,
                        certificates, sources, excluded)
    finally:
        if spool is not None:
            spool.abort()
        if index is not None:
            index.close()
        shutil.rmtree(workdir, ignore_errors=True)
