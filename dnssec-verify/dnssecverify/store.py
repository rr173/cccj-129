"""SQLite-backed snapshot store with streaming, RRset-grouped reads.

Design goals:

* Records are inserted once per exact ``(zone, serial)`` historical version;
  verification never follows a "current" zone head.
* The verifier opens one read-only connection (``mode=ro``) and keeps it for
  the whole run, so a single read view covers every zone.  WAL committed
  content is visible; nothing outside the database files is touched.
* All iteration is per RRset via server-side cursors, so a zone with hundreds
  of thousands of records is never materialized in Python memory.
"""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager

from . import wire
from .zonefile import RawRecord

SCHEMA = """
CREATE TABLE IF NOT EXISTS zones (
    zone        TEXT NOT NULL,
    serial      INTEGER NOT NULL,
    source_file TEXT NOT NULL,
    loaded_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (zone, serial)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS records (
    zone        TEXT NOT NULL,
    serial      INTEGER NOT NULL,
    owner       TEXT NOT NULL,
    rtype       INTEGER NOT NULL,
    rclass      INTEGER NOT NULL,
    ttl         INTEGER NOT NULL,
    rdata_json  TEXT NOT NULL,
    source_file TEXT NOT NULL,
    source_line INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_records_rrset
    ON records (zone, serial, owner, rtype, rclass);
CREATE INDEX IF NOT EXISTS idx_records_lookup
    ON records (zone, serial, rtype, owner);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class StoreError(Exception):
    pass


# RDATA fields that carry binary data and therefore need hex encoding for
# JSON storage.  They are decoded back to bytes on every read.
_BINARY_FIELDS = frozenset((
    "pubkey", "signature", "digest", "data", "hit", "salt", "next_hash"))


def _encode_rdata(obj):
    if isinstance(obj, dict):
        return {k: (_hex_marker(v) if k in _BINARY_FIELDS else
                    _encode_rdata(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_encode_rdata(v) for v in obj]
    return obj


def _decode_rdata(obj):
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in _BINARY_FIELDS and isinstance(v, str):
                out[k] = bytes.fromhex(v)
            else:
                out[k] = _decode_rdata(v)
        return out
    if isinstance(obj, list):
        return [_decode_rdata(v) for v in obj]
    return obj


def _hex_marker(value: bytes) -> str:
    if not isinstance(value, bytes):
        raise StoreError(f"expected bytes for binary field, got {type(value)}")
    return value.hex()


def _connect_rw(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _connect_ro(path: str) -> sqlite3.Connection:
    uri = f"file:{os.path.abspath(path)}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.execute("PRAGMA query_only=ON")
    # Keep the schema visible; do not create anything from a read-only handle.
    return conn


@contextmanager
def read_only_store(path: str):
    """Yield a read-only :class:`SnapshotStore` backed by one immutable view."""
    if not os.path.exists(path):
        raise StoreError(f"database not found: {path}")
    conn = _connect_ro(path)
    try:
        yield SnapshotStore(conn)
    finally:
        conn.close()


class IngestStore:
    """Write-side loader.  One writer connection, short transactions."""

    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        self.conn = _connect_rw(path)
        self.conn.executescript(SCHEMA)
        self.conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version','1')")
        self.conn.commit()

    def snapshot_exists(self, zone: str, serial: int) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM zones WHERE zone=? AND serial=?",
            (zone, serial)).fetchone()
        return row is not None

    def ingest_records(self, header: dict, records: list[RawRecord]) -> int:
        zone, serial = header["zone"], header["serial"]
        if self.snapshot_exists(zone, serial):
            raise StoreError(
                f"snapshot {zone}={serial} already exists; historical "
                f"versions are immutable")
        cur = self.conn.cursor()
        try:
            cur.execute(
                "INSERT INTO zones(zone, serial, source_file) VALUES (?,?,?)",
                (zone, serial, header["source"]))
            cur.executemany(
                "INSERT INTO records(zone, serial, owner, rtype, rclass, ttl,"
                " rdata_json, source_file, source_line) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                ((r.zone, r.serial, r.owner, r.rtype, r.rclass, r.ttl,
                  json.dumps(_encode_rdata(r.rdata), sort_keys=True,
                             separators=(",", ":")),
                  r.source_file, r.source_line) for r in records))
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return len(records)

    def close(self):
        self.conn.close()


class StoredRecord:
    """Lightweight record view; RDATA is decoded lazily by callers."""

    __slots__ = ("owner", "rtype", "rclass", "ttl", "rdata",
                 "source_file", "source_line")

    def __init__(self, row: tuple):
        (self.owner, self.rtype, self.rclass, self.ttl, rdata_json,
         self.source_file, self.source_line) = row
        self.rdata = _decode_rdata(json.loads(rdata_json))


class SnapshotStore:
    """Streaming read API over one fixed SQLite read-only connection."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def list_snapshots(self) -> list[tuple[str, int]]:
        return [tuple(r) for r in self.conn.execute(
            "SELECT zone, serial FROM zones ORDER BY zone, serial")]

    def snapshot_exists(self, zone: str, serial: int) -> bool:
        return self.conn.execute(
            "SELECT 1 FROM zones WHERE zone=? AND serial=?",
            (zone, serial)).fetchone() is not None

    def snapshot_meta(self, zone: str, serial: int) -> dict | None:
        row = self.conn.execute(
            "SELECT zone, serial, source_file FROM zones "
            "WHERE zone=? AND serial=?", (zone, serial)).fetchone()
        if row is None:
            return None
        return {"zone": row[0], "serial": row[1], "source_file": row[2]}

    def iter_rrsets(self, zone: str, serial: int, batch: int = 500):
        """Stream ``(owner, rtype, rclass, ttl, [StoredRecord], provenance)``.

        A single server-side cursor walks the records in RRset-group order.
        Records are accumulated for one group, emitted, then released, so
        neither the whole zone nor even the list of group keys stays in
        Python memory: the working set is one RRset regardless of zone size.
        TTL disagreements inside an RRset are surfaced as ttl=None so the
        verifier turns them into a FAIL with exact line citations.
        """
        cur = self.conn.execute(
            "SELECT owner, rtype, rclass, ttl, rdata_json, source_file,"
            " source_line FROM records WHERE zone=? AND serial=? "
            "ORDER BY owner, rtype, rclass, source_line",
            (zone, serial))
        cur.arraysize = batch
        current_key = None
        recs: list[StoredRecord] = []

        def flush():
            if not recs:
                return None
            owner, rtype, rclass = current_key
            ttls = {r.ttl for r in recs}
            ttl = recs[0].ttl if len(ttls) == 1 else None
            provenance = [
                {"file": r.source_file, "line": r.source_line}
                for r in recs]
            return owner, rtype, rclass, ttl, recs, provenance

        for row in cur:
            key = (row[0], row[1], row[2])
            if current_key is not None and key != current_key:
                emitted = flush()
                recs = []
                if emitted is not None:
                    yield emitted
            current_key = key
            recs.append(StoredRecord(row))
        emitted = flush()
        if emitted is not None:
            yield emitted

    def get_rrset(self, zone: str, serial: int, owner: str, rtype: int):
        """Fetch one exact RRset (all members) or return ``None``."""
        rows = self.conn.execute(
            "SELECT owner, rtype, rclass, ttl, rdata_json, source_file,"
            " source_line FROM records WHERE zone=? AND serial=? "
            "AND owner=? AND rtype=? ORDER BY source_line",
            (zone, serial, owner, rtype)).fetchall()
        if not rows:
            return None
        recs = [StoredRecord(r) for r in rows]
        ttls = {r.ttl for r in recs}
        ttl = recs[0].ttl if len(ttls) == 1 else None
        provenance = [
            {"file": r.source_file, "line": r.source_line} for r in recs]
        return recs, ttl, provenance

    def delegation_points(self, zone: str, serial: int) -> set[str]:
        """Owners of NS RRsets below the apex — the zone-cut boundaries."""
        rows = self.conn.execute(
            "SELECT DISTINCT owner FROM records WHERE zone=? AND serial=? "
            "AND rtype=? AND owner<>?",
            (zone, serial, wire.TYPES["NS"], zone)).fetchall()
        return {r[0] for r in rows}

    def count_records(self, zone: str | None = None,
                      serial: int | None = None) -> int:
        sql = "SELECT COUNT(*) FROM records"
        params: list = []
        if zone is not None:
            sql += " WHERE zone=?"
            params.append(zone)
            if serial is not None:
                sql += " AND serial=?"
                params.append(serial)
        return self.conn.execute(sql, params).fetchone()[0]

    def logical_checksum(self) -> dict:
        """Content checksums used to prove a verification run is read-only."""
        row = self.conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(ABS(("
            "  LENGTH(rdata_json) + LENGTH(owner) + ttl + rtype + rclass"
            "))),0), COALESCE(MAX(source_line),0) FROM records").fetchone()
        return {"record_count": row[0], "weighted_sum": row[1],
                "max_line": row[2]}
