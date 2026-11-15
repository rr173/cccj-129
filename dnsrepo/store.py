"""SQLite-backed versioned zone storage.

Each publish is a single SQLite transaction: insert the version row
(status 'publishing'), insert all records, mark the version 'published'
and move the zone head.  A crash or failure anywhere rolls the whole
transaction back, so the repository is never left half-published.

All check-and-write sequences (publishing, handoff receive) run inside
``Store.write_txn``: the write lock is taken with ``BEGIN IMMEDIATE``
*before* any state is read, so a decision made after waiting for the
lock is never based on pre-wait reads.
"""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from .records import Record

SCHEMA = """
CREATE TABLE IF NOT EXISTS zones (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    current_version_id INTEGER,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS versions (
    id INTEGER PRIMARY KEY,
    zone_id INTEGER NOT NULL REFERENCES zones(id),
    serial INTEGER NOT NULL,
    kind TEXT NOT NULL,              -- 'master' | 'increment'
    status TEXT NOT NULL,            -- 'publishing' | 'published' | 'failed'
    source_file TEXT,
    created_at TEXT NOT NULL,
    UNIQUE (zone_id, serial)
);
CREATE TABLE IF NOT EXISTS records (
    id INTEGER PRIMARY KEY,
    version_id INTEGER NOT NULL REFERENCES versions(id),
    owner TEXT NOT NULL,
    rtype TEXT NOT NULL,
    ttl INTEGER NOT NULL,
    rdata TEXT NOT NULL,
    known INTEGER NOT NULL DEFAULT 1,
    line_no INTEGER,                 -- line in the source where introduced
    introduced_in INTEGER NOT NULL REFERENCES versions(id)
);
CREATE INDEX IF NOT EXISTS idx_records_version ON records(version_id);
CREATE INDEX IF NOT EXISTS idx_records_owner ON records(version_id, owner);
"""


def _now():
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, path):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.executescript(SCHEMA)
        self._recover()

    def close(self):
        self.conn.close()

    def _recover(self):
        # Defensive: a crash mid-publish normally rolls the transaction
        # back entirely; if a 'publishing' row ever survives, fail it so
        # it is never mistaken for a usable version.
        with self.conn:
            self.conn.execute(
                "UPDATE versions SET status='failed' WHERE status='publishing'")

    @contextmanager
    def write_txn(self):
        """One atomic write transaction holding the write lock throughout.

        The lock is acquired (``BEGIN IMMEDIATE``) before any statement
        of the caller runs, so checks performed inside the block observe
        the state that the commit will actually build on.  Any exception
        rolls everything back.
        """
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.conn.rollback()
            raise
        try:
            self.conn.commit()
        except BaseException:
            self.conn.rollback()
            raise

    # --------------------------------------------------------------
    # zones
    # --------------------------------------------------------------
    def get_zone(self, name):
        return self.conn.execute(
            "SELECT * FROM zones WHERE name = ?", (name,)).fetchone()

    def ensure_zone(self, name):
        """Return the zone row, creating the zone if needed.

        The insert (if any) happens in the caller's transaction; callers
        must hold ``write_txn`` (or commit themselves).
        """
        row = self.get_zone(name)
        if row is not None:
            return row
        self.conn.execute(
            "INSERT INTO zones (name, created_at) VALUES (?, ?)",
            (name, _now()))
        return self.get_zone(name)

    def list_zones(self):
        return self.conn.execute(
            "SELECT z.*, v.serial AS current_serial FROM zones z "
            "LEFT JOIN versions v ON v.id = z.current_version_id "
            "ORDER BY z.name").fetchall()

    # --------------------------------------------------------------
    # versions
    # --------------------------------------------------------------
    def get_version(self, version_id):
        return self.conn.execute(
            "SELECT * FROM versions WHERE id = ?", (version_id,)).fetchone()

    def current_version(self, zone_id):
        return self.conn.execute(
            "SELECT v.* FROM versions v "
            "JOIN zones z ON z.current_version_id = v.id "
            "WHERE z.id = ?", (zone_id,)).fetchone()

    def version_by_serial(self, zone_id, serial):
        return self.conn.execute(
            "SELECT * FROM versions "
            "WHERE zone_id = ? AND serial = ? AND status = 'published'",
            (zone_id, serial)).fetchone()

    def list_versions(self, zone_id):
        return self.conn.execute(
            "SELECT * FROM versions WHERE zone_id = ? AND status = 'published' "
            "ORDER BY id", (zone_id,)).fetchall()

    def record_count(self, version_id):
        row = self.conn.execute(
            "SELECT COUNT(*) AS n FROM records WHERE version_id = ?",
            (version_id,)).fetchone()
        return row["n"]

    # --------------------------------------------------------------
    # records
    # --------------------------------------------------------------
    def version_records(self, version_id):
        rows = self.conn.execute(
            "SELECT r.owner, r.rtype, r.ttl, r.rdata, r.known, r.line_no, "
            "       r.introduced_in, v.source_file AS source_file "
            "FROM records r JOIN versions v ON v.id = r.introduced_in "
            "WHERE r.version_id = ? "
            "ORDER BY r.owner, r.rtype, r.rdata", (version_id,)).fetchall()
        return [Record(owner=row["owner"], rtype=row["rtype"], ttl=row["ttl"],
                       rdata=row["rdata"], known=bool(row["known"]),
                       line_no=row["line_no"],
                       introduced_in=row["introduced_in"],
                       source_file=row["source_file"])
                for row in rows]

    # --------------------------------------------------------------
    # publishing
    # --------------------------------------------------------------
    def publish(self, zone_id, serial, kind, source_file, records):
        """Insert a full snapshot; returns the version id.

        Runs inside the caller's ``write_txn``: the version row, its
        records and the head move commit or roll back together with
        everything else in that transaction.
        """
        version_id = self._insert_version(zone_id, serial, kind,
                                          source_file)
        self._insert_records(version_id, records)
        self._finalize(zone_id, version_id)
        return version_id

    def _insert_version(self, zone_id, serial, kind, source_file,
                        created_at=None):
        cur = self.conn.execute(
            "INSERT INTO versions (zone_id, serial, kind, status, "
            "                     source_file, created_at) "
            "VALUES (?, ?, ?, 'publishing', ?, ?)",
            (zone_id, serial, kind, source_file, created_at or _now()))
        return cur.lastrowid

    def _insert_records(self, version_id, records):
        self.conn.executemany(
            "INSERT INTO records (version_id, owner, rtype, ttl, rdata, "
            "                    known, line_no, introduced_in) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [(version_id, r.owner, r.rtype, r.ttl, r.rdata,
              1 if r.known else 0, r.line_no,
              r.introduced_in if r.introduced_in is not None else version_id)
             for r in records])

    def _finalize(self, zone_id, version_id):
        self.conn.execute(
            "UPDATE versions SET status = 'published' WHERE id = ?",
            (version_id,))
        self.conn.execute(
            "UPDATE zones SET current_version_id = ? WHERE id = ?",
            (version_id, zone_id))
