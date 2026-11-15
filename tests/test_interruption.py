"""Publish interruption: a failed or crashed publish must leave the
repository exactly as it was, and zone file writes must be atomic."""

import os
import sqlite3
import tempfile
import unittest
from unittest import mock

from dnsrepo.generator import write_zone_file
from dnsrepo.repo import Repository
from dnsrepo.store import Store

from .helpers import INCREMENT_V2, MASTER_V1


class PublishRollbackTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "test.db")
        self.repo = Repository(self.db)
        self.repo.publish_master("example.com.", MASTER_V1)

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def test_failure_mid_publish_rolls_back(self):
        store = self.repo.store
        with mock.patch.object(store, "_insert_records",
                               side_effect=IOError("disk full")):
            with self.assertRaises(IOError):
                self.repo.publish_increment(INCREMENT_V2)
        # head unchanged
        self.assertEqual(self.repo.current("example.com.").serial,
                         2024010100)
        # no half-published version anywhere
        rows = store.conn.execute(
            "SELECT status, COUNT(*) AS n FROM versions GROUP BY status"
        ).fetchall()
        self.assertEqual({r["status"]: r["n"] for r in rows},
                         {"published": 1})
        # repository still usable afterwards
        self.repo.publish_increment(INCREMENT_V2)
        self.assertEqual(self.repo.current("example.com.").serial,
                         2024010101)

    def test_failure_at_finalize_rolls_back(self):
        store = self.repo.store
        with mock.patch.object(store, "_finalize",
                               side_effect=sqlite3.OperationalError("boom")):
            with self.assertRaises(sqlite3.OperationalError):
                self.repo.publish_increment(INCREMENT_V2)
        self.assertEqual(self.repo.current("example.com.").serial,
                         2024010100)
        n = store.conn.execute(
            "SELECT COUNT(*) AS n FROM versions").fetchone()
        self.assertEqual(n["n"], 1)

    def test_crash_between_statements_leaves_no_trace(self):
        # simulate a hard crash: insert a version row on a private
        # connection and drop the connection without committing
        store = self.repo.store
        victim = Store(self.db)
        victim._insert_version(1, 2024010999, "increment", None)
        victim.conn.close()  # never committed -> rolled back
        rows = store.conn.execute(
            "SELECT COUNT(*) AS n FROM versions WHERE serial = 2024010999"
        ).fetchone()
        self.assertEqual(rows["n"], 0)

    def test_recovery_fails_stale_publishing_rows(self):
        # a 'publishing' row that somehow got committed is failed on open
        store = self.repo.store
        with store.conn:
            store.conn.execute(
                "INSERT INTO versions (zone_id, serial, kind, status, "
                "created_at) VALUES (1, 555, 'master', 'publishing', 'now')")
        store._recover()
        row = store.conn.execute(
            "SELECT status FROM versions WHERE serial = 555").fetchone()
        self.assertEqual(row["status"], "failed")
        # and it is invisible to queries
        self.assertEqual([v.serial for v in self.repo.versions("example.com.")],
                         [2024010100])


class AtomicFileWriteTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "example.com.zone")

    def tearDown(self):
        self.tmp.cleanup()

    def test_write_and_replace(self):
        write_zone_file(self.path, "v1\n")
        write_zone_file(self.path, "v2\n")
        with open(self.path) as fh:
            self.assertEqual(fh.read(), "v2\n")

    def test_failed_write_keeps_old_file_and_cleans_tmp(self):
        write_zone_file(self.path, "good\n")
        with mock.patch("dnsrepo.generator.os.replace",
                        side_effect=OSError("crash")):
            with self.assertRaises(OSError):
                write_zone_file(self.path, "bad\n")
        with open(self.path) as fh:
            self.assertEqual(fh.read(), "good\n")
        leftovers = [f for f in os.listdir(self.tmp.name) if ".tmp." in f]
        self.assertEqual(leftovers, [])

    def test_failed_first_write_leaves_nothing(self):
        with mock.patch("dnsrepo.generator.os.replace",
                        side_effect=OSError("crash")):
            with self.assertRaises(OSError):
                write_zone_file(self.path, "bad\n")
        self.assertEqual(os.listdir(self.tmp.name), [])


if __name__ == "__main__":
    unittest.main()
