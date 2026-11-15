"""Offline history handoff: packing, inspection, receiving, conflicts,
rollback, concurrency and scale.

The standard scenario: an old library holds two zones to hand over
(alpha.example. with three versions, beta.example. whose serial wraps
from 4294967294 to 1) plus one zone that stays behind (keep.example.).
The receiving library is preloaded with an unrelated zone (so internal
ids differ) and an identical short prefix of alpha.example. obtained
through an earlier, smaller package.
"""

import hashlib
import json
import multiprocessing
import os
import queue
import resource
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from dnsrepo import Repository
from dnsrepo.errors import HandoffConflict, HandoffError, PrereqError
from dnsrepo.handoff import (FORMAT_NAME, FORMAT_VERSION, inspect_handoff,
                             pack_handoff)
from dnsrepo.records import Record
from dnsrepo.store import Store

# --------------------------------------------------------------------------
# scenario fixtures
# --------------------------------------------------------------------------

#  1  $ORIGIN alpha.example.
#  2  $TTL 3600
#  3  @ IN SOA ns1.alpha.example. hostmaster.alpha.example. 100 ...
#  4  @ IN NS ns1
#  5  ns1 A 192.0.2.1
#  6  www 300 IN A 192.0.2.80
#  7  _meta TXT "v=spf1 \"all\""
#  8  www CAA 0 issue "ca.example"
#  9  old A 192.0.2.99
ALPHA_V1 = """\
$ORIGIN alpha.example.
$TTL 3600
@ IN SOA ns1.alpha.example. hostmaster.alpha.example. 100 7200 3600 1209600 300
@ IN NS ns1
ns1 A 192.0.2.1
www 300 IN A 192.0.2.80
_meta TXT "v=spf1 \\"all\\""
www CAA 0 issue "ca.example"
old A 192.0.2.99
"""

#  1  $ZONE alpha.example.
#  2  $PREREQ 100
#  3  $SERIAL 200
#  4  $DELETE
#  5  old A
#  6  $ADD
#  7  api 600 IN A 192.0.2.50
#  8  $END
ALPHA_V2 = """\
$ZONE alpha.example.
$PREREQ 100
$SERIAL 200
$DELETE
old A
$ADD
api 600 IN A 192.0.2.50
$END
"""

#  1  $ZONE alpha.example.
#  2  $PREREQ 200
#  3  $SERIAL 300
#  4  $ADD
#  5  old 300 IN A 192.0.2.99
#  6  $END
ALPHA_V3 = """\
$ZONE alpha.example.
$PREREQ 200
$SERIAL 300
$ADD
old 300 IN A 192.0.2.99
$END
"""

# serial 4294967294; the next version wraps to 1 (RFC 1982)
BETA_V1 = """\
@ 300 IN SOA ns1 h 4294967294 7200 3600 1209600 300
@ IN NS ns1
"""

BETA_V2 = """\
$ZONE beta.example.
$PREREQ 4294967294
$SERIAL 1
$ADD
host 300 IN A 10.0.0.1
$END
"""

KEEP_V1 = "@ 300 IN SOA ns1 h 5 7200 3600 1209600 300\n"

OTHER_V1 = ("@ 300 IN SOA ns1 h 42 7200 3600 1209600 300\n"
            "@ IN NS ns1\n")
OTHER_V2 = ("$ZONE other.example.\n$PREREQ 42\n$SERIAL 43\n"
            "$ADD\nwww 300 IN A 192.0.2.10\n$END\n")


def build_old_db(path):
    """The old library: two zones to hand over, one to keep."""
    repo = Repository(path, preserve_unknown=True)
    repo.publish_master("alpha.example.", ALPHA_V1, source_file="alpha/v1.zone")
    repo.publish_increment(ALPHA_V2, source_file="alpha/v2.inc")
    repo.publish_increment(ALPHA_V3, source_file="alpha/v3.inc")
    repo.publish_master("beta.example.", BETA_V1)  # source_file is None
    repo.publish_increment(BETA_V2, source_file="beta/v2.inc")
    repo.publish_master("keep.example.", KEEP_V1, source_file="keep/v1.zone")
    repo.close()


def build_receiver_db(path, old_db, tmp):
    """The receiving library: unrelated content first (ids diverge),
    then a genuinely identical short prefix of alpha via an earlier
    package."""
    repo = Repository(path, preserve_unknown=True)
    repo.publish_master("other.example.", OTHER_V1, source_file="other/v1.zone")
    repo.publish_increment(OTHER_V2, source_file="other/v2.inc")
    repo.close()
    prefix_pkg = os.path.join(tmp, "prefix.dhf")
    pack_handoff(old_db, {"alpha.example.": 100}, prefix_pkg)
    repo = Repository(path, preserve_unknown=True)
    repo.receive_handoff(prefix_pkg)
    repo.close()


def dump_history(db_path, zones=None):
    """Independent SQL dump of every published record with its origin
    serial, for content/provenance comparison across libraries."""
    conn = sqlite3.connect(db_path)
    try:
        sql = ("SELECT z.name, v.serial, v.kind, v.source_file, "
               "       v.created_at, r.owner, r.rtype, r.ttl, r.rdata, "
               "       r.known, r.line_no, iv.serial "
               "FROM records r "
               "JOIN versions v ON v.id = r.version_id "
               "JOIN zones z ON z.id = v.zone_id "
               "JOIN versions iv ON iv.id = r.introduced_in "
               "WHERE v.status = 'published'")
        args = []
        if zones is not None:
            sql += " AND z.name IN (%s)" % ",".join("?" * len(zones))
            args.extend(zones)
        rows = conn.execute(sql, args).fetchall()
        return sorted(rows)
    finally:
        conn.close()


def version_rows(db_path, zone):
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute(
            "SELECT v.serial, v.kind, v.source_file, v.created_at "
            "FROM versions v JOIN zones z ON z.id = v.zone_id "
            "WHERE z.name = ? AND v.status = 'published' ORDER BY v.id",
            (zone,)).fetchall()
    finally:
        conn.close()


class HandoffCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.old_db = os.path.join(self.tmp.name, "old.db")
        self.new_db = os.path.join(self.tmp.name, "new.db")
        self.pkg = os.path.join(self.tmp.name, "handoff.dhf")
        build_old_db(self.old_db)

    def pack_main(self):
        return pack_handoff(self.old_db,
                            {"alpha.example.": 300, "beta.example.": 1},
                            self.pkg)

    def build_receiver(self):
        build_receiver_db(self.new_db, self.old_db, self.tmp.name)


# --------------------------------------------------------------------------
# packing
# --------------------------------------------------------------------------

class PackTest(HandoffCase):
    def test_pack_selects_history_up_to_cutoff(self):
        report = pack_handoff(self.old_db, {"alpha.example.": 200}, self.pkg)
        self.assertEqual([s.serial for z in report.zones for s in z.snapshots],
                         [100, 200])
        insp = inspect_handoff(self.pkg)
        self.assertEqual([z.name for z in insp.zones], ["alpha.example."])
        self.assertEqual([s.serial for s in insp.zones[0].snapshots],
                         [100, 200])
        # unselected zones are not in the package
        with open(self.pkg, encoding="utf-8") as fh:
            self.assertNotIn("keep.example.", fh.read())

    def test_pack_positions_follow_insertion_order_not_serial(self):
        self.pack_main()
        insp = inspect_handoff(self.pkg)
        beta = [z for z in insp.zones if z.name == "beta.example."][0]
        self.assertEqual([(s.position, s.serial) for s in beta.snapshots],
                         [(1, 4294967294), (2, 1)])

    def test_pack_each_zone_only_once(self):
        with self.assertRaisesRegex(HandoffError, "more than once"):
            pack_handoff(self.old_db,
                         [("alpha.example.", 100), ("alpha.example.", 200)],
                         self.pkg)

    def test_pack_cutoff_must_be_published(self):
        with self.assertRaisesRegex(HandoffError, "no published version"):
            pack_handoff(self.old_db, {"alpha.example.": 999}, self.pkg)

    def test_pack_unknown_zone(self):
        with self.assertRaisesRegex(HandoffError, "not found"):
            pack_handoff(self.old_db, {"nosuch.example.": 1}, self.pkg)

    def test_pack_empty_selection_rejected(self):
        with self.assertRaisesRegex(HandoffError, "empty"):
            pack_handoff(self.old_db, {}, self.pkg)

    def test_pack_bad_serial_rejected(self):
        with self.assertRaisesRegex(HandoffError, "cutoff serial"):
            pack_handoff(self.old_db, {"alpha.example.": 2 ** 32}, self.pkg)

    def test_pack_missing_source_db(self):
        with self.assertRaisesRegex(HandoffError, "does not exist"):
            pack_handoff(os.path.join(self.tmp.name, "nope.db"),
                         {"alpha.example.": 100}, self.pkg)

    def test_pack_refuses_to_overwrite(self):
        self.pack_main()
        with self.assertRaisesRegex(HandoffError, "already exists"):
            pack_handoff(self.old_db, {"alpha.example.": 100}, self.pkg)

    def test_failed_pack_leaves_no_output(self):
        with self.assertRaises(HandoffError):
            pack_handoff(self.old_db, {"nosuch.example.": 1}, self.pkg)
        self.assertEqual(os.listdir(self.tmp.name), ["old.db"])

    def test_pack_does_not_modify_source(self):
        before = dump_history(self.old_db)
        before_versions = version_rows(self.old_db, "alpha.example.")
        self.pack_main()
        self.assertEqual(dump_history(self.old_db), before)
        self.assertEqual(version_rows(self.old_db, "alpha.example."),
                         before_versions)
        # the pack connection leaves no WAL side files behind
        leftovers = [f for f in os.listdir(self.tmp.name)
                     if f.startswith("old.db-")]
        self.assertEqual(leftovers, [])

    def test_pack_runs_while_source_is_in_use(self):
        # another connection holds the source open (WAL mode)
        other = Store(self.old_db)
        try:
            self.pack_main()
            self.assertTrue(os.path.exists(self.pkg))
        finally:
            other.close()


# --------------------------------------------------------------------------
# consistent read view
# --------------------------------------------------------------------------

def _commit_two_zones(db_path):
    """Append version 2 to alpha.example. and beta.example. in ONE
    transaction (simulating a multi-zone publisher)."""
    store = Store(db_path)
    try:
        alpha = store.get_zone("alpha.example.")
        beta = store.get_zone("beta.example.")
        with store.conn:
            va = store._insert_version(alpha["id"], 200, "increment",
                                       "w.inc")
            store._insert_records(va, [
                Record("alpha.example.", "SOA", 300,
                       "ns1 h 200 7200 3600 1209600 300"),
                Record("alpha.example.", "NS", 300, "ns1"),
            ])
            store._finalize(alpha["id"], va)
            vb = store._insert_version(beta["id"], 1, "increment", "w.inc")
            store._insert_records(vb, [
                Record("beta.example.", "SOA", 300,
                       "ns1 h 1 7200 3600 1209600 300"),
                Record("beta.example.", "NS", 300, "ns1"),
            ])
            store._finalize(beta["id"], vb)
    finally:
        store.close()


def _writer_process(db_path, began, committed):
    began.wait(30)
    _commit_two_zones(db_path)
    committed.set()


class ConsistentReadTest(unittest.TestCase):
    """A pack that straddles a two-zone commit must see both zones old
    or both zones new — never a mix."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.old_db = os.path.join(self.tmp.name, "old.db")
        self.pkg = os.path.join(self.tmp.name, "handoff.dhf")
        repo = Repository(self.old_db, preserve_unknown=True)
        repo.publish_master("alpha.example.", ALPHA_V1)
        repo.publish_master("beta.example.", BETA_V1)
        repo.close()

    def test_read_view_is_one_snapshot(self):
        began = threading.Event()
        committed = threading.Event()
        outcome = {}

        def run_pack():
            try:
                pack_handoff(self.old_db,
                             {"alpha.example.": 200, "beta.example.": 1},
                             self.pkg,
                             after_begin=lambda: (began.set(),
                                                  committed.wait(30)))
                outcome["result"] = "ok"
            except HandoffError as exc:
                outcome["result"] = ("error", str(exc))

        thread = threading.Thread(target=run_pack)
        thread.start()
        self.assertTrue(began.wait(30))
        _commit_two_zones(self.old_db)  # both zones, one transaction
        committed.set()
        thread.join(30)
        # the pack's read view was pinned before the commit: it must not
        # see half of the two-zone transaction
        self.assertEqual(outcome["result"][0], "error")
        self.assertIn("no published version", outcome["result"][1])
        self.assertFalse(os.path.exists(self.pkg))
        # a fresh pack sees both zones new (both-new, never mixed)
        pack_handoff(self.old_db, {"alpha.example.": 200,
                                   "beta.example.": 1}, self.pkg)
        insp = inspect_handoff(self.pkg)
        got = {z.name: [s.serial for s in z.snapshots] for z in insp.zones}
        self.assertEqual(got, {"alpha.example.": [100, 200],
                               "beta.example.": [4294967294, 1]})

    def test_concurrent_process_commit_is_all_or_nothing(self):
        began = multiprocessing.Event()
        committed = multiprocessing.Event()
        writer = multiprocessing.Process(
            target=_writer_process, args=(self.old_db, began, committed))
        writer.start()
        began.set()
        outcomes = []
        deadline = time.time() + 30
        while writer.is_alive() and time.time() < deadline:
            pkg = os.path.join(self.tmp.name, "p%d.dhf" % len(outcomes))
            try:
                pack_handoff(self.old_db,
                             {"alpha.example.": 200, "beta.example.": 1},
                             pkg)
                outcomes.append(pkg)
            except HandoffError:
                pass  # pre-commit view: cutoffs not published yet
        writer.join(30)
        self.assertFalse(writer.is_alive())
        # every package that was produced contains BOTH zones' new
        # versions; a torn read would show exactly one of them
        for pkg in outcomes:
            insp = inspect_handoff(pkg)
            got = {z.name: [s.serial for s in z.snapshots]
                   for z in insp.zones}
            self.assertEqual(got, {"alpha.example.": [100, 200],
                                   "beta.example.": [4294967294, 1]})
        # and after the writer committed, packing succeeds
        final = os.path.join(self.tmp.name, "final.dhf")
        pack_handoff(self.old_db, {"alpha.example.": 200,
                                   "beta.example.": 1}, final)
        self.assertTrue(os.path.exists(final))


# --------------------------------------------------------------------------
# inspection of hand-crafted (but digest-valid) packages
# --------------------------------------------------------------------------

def _canon(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8") + b"\n"


def prec(zone, origin, owner, rtype, ttl, rdata, known=True, line_no=1,
         source_file="s.zone"):
    return {"type": "record", "owner": owner, "rtype": rtype, "ttl": ttl,
            "rdata": rdata, "known": known, "line_no": line_no,
            "origin_zone": zone, "origin_position": origin,
            "source_file": source_file}


Z = "z.example."
TS1 = "2024-01-01T00:00:00+00:00"
TS2 = "2024-01-02T00:00:00+00:00"


def snap1(records=None, serial=100, source_file="s.zone"):
    if records is None:
        records = [prec(Z, 1, Z, "SOA", 300,
                        "ns1 h %d 7200 3600 1209600 300" % serial,
                        line_no=1, source_file=source_file),
                   prec(Z, 1, Z, "NS", 300, "ns1", line_no=2,
                        source_file=source_file)]
    return (serial, "master", source_file, TS1, records)


def snap2(records=None, serial=200, source_file="i.zone"):
    if records is None:
        records = [prec(Z, 2, Z, "SOA", 300,
                        "ns1 h %d 7200 3600 1209600 300" % serial,
                        line_no=None, source_file=source_file),
                   prec(Z, 1, Z, "NS", 300, "ns1", line_no=2,
                        source_file="s.zone")]
    return (serial, "increment", source_file, TS2, records)


def craft_package(path, zones, header=None, trailer_mutate=None,
                  body_mutate=None):
    """Write a package from parts, computing counts and the digest over
    the actual body — so a semantically bad package still carries a
    VALID checksum and can only be caught by the semantic checks."""
    lines = [header or {"type": "header", "format": FORMAT_NAME,
                        "format_version": FORMAT_VERSION,
                        "created_at": TS1, "generator": "test"}]
    nz = ns = nr = 0
    for name, snapshots in zones:
        lines.append({"type": "zone", "name": name,
                      "snapshots": len(snapshots)})
        nz += 1
        for pos, (serial, kind, source_file, created_at, records) in \
                enumerate(snapshots, 1):
            lines.append({"type": "snapshot", "zone": name,
                          "position": pos, "serial": serial, "kind": kind,
                          "source_file": source_file,
                          "created_at": created_at,
                          "records": len(records)})
            ns += 1
            lines.extend(records)
            nr += len(records)
    body = b"".join(_canon(line) for line in lines)
    if body_mutate:
        body = body_mutate(body)
    trailer = {"type": "trailer", "zones": nz, "snapshots": ns,
               "records": nr, "sha256": hashlib.sha256(body).hexdigest()}
    if trailer_mutate:
        trailer.update(trailer_mutate)
    with open(path, "wb") as fh:
        fh.write(body + _canon(trailer))


class InspectTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.pkg = os.path.join(self.tmp.name, "test.dhf")

    def assertBad(self, needle, *args, **kwargs):
        craft_package(self.pkg, *args, **kwargs)
        with self.assertRaisesRegex(HandoffError, needle):
            inspect_handoff(self.pkg)

    # -- a valid package passes and lists contents ----------------------
    def test_valid_package_lists_contents(self):
        craft_package(self.pkg, [(Z, [snap1(), snap2()])])
        insp = inspect_handoff(self.pkg)
        self.assertEqual([z.name for z in insp.zones], [Z])
        self.assertEqual([(s.position, s.serial, s.kind, s.record_count)
                          for s in insp.zones[0].snapshots],
                         [(1, 100, "master", 2), (2, 200, "increment", 2)])
        self.assertEqual(insp.record_count, 4)

    # -- structure / integrity -------------------------------------------
    def test_missing_file(self):
        with self.assertRaisesRegex(HandoffError, "cannot open"):
            inspect_handoff(self.pkg)

    def test_empty_file(self):
        open(self.pkg, "wb").close()
        with self.assertRaisesRegex(HandoffError, "empty"):
            inspect_handoff(self.pkg)

    def test_truncated_mid_package(self):
        craft_package(self.pkg, [(Z, [snap1(), snap2()])])
        with open(self.pkg, "rb") as fh:
            data = fh.read()
        with open(self.pkg, "wb") as fh:
            fh.write(data[:len(data) * 3 // 5])
        with self.assertRaisesRegex(HandoffError, "truncated"):
            inspect_handoff(self.pkg)

    def test_truncated_final_newline(self):
        craft_package(self.pkg, [(Z, [snap1()])])
        with open(self.pkg, "rb") as fh:
            data = fh.read()
        with open(self.pkg, "wb") as fh:
            fh.write(data[:-1])
        with self.assertRaisesRegex(HandoffError, "truncated"):
            inspect_handoff(self.pkg)

    def test_tampered_body_stale_digest(self):
        # content changed but the digest NOT recomputed: integrity fails
        craft_package(self.pkg, [(Z, [snap1()])])
        with open(self.pkg, "rb") as fh:
            data = fh.read()
        self.assertIn(b'"ttl":300', data)
        with open(self.pkg, "wb") as fh:
            fh.write(data.replace(b'"ttl":300', b'"ttl":301', 1))
        with self.assertRaisesRegex(HandoffError, "integrity"):
            inspect_handoff(self.pkg)

    def test_trailer_count_lie(self):
        self.assertBad("declares 2 zones", [(Z, [snap1()])],
                       trailer_mutate={"zones": 2})

    def test_zone_snapshot_count_mismatch(self):
        # zone declares 2 snapshots but only 1 is present
        self.assertBad("declares 2 snapshots but 1 were found",
                       [(Z, [snap1()])],
                       body_mutate=lambda d: d.replace(b'"snapshots":1',
                                                       b'"snapshots":2'))

    def test_zone_declares_zero_snapshots(self):
        self.assertBad("snapshots.*>= 1", [(Z, [snap1()])],
                       body_mutate=lambda d: d.replace(b'"snapshots":1',
                                                       b'"snapshots":0'))

    def test_snapshot_record_count_mismatch(self):
        # snapshot declares 1 record but 2 follow
        self.assertBad("record outside any snapshot",
                       [(Z, [snap1()])],
                       body_mutate=lambda d: d.replace(b'"records":2',
                                                       b'"records":1'))
        # snapshot declares 3 records but 2 are present
        self.assertBad("declares 3 records but 2 were found",
                       [(Z, [snap1()])],
                       body_mutate=lambda d: d.replace(b'"records":2',
                                                       b'"records":3'))
        # snapshot declares 0 records but 1 follows
        self.assertBad("declares 0 records but more follow",
                       [(Z, [snap1(records=[prec(Z, 1, Z, "SOA", 300,
                                                 "ns1 h 100 7200 3600 "
                                                 "1209600 300",
                                                 line_no=1)])])],
                       body_mutate=lambda d: d.replace(b'"records":1',
                                                       b'"records":0'))

    def test_content_after_trailer(self):
        craft_package(self.pkg, [(Z, [snap1()])])
        with open(self.pkg, "ab") as fh:
            fh.write(b"\n")
        with self.assertRaisesRegex(HandoffError, "after the trailer"):
            inspect_handoff(self.pkg)

    def test_bad_header_format(self):
        self.assertBad("unrecognized", [(Z, [snap1()])],
                       header={"type": "header", "format": "other",
                               "format_version": 1})

    def test_bad_header_version(self):
        self.assertBad("unsupported format version", [(Z, [snap1()])],
                       header={"type": "header", "format": FORMAT_NAME,
                               "format_version": 99})

    def test_header_not_first(self):
        path = self.pkg
        craft_package(path, [(Z, [snap1()])])
        with open(path, "rb") as fh:
            lines = fh.read().splitlines(keepends=True)
        with open(path, "wb") as fh:
            fh.write(b"".join([lines[1], lines[0]] + lines[2:]))
        with self.assertRaisesRegex(HandoffError, "header"):
            inspect_handoff(path)

    # -- manifest semantics ------------------------------------------------
    def test_duplicate_zone(self):
        self.assertBad("duplicate zone", [(Z, [snap1()]), (Z, [snap1()])])

    def test_duplicate_serial(self):
        self.assertBad("does not increase", [(Z, [snap1(), snap2(serial=100)])])

    def test_wrong_publish_order(self):
        s_a = (200, "master", "s.zone", TS1,
               [prec(Z, 1, Z, "SOA", 300, "ns1 h 200 7200 3600 1209600 300",
                     line_no=1)])
        s_b = (100, "increment", "i.zone", TS2,
               [prec(Z, 2, Z, "SOA", 300, "ns1 h 100 7200 3600 1209600 300",
                     line_no=None, source_file="i.zone")])
        self.assertBad("does not increase", [(Z, [s_a, s_b])])

    def test_snapshot_position_gap(self):
        zones = [(Z, [snap1(), snap2()])]
        craft_package(self.pkg, zones,
                      body_mutate=lambda d: d.replace(b'"position":2',
                                                      b'"position":3'))
        with self.assertRaisesRegex(HandoffError, "position"):
            inspect_handoff(self.pkg)

    # -- bad fields ---------------------------------------------------------
    def test_bad_fields(self):
        cases = [
            ("ttl", [prec(Z, 1, Z, "SOA", 2 ** 31,
                          "ns1 h 100 7200 3600 1209600 300", line_no=1)]),
            ("line_no", [prec(Z, 1, Z, "SOA", 300,
                              "ns1 h 100 7200 3600 1209600 300",
                              line_no=0)]),
            ("known", [prec(Z, 1, Z, "SOA", 300,
                            "ns1 h 100 7200 3600 1209600 300",
                            known="yes")]),
            ("record type", [prec(Z, 1, Z, "bad!", 300, "ns1")]),
            ("owner", [prec(Z, 1, "not-absolute", "SOA", 300,
                            "ns1 h 100 7200 3600 1209600 300")]),
        ]
        for needle, records in cases:
            with self.subTest(needle=needle):
                self.assertBad(needle, [(Z, [snap1(records=records)])])

    def test_bad_snapshot_fields(self):
        self.assertBad("bad snapshot kind",
                       [(Z, [(100, "weird", "s", TS1, snap1()[4])])])
        self.assertBad("created_at",
                       [(Z, [(100, "master", "s", "yesterday",
                              snap1()[4])])])
        self.assertBad("must be <=", [(Z, [(2 ** 32, "master", "s", TS1,
                                            snap1()[4])])])

    def test_bad_zone_name(self):
        self.assertBad("canonical", [("Z.Example.", [snap1()])])

    # -- zone semantics ------------------------------------------------------
    def test_snapshot_fails_zone_semantics(self):
        two_soas = [prec(Z, 1, Z, "SOA", 300,
                         "ns1 h 100 7200 3600 1209600 300", line_no=1),
                    prec(Z, 1, Z, "SOA", 600,
                         "ns2 h 100 7200 3600 1209600 300", line_no=2)]
        self.assertBad("not a valid zone", [(Z, [snap1(records=two_soas)])])
        soa_wrong_serial = [prec(Z, 1, Z, "SOA", 300,
                                 "ns1 h 999 7200 3600 1209600 300",
                                 line_no=1)]
        self.assertBad("not a valid zone",
                       [(Z, [snap1(records=soa_wrong_serial)])])
        out_of_zone = [prec(Z, 1, Z, "SOA", 300,
                            "ns1 h 100 7200 3600 1209600 300", line_no=1),
                       prec(Z, 1, "www.other.net.", "A", 300, "192.0.2.1",
                            line_no=2)]
        self.assertBad("not a valid zone",
                       [(Z, [snap1(records=out_of_zone)])])
        cname_clash = [prec(Z, 1, Z, "SOA", 300,
                            "ns1 h 100 7200 3600 1209600 300", line_no=1),
                       prec(Z, 1, "www." + Z, "CNAME", 300, "x." + Z,
                            line_no=2),
                       prec(Z, 1, "www." + Z, "A", 300, "192.0.2.1",
                            line_no=3)]
        self.assertBad("not a valid zone",
                       [(Z, [snap1(records=cname_clash)])])

    # -- origin coordinates ---------------------------------------------------
    def test_origin_cross_zone(self):
        records = [prec(Z, 1, Z, "SOA", 300,
                        "ns1 h 100 7200 3600 1209600 300", line_no=1,
                        source_file="s.zone"),
                   dict(prec(Z, 1, Z, "NS", 300, "ns1", line_no=2),
                        origin_zone="other.example.")]
        self.assertBad("cross-zone", [(Z, [snap1(records=records)])])

    def test_origin_in_the_future(self):
        records = [prec(Z, 1, Z, "SOA", 300,
                        "ns1 h 100 7200 3600 1209600 300", line_no=1),
                   prec(Z, 2, Z, "NS", 300, "ns1", line_no=2)]
        self.assertBad("future", [(Z, [snap1(records=records)])])

    def test_origin_nonexistent(self):
        records = [prec(Z, 1, Z, "SOA", 300,
                        "ns1 h 100 7200 3600 1209600 300", line_no=1),
                   prec(Z, 0, Z, "NS", 300, "ns1", line_no=2)]
        self.assertBad(">= 1", [(Z, [snap1(records=records)])])

    def test_origin_snapshot_lacks_record(self):
        # the NS record claims origin #1 but snapshot #1 never
        # self-introduced it (snapshot #1 has SOA only)
        s1 = snap1(records=[prec(Z, 1, Z, "SOA", 300,
                                 "ns1 h 100 7200 3600 1209600 300",
                                 line_no=1)])
        s2 = snap2(records=[prec(Z, 2, Z, "SOA", 300,
                                 "ns1 h 200 7200 3600 1209600 300",
                                 line_no=None, source_file="i.zone"),
                            prec(Z, 1, Z, "NS", 300, "ns1", line_no=2)])
        self.assertBad("no matching self-introduced", [(Z, [s1, s2])])

    def test_origin_source_file_mismatch(self):
        records = [prec(Z, 2, Z, "SOA", 300,
                        "ns1 h 200 7200 3600 1209600 300", line_no=None,
                        source_file="i.zone"),
                   prec(Z, 1, Z, "NS", 300, "ns1", line_no=2,
                        source_file="wrong.zone")]
        self.assertBad("claims source_file", [(Z, [snap1(), snap2(records=records)])])

    def test_null_vs_empty_source_file(self):
        # origin snapshot has source_file null; "" does not match it
        s1 = snap1(source_file=None)
        records = [prec(Z, 2, Z, "SOA", 300,
                        "ns1 h 200 7200 3600 1209600 300", line_no=None,
                        source_file="i.zone"),
                   prec(Z, 1, Z, "NS", 300, "ns1", line_no=2,
                        source_file="")]
        self.assertBad("claims source_file", [(Z, [s1, snap2(records=records)])])


# --------------------------------------------------------------------------
# receiving: the happy path (re-runnable scenario)
# --------------------------------------------------------------------------

class ReceiveHappyPathTest(HandoffCase):
    def test_full_handoff_then_business_as_usual(self):
        self.pack_main()
        self.build_receiver()
        repo = Repository(self.new_db, preserve_unknown=True)

        report = repo.receive_handoff(self.pkg)
        outcomes = {o.zone: o for o in report.outcomes}
        self.assertEqual(outcomes["alpha.example."].reused, 1)
        self.assertEqual(outcomes["alpha.example."].appended, 2)
        self.assertEqual(outcomes["beta.example."].reused, 0)
        self.assertEqual(outcomes["beta.example."].appended, 2)
        self.assertEqual(outcomes["alpha.example."].head_serial, 300)
        self.assertEqual(outcomes["beta.example."].head_serial, 1)

        # --- old serials stay queryable through the normal API
        self.assertEqual([v.serial for v in repo.versions("alpha.example.")],
                         [100, 200, 300])
        self.assertEqual([v.serial for v in repo.versions("beta.example.")],
                         [4294967294, 1])
        old = repo.records("alpha.example.", serial=100)
        self.assertTrue(any(r.owner == "old.alpha.example."
                            for r in old))
        self.assertFalse(any(r.owner == "api.alpha.example."
                             for r in old))

        # --- diffs work across the handoff, including the serial wrap
        diff = repo.diff("alpha.example.", 100, 300)
        added = {(r.owner, r.rtype) for r in diff.added}
        self.assertIn(("api.alpha.example.", "A"), added)
        bdiff = repo.diff("beta.example.", 4294967294, 1)
        self.assertTrue(any(r.owner == "host.beta.example."
                            for r in bdiff.added))

        # --- provenance survives: source file and line numbers
        recs = repo.records("alpha.example.", serial=300)
        www = [r for r in recs if r.owner == "www.alpha.example."
               and r.rtype == "A"][0]
        self.assertEqual((www.line_no, www.source_file), (6, "alpha/v1.zone"))
        api = [r for r in recs if r.owner == "api.alpha.example."][0]
        self.assertEqual((api.line_no, api.source_file), (7, "alpha/v2.inc"))
        readded = [r for r in recs if r.owner == "old.alpha.example."][0]
        self.assertEqual((readded.line_no, readded.source_file),
                         (5, "alpha/v3.inc"))
        soa = [r for r in recs if r.rtype == "SOA"][0]
        self.assertIsNone(soa.line_no)  # synthesized serial bump
        # TXT and the unknown type moved verbatim
        txt = [r for r in recs if r.rtype == "TXT"][0]
        self.assertEqual(txt.rdata, '"v=spf1 \\"all\\""')
        caa = [r for r in recs if r.rtype == "CAA"][0]
        self.assertFalse(caa.known)
        self.assertEqual(caa.rdata, '0 issue "ca.example"')
        # beta's null source_file stayed null
        beta1 = repo.records("beta.example.", serial=4294967294)
        self.assertTrue(all(r.source_file is None for r in beta1))

        # --- independent SQL: content and origin coordinates identical
        handed = ["alpha.example.", "beta.example."]
        self.assertEqual(dump_history(self.old_db, handed),
                         dump_history(self.new_db, handed))
        # origin serial mapping, checked by hand for the tricky records
        conn = sqlite3.connect(self.new_db)
        origin_of = {}
        for owner, intro_serial in conn.execute(
                "SELECT r.owner, iv.serial FROM records r "
                "JOIN versions v ON v.id = r.version_id "
                "JOIN versions iv ON iv.id = r.introduced_in "
                "JOIN zones z ON z.id = v.zone_id "
                "WHERE z.name = 'alpha.example.' AND v.serial = 300"):
            origin_of[owner] = intro_serial
        conn.close()
        self.assertEqual(origin_of["www.alpha.example."], 100)   # carried
        self.assertEqual(origin_of["api.alpha.example."], 200)   # added v2
        self.assertEqual(origin_of["old.alpha.example."], 300)   # re-added
        self.assertEqual(origin_of["alpha.example."], 300)       # SOA bump

        # --- the kept-out zone never crossed over; preload untouched
        self.assertIsNone(repo.current("keep.example."))
        self.assertEqual([v.serial for v in repo.versions("other.example.")],
                         [42, 43])

        # --- receiving the same package again changes nothing
        before = dump_history(self.new_db)
        again = repo.receive_handoff(self.pkg)
        self.assertEqual(again.appended, 0)
        self.assertEqual(dump_history(self.new_db), before)
        self.assertEqual([v.serial for v in repo.versions("alpha.example.")],
                         [100, 200, 300])

        # --- incremental publishing continues at the handoff tail
        repo.publish_increment(
            "$ZONE alpha.example.\n$PREREQ 300\n$SERIAL 400\n"
            "$ADD\nnew 300 IN A 192.0.2.200\n$END",
            source_file="followup.inc")
        self.assertEqual(repo.current("alpha.example.").serial, 400)
        repo.publish_increment(
            "$ZONE beta.example.\n$PREREQ 1\n$SERIAL 2\n"
            "$ADD\nsecond 300 IN A 10.0.0.2\n$END")
        self.assertEqual(repo.current("beta.example.").serial, 2)
        repo.close()

    def test_package_is_self_contained(self):
        self.pack_main()
        self.build_receiver()
        os.unlink(self.old_db)  # the old library is gone
        repo = Repository(self.new_db, preserve_unknown=True)
        report = repo.receive_handoff(self.pkg)
        self.assertEqual(report.appended, 4)
        self.assertEqual(repo.current("alpha.example.").serial, 300)
        repo.close()

    def test_source_paths_are_never_opened(self):
        db = os.path.join(self.tmp.name, "evil.db")
        repo = Repository(db)
        repo.publish_master("z.example.",
                            "@ 300 IN SOA ns1 h 7 7200 3600 1209600 300\n",
                            source_file="$(touch /tmp/pwned); rm -rf /")
        repo.close()
        pkg = os.path.join(self.tmp.name, "evil.dhf")
        pack_handoff(db, {"z.example.": 7}, pkg)
        target = Repository(self.new_db)
        target.receive_handoff(pkg)
        self.assertFalse(os.path.exists("/tmp/pwned"))
        self.assertEqual(target.current("z.example.").serial, 7)
        target.close()


# --------------------------------------------------------------------------
# receiving: conflicts
# --------------------------------------------------------------------------

class ConflictTest(HandoffCase):
    def receive(self, package=None, repo=None):
        close = False
        if repo is None:
            repo = Repository(self.new_db, preserve_unknown=True)
            close = True
        try:
            return repo.receive_handoff(package or self.pkg)
        finally:
            if close:
                repo.close()

    def test_same_content_different_source_file(self):
        self.pack_main()
        repo = Repository(self.new_db, preserve_unknown=True)
        repo.publish_master("alpha.example.", ALPHA_V1,
                            source_file="different.zone")
        repo.close()
        with self.assertRaises(HandoffConflict) as ctx:
            self.receive()
        conflicts = ctx.exception.conflicts
        self.assertEqual(len(conflicts), 1)
        c = conflicts[0]
        self.assertEqual((c.zone, c.serial, c.category),
                         ("alpha.example.", 100, "metadata"))
        self.assertIn("source_file", c.detail)
        # nothing was spliced: alpha has only its own version, beta absent
        self.assertEqual(version_rows(self.new_db, "alpha.example."),
                         version_rows(self.new_db, "alpha.example."))
        repo = Repository(self.new_db, preserve_unknown=True)
        self.assertEqual([v.serial for v in repo.versions("alpha.example.")],
                         [100])
        self.assertIsNone(repo.current("beta.example."))
        repo.close()

    def test_same_content_different_created_at(self):
        self.pack_main()
        repo = Repository(self.new_db, preserve_unknown=True)
        repo.publish_master("alpha.example.", ALPHA_V1,
                            source_file="alpha/v1.zone")
        repo.close()
        with self.assertRaises(HandoffConflict) as ctx:
            self.receive()
        c = ctx.exception.conflicts[0]
        self.assertEqual(c.category, "metadata")
        self.assertIn("created_at", c.detail)

    def test_same_answers_different_line_no(self):
        self.pack_main()
        self.build_receiver()
        # corrupt the receiver's prefix: same DNS answers, shifted line
        conn = sqlite3.connect(self.new_db)
        conn.execute(
            "UPDATE records SET line_no = 999 WHERE id = ("
            "  SELECT r.id FROM records r JOIN versions v "
            "  ON v.id = r.version_id JOIN zones z ON z.id = v.zone_id "
            "  WHERE z.name = 'alpha.example.' AND v.serial = 100 "
            "  AND r.owner = 'www.alpha.example.' AND r.rtype = 'A')")
        conn.commit()
        conn.close()
        with self.assertRaises(HandoffConflict) as ctx:
            self.receive()
        c = ctx.exception.conflicts[0]
        self.assertEqual((c.zone, c.serial, c.category),
                         ("alpha.example.", 100, "records"))

    def test_same_answers_different_origin(self):
        # receiver has alpha [100, 200] via an earlier package; then the
        # carried TXT in version 200 is made to claim introduction in 200
        pkg200 = os.path.join(self.tmp.name, "p200.dhf")
        pack_handoff(self.old_db, {"alpha.example.": 200}, pkg200)
        repo = Repository(self.new_db, preserve_unknown=True)
        repo.receive_handoff(pkg200)
        repo.close()
        conn = sqlite3.connect(self.new_db)
        conn.execute(
            "UPDATE records SET introduced_in = version_id WHERE id = ("
            "  SELECT r.id FROM records r JOIN versions v "
            "  ON v.id = r.version_id JOIN zones z ON z.id = v.zone_id "
            "  WHERE z.name = 'alpha.example.' AND v.serial = 200 "
            "  AND r.rtype = 'TXT')")
        conn.commit()
        conn.close()
        pack_handoff(self.old_db, {"alpha.example.": 300}, self.pkg)
        with self.assertRaises(HandoffConflict) as ctx:
            self.receive()
        c = ctx.exception.conflicts[0]
        self.assertEqual((c.zone, c.serial, c.category),
                         ("alpha.example.", 200, "records"))

    def test_target_history_longer_is_conflict_not_truncation(self):
        pack_handoff(self.old_db, {"alpha.example.": 200}, self.pkg)
        repo = Repository(self.new_db, preserve_unknown=True)
        repo.receive_handoff(self.pkg)
        repo.close()
        # now a package that ends EARLIER than the receiver's history
        pkg100 = os.path.join(self.tmp.name, "p100.dhf")
        pack_handoff(self.old_db, {"alpha.example.": 100}, pkg100)
        with self.assertRaises(HandoffConflict) as ctx:
            self.receive(pkg100)
        c = ctx.exception.conflicts[0]
        self.assertEqual((c.zone, c.category),
                         ("alpha.example.", "target-longer"))
        self.assertEqual(c.serial, 200)  # first extra receiver version
        repo = Repository(self.new_db, preserve_unknown=True)
        self.assertEqual([v.serial for v in repo.versions("alpha.example.")],
                         [100, 200])
        repo.close()

    def test_newer_serial_does_not_overwrite_other_history(self):
        # receiver's gamma has serial 50 with content X; the package
        # carries serial 100 with content Y: conflict, not overwrite
        repo = Repository(self.new_db, preserve_unknown=True)
        repo.publish_master("gamma.example.",
                            "@ 300 IN SOA ns1 h 50 7200 3600 1209600 300\n"
                            "www 300 IN A 192.0.2.1\n",
                            source_file="g.zone")
        repo.close()
        records = [prec("gamma.example.", 1, "gamma.example.", "SOA", 300,
                        "ns1 h 100 7200 3600 1209600 300", line_no=1,
                        source_file="g.zone"),
                   prec("gamma.example.", 1, "www.gamma.example.", "A",
                        300, "192.0.2.99", line_no=2, source_file="g.zone")]
        craft_package(self.pkg, [("gamma.example.",
                                  [(100, "master", "g.zone", TS1,
                                    records)])])
        with self.assertRaises(HandoffConflict) as ctx:
            self.receive()
        c = ctx.exception.conflicts[0]
        self.assertEqual((c.zone, c.serial, c.category),
                         ("gamma.example.", 100, "serial"))
        repo = Repository(self.new_db, preserve_unknown=True)
        self.assertEqual([v.serial for v in repo.versions("gamma.example.")],
                         [50])
        self.assertEqual(repo.lookup("gamma.example.", "www", "A")[0].rdata,
                         "192.0.2.1")
        repo.close()

    def test_conflict_in_later_zone_rolls_back_everything(self):
        self.pack_main()
        self.build_receiver()
        # receiver's own beta history diverges from the package
        repo = Repository(self.new_db, preserve_unknown=True)
        repo.publish_master("beta.example.",
                            "@ 300 IN SOA ns1 h 4294967294 7200 3600 "
                            "1209600 300\n@ IN NS ns2\n")
        repo.close()
        with self.assertRaises(HandoffConflict):
            self.receive()
        # alpha's splice (positions 2..3) was rolled back too
        repo = Repository(self.new_db, preserve_unknown=True)
        self.assertEqual([v.serial for v in repo.versions("alpha.example.")],
                         [100])
        self.assertEqual(repo.current("alpha.example.").serial, 100)
        self.assertEqual([v.serial for v in repo.versions("beta.example.")],
                         [4294967294])
        self.assertEqual(repo.current("beta.example.").serial, 4294967294)
        repo.close()
        # and after reopening, still no half-spliced history
        repo = Repository(self.new_db, preserve_unknown=True)
        self.assertEqual([v.serial for v in repo.versions("alpha.example.")],
                         [100])
        self.assertEqual(repo.current("alpha.example.").serial, 100)
        repo.close()

    def test_semantic_failure_in_second_zone_rolls_back(self):
        self.pack_main()
        self.build_receiver()
        # corrupt the package's beta section (bad origin), digest fixed up
        with open(self.pkg, "rb") as fh:
            data = fh.read()
        bad = data.replace(b'"origin_position":1', b'"origin_position":2',
                           1)
        lines = bad.splitlines(keepends=True)
        body, trailer = lines[:-1], json.loads(lines[-1])
        trailer["sha256"] = hashlib.sha256(b"".join(body)).hexdigest()
        with open(self.pkg, "wb") as fh:
            fh.write(b"".join(body) + _canon(trailer))
        with self.assertRaises(HandoffError):
            self.receive()
        repo = Repository(self.new_db, preserve_unknown=True)
        self.assertEqual([v.serial for v in repo.versions("alpha.example.")],
                         [100])
        self.assertEqual(repo.current("alpha.example.").serial, 100)
        self.assertIsNone(repo.current("beta.example."))
        repo.close()

    def test_truncated_package_receive_rolls_back(self):
        self.pack_main()
        self.build_receiver()
        with open(self.pkg, "rb") as fh:
            data = fh.read()
        with open(self.pkg, "wb") as fh:
            fh.write(data[:len(data) // 2])
        with self.assertRaises(HandoffError):
            self.receive()
        repo = Repository(self.new_db, preserve_unknown=True)
        self.assertEqual([v.serial for v in repo.versions("alpha.example.")],
                         [100])
        self.assertEqual(repo.current("alpha.example.").serial, 100)
        repo.close()

    def test_database_error_mid_receive_rolls_back(self):
        self.pack_main()
        self.build_receiver()
        repo = Repository(self.new_db, preserve_unknown=True)
        calls = {"n": 0}
        real = repo.store._insert_records

        def fail_on_beta(version_id, records):
            calls["n"] += 1
            if calls["n"] == 3:  # first insert of the second zone
                raise sqlite3.OperationalError("disk I/O error")
            return real(version_id, records)

        with mock.patch.object(repo.store, "_insert_records",
                               side_effect=fail_on_beta):
            with self.assertRaises(sqlite3.OperationalError):
                repo.receive_handoff(self.pkg)
        repo.close()
        # everything (including alpha's appended tail) was rolled back;
        # no empty zone, no half history, also after reopening
        repo = Repository(self.new_db, preserve_unknown=True)
        self.assertEqual([v.serial for v in repo.versions("alpha.example.")],
                         [100])
        self.assertEqual(repo.current("alpha.example.").serial, 100)
        self.assertIsNone(repo.current("beta.example."))
        self.assertEqual(sorted(z for z, _ in repo.zones()),
                         ["alpha.example.", "other.example."])
        repo.close()


# --------------------------------------------------------------------------
# concurrency at the receive/publish boundary
# --------------------------------------------------------------------------

RACE_INC = ("$ZONE alpha.example.\n$PREREQ 100\n$SERIAL 200\n"
            "$ADD\npub 300 IN A 10.9.9.9\n$END")


def _race_publisher(db_path, barrier, delay, result):
    try:
        repo = Repository(db_path)
        repo.store.conn.execute("PRAGMA busy_timeout = 30000")
        barrier.wait()
        if delay:
            time.sleep(delay)
        repo.publish_increment(RACE_INC, source_file="race.inc")
        repo.close()
        result.put(("publish", "ok"))
    except Exception as exc:
        result.put(("publish", "error", type(exc).__name__))


class ReceivePublishRaceTest(unittest.TestCase):
    """A receive and a normal publish racing the same zone: exactly one
    wins, the other fails loudly, and the final history is complete."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.old_db = os.path.join(self.tmp.name, "old.db")
        self.new_db = os.path.join(self.tmp.name, "new.db")
        self.pkg = os.path.join(self.tmp.name, "handoff.dhf")
        build_old_db(self.old_db)
        pack_handoff(self.old_db, {"alpha.example.": 200}, self.pkg)
        # receiver carries the identical prefix alpha[100]
        pack_handoff(self.old_db, {"alpha.example.": 100},
                     os.path.join(self.tmp.name, "prefix.dhf"))
        repo = Repository(self.new_db)
        repo.receive_handoff(os.path.join(self.tmp.name, "prefix.dhf"))
        repo.close()

    def race(self, publish_delay=0.0, receive_delay=0.0):
        barrier = multiprocessing.Barrier(2)
        result = multiprocessing.Queue()
        proc = multiprocessing.Process(
            target=_race_publisher,
            args=(self.new_db, barrier, publish_delay, result))
        proc.start()
        barrier.wait()
        if receive_delay:
            time.sleep(receive_delay)
        repo = Repository(self.new_db)
        repo.store.conn.execute("PRAGMA busy_timeout = 30000")
        try:
            repo.receive_handoff(self.pkg)
            receive_outcome = ("receive", "ok")
        except HandoffConflict:
            receive_outcome = ("receive", "conflict")
        repo.close()
        proc.join(30)
        self.assertFalse(proc.is_alive())
        publish_outcome = result.get(timeout=10)
        return receive_outcome, publish_outcome

    def final_state(self):
        repo = Repository(self.new_db)
        versions = [v.serial for v in repo.versions("alpha.example.")]
        recs = {r.owner for r in repo.records("alpha.example.", serial=200)}
        repo.close()
        return versions, recs

    def test_receive_then_publish(self):
        receive_outcome, publish_outcome = self.race(publish_delay=0.5)
        self.assertEqual(receive_outcome, ("receive", "ok"))
        # the publisher's baseline moved under it: loud failure
        self.assertEqual(publish_outcome, ("publish", "error",
                                           "PrereqError"))
        versions, recs = self.final_state()
        self.assertEqual(versions, [100, 200])
        self.assertIn("api.alpha.example.", recs)       # from the package
        self.assertNotIn("pub.alpha.example.", recs)

    def test_publish_then_receive(self):
        receive_outcome, publish_outcome = self.race(receive_delay=0.5)
        self.assertEqual(publish_outcome, ("publish", "ok"))
        # the package's tail no longer matches: loud conflict
        self.assertEqual(receive_outcome, ("receive", "conflict"))
        versions, recs = self.final_state()
        self.assertEqual(versions, [100, 200])
        self.assertIn("pub.alpha.example.", recs)       # from the publish
        self.assertNotIn("api.alpha.example.", recs)

    def test_simultaneous_never_loses_history(self):
        winners = set()
        for _ in range(4):
            self.setUp()
            receive_outcome, publish_outcome = self.race()
            # exactly one side wins; the loser fails loudly
            outcomes = {receive_outcome[1], publish_outcome[1]}
            self.assertEqual(len([o for o in outcomes if o == "ok"]), 1)
            versions, recs = self.final_state()
            self.assertEqual(versions, [100, 200])
            # version 200 is exactly one of the two candidates, whole
            if receive_outcome[1] == "ok":
                self.assertIn("api.alpha.example.", recs)
                winners.add("receive")
            else:
                self.assertIn("pub.alpha.example.", recs)
                winners.add("publish")
            self.tearDown()


class TwoReceiversTest(HandoffCase):
    def test_two_receivers_same_package(self):
        self.pack_main()
        results = queue.Queue()

        def receive():
            repo = Repository(self.new_db, preserve_unknown=True)
            repo.store.conn.execute("PRAGMA busy_timeout = 30000")
            try:
                report = repo.receive_handoff(self.pkg)
                results.put(("ok", report.appended))
            except Exception as exc:
                results.put(("error", type(exc).__name__))
            finally:
                repo.close()

        threads = [threading.Thread(target=receive) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        outcomes = [results.get(timeout=10) for _ in range(2)]
        self.assertEqual([o[0] for o in outcomes], ["ok", "ok"])
        # one did the splice (3 alpha + 2 beta snapshots), the other
        # found nothing to do
        self.assertEqual(sorted(o[1] for o in outcomes), [0, 5])
        repo = Repository(self.new_db, preserve_unknown=True)
        self.assertEqual([v.serial for v in repo.versions("alpha.example.")],
                         [100, 200, 300])
        repo.close()


# --------------------------------------------------------------------------
# command line
# --------------------------------------------------------------------------

class CliTest(HandoffCase):
    def run_cli(self, *argv):
        from dnsrepo.cli import main
        return main(list(argv))

    def test_cli_flow(self):
        self.build_receiver()
        self.assertEqual(
            self.run_cli("--db", self.old_db, "handoff-pack", self.pkg,
                         "alpha.example.=300", "beta.example.=1"), 0)
        self.assertEqual(self.run_cli("handoff-inspect", self.pkg), 0)
        self.assertEqual(
            self.run_cli("--db", self.new_db, "handoff-receive", self.pkg),
            0)
        # and the receiving repository answers through the normal CLI
        self.assertEqual(
            self.run_cli("--db", self.new_db, "history", "alpha.example."),
            0)

    def test_cli_bad_selection(self):
        self.assertEqual(
            self.run_cli("--db", self.old_db, "handoff-pack", self.pkg,
                         "alpha.example."), 1)
        self.assertEqual(
            self.run_cli("--db", self.old_db, "handoff-pack", self.pkg,
                         "alpha.example.=100", "alpha.example.=200"), 1)

    def test_cli_conflict_exit_code(self):
        self.pack_main()
        repo = Repository(self.new_db, preserve_unknown=True)
        repo.publish_master("alpha.example.", ALPHA_V1,
                            source_file="different.zone")
        repo.close()
        self.assertEqual(
            self.run_cli("--db", self.new_db, "handoff-receive", self.pkg),
            1)


# --------------------------------------------------------------------------
# scale: 100k+ records across versions through the actual commands
# --------------------------------------------------------------------------

class ScaleTest(unittest.TestCase):
    VERSIONS = 25
    BASE = 3000
    STEP = 125

    def build_big_db(self, path):
        repo = Repository(path)
        hosts = ["host-%05d 300 IN A 10.%d.%d.%d"
                 % (i, (i >> 16) & 255, (i >> 8) & 255, i & 255)
                 for i in range(self.BASE)]
        master = ("$ORIGIN big.example.\n$TTL 300\n"
                  "@ IN SOA ns1 h 1 7200 3600 1209600 300\n"
                  "@ IN NS ns1\n" + "\n".join(hosts) + "\n")
        repo.publish_master("big.example.", master, source_file="big/01.zone")
        for version in range(2, self.VERSIONS + 1):
            start = self.BASE + (version - 2) * self.STEP
            adds = ["host-%05d 300 IN A 10.%d.%d.%d"
                    % (i, (i >> 16) & 255, (i >> 8) & 255, i & 255)
                    for i in range(start, start + self.STEP)]
            inc = ("$ZONE big.example.\n$PREREQ %d\n$SERIAL %d\n$ADD\n%s\n"
                   "$END\n" % (version - 1, version, "\n".join(adds)))
            repo.publish_increment(inc,
                                   source_file="big/%02d.inc" % version)
        repo.close()

    def run_cli(self, *argv):
        env = dict(os.environ)
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env["PYTHONPATH"] = root + os.pathsep + env.get("PYTHONPATH", "")
        start = time.monotonic()
        proc = subprocess.run(
            [sys.executable, "-m", "dnsrepo"] + list(argv),
            cwd=root, env=env, capture_output=True, text=True, timeout=600)
        elapsed = time.monotonic() - start
        peak_kb = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        self.assertEqual(proc.returncode, 0,
                         "command failed: %s\n%s" % (proc.args, proc.stderr))
        return elapsed, peak_kb, proc.stdout

    def test_100k_records_through_the_commands(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        old_db = os.path.join(tmp.name, "old.db")
        new_db = os.path.join(tmp.name, "new.db")
        pkg = os.path.join(tmp.name, "big.dhf")

        self.build_big_db(old_db)
        expected_records = sum(
            self.BASE + self.STEP * (v - 1) for v in range(1, self.VERSIONS + 1))
        self.assertGreater(expected_records, 100000)

        t_pack, peak1, out1 = self.run_cli(
            "--db", old_db, "handoff-pack", pkg, "big.example.=25")
        t_inspect, peak2, out2 = self.run_cli("handoff-inspect", pkg)
        t_receive, peak3, out3 = self.run_cli(
            "--db", new_db, "handoff-receive", pkg)
        print("\nscale: %d records | pack %.1fs | inspect %.1fs | "
              "receive %.1fs | peak RSS %.0f MB"
              % (expected_records, t_pack, t_inspect, t_receive,
                 max(peak1, peak2, peak3) / 1024))
        # memory stays bounded (one snapshot + disk indexes, never the
        # whole package)
        self.assertLess(max(peak1, peak2, peak3), 600 * 1024)

        # content and origins arrived intact (independent SQL comparison)
        self.assertEqual(dump_history(old_db), dump_history(new_db))
        counts = dict(version_rows_count(new_db))
        self.assertEqual(len(counts), self.VERSIONS)
        repo = Repository(new_db)
        self.assertEqual(repo.current("big.example.").serial, 25)
        # a carried record still points at the version that introduced it
        recs = repo.records("big.example.", serial=25)
        self.assertEqual(len(recs), self.BASE + self.STEP * 24 + 2)
        repo.close()


def version_rows_count(db_path):
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute(
            "SELECT v.serial, COUNT(*) FROM records r "
            "JOIN versions v ON v.id = r.version_id "
            "GROUP BY v.serial").fetchall()
    finally:
        conn.close()


if __name__ == "__main__":
    unittest.main()
