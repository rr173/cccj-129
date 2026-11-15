"""End-to-end repository behaviour: publishing, queryable versions,
record lineage (source lines), diffs, resolve, export."""

import os
import tempfile
import unittest

from dnsrepo.repo import Repository
from dnsrepo.errors import ZoneError

from .helpers import INCREMENT_V2, MASTER_V1


class RepoTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "test.db")
        self.repo = Repository(self.db)
        self.repo.publish_master("example.com.", MASTER_V1,
                                 source_file="zones/v1.zone")
        self.repo.publish_increment(INCREMENT_V2, source_file="incr/v2.inc")

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    # -- versions -----------------------------------------------------
    def test_current_version(self):
        info = self.repo.current("example.com.")
        self.assertEqual(info.serial, 2024010101)
        self.assertEqual(info.kind, "increment")

    def test_zone_listing(self):
        self.assertEqual(self.repo.zones(), [("example.com.", 2024010101)])

    def test_history_lists_all_versions(self):
        versions = self.repo.versions("example.com.")
        self.assertEqual([v.serial for v in versions],
                         [2024010100, 2024010101])
        self.assertEqual([v.kind for v in versions], ["master", "increment"])
        self.assertEqual(versions[0].source_file, "zones/v1.zone")
        self.assertTrue(all(v.record_count > 0 for v in versions))

    def test_old_versions_stay_queryable(self):
        old = self.repo.records("example.com.", serial=2024010100)
        self.assertTrue(any(r.owner == "mail.example.com."
                            and r.rtype == "A" for r in old))
        new = self.repo.records("example.com.", serial=2024010101)
        self.assertFalse(any(r.owner == "mail.example.com."
                             and r.rtype == "A" for r in new))

    def test_unknown_serial_raises(self):
        with self.assertRaises(ZoneError):
            self.repo.records("example.com.", serial=42)

    def test_unknown_zone_raises(self):
        with self.assertRaises(ZoneError):
            self.repo.records("nosuchzone.example.")

    # -- record lineage -------------------------------------------------
    def test_lineage_master_lines(self):
        recs = self.repo.records("example.com.", serial=2024010100)
        www = [r for r in recs if r.owner == "www.example.com."
               and r.rdata == "192.0.2.80"][0]
        self.assertEqual(www.line_no, 15)
        self.assertEqual(www.source_file, "zones/v1.zone")
        soa = [r for r in recs if r.rtype == "SOA"][0]
        self.assertEqual(soa.line_no, 3)

    def test_lineage_carried_and_new_records(self):
        recs = self.repo.records("example.com.", serial=2024010101)
        # carried record keeps the master file line number and source
        ns1 = [r for r in recs if r.owner == "ns1.example.com."][0]
        self.assertEqual(ns1.line_no, 12)
        self.assertEqual(ns1.source_file, "zones/v1.zone")
        # added record points at the increment file
        api = [r for r in recs if r.owner == "api.example.com."][0]
        self.assertEqual(api.line_no, 5)
        self.assertEqual(api.source_file, "incr/v2.inc")
        # replaced record likewise
        www = [r for r in recs if r.owner == "www.example.com."][0]
        self.assertEqual(www.line_no, 7)
        self.assertEqual(www.source_file, "incr/v2.inc")

    # -- queries --------------------------------------------------------
    def test_lookup_current(self):
        recs = self.repo.lookup("example.com.", "www", "A")
        self.assertEqual([r.rdata for r in recs], ["192.0.2.90"])

    def test_lookup_all_types_at_name(self):
        recs = self.repo.lookup("example.com.", "@")
        types = {r.rtype for r in recs}
        self.assertIn("SOA", types)
        self.assertIn("NS", types)

    def test_resolve_a_record(self):
        answer = self.repo.resolve("example.com.", "api", "A")
        self.assertEqual(answer.status, "ok")
        self.assertEqual([r.rdata for r in answer.records], ["192.0.2.50"])

    def test_resolve_follows_cname(self):
        answer = self.repo.resolve("example.com.", "alias", "A")
        self.assertEqual(answer.status, "ok")
        self.assertEqual(answer.chain,
                         [("alias.example.com.", "www.example.com.")])
        self.assertEqual([r.rdata for r in answer.records], ["192.0.2.90"])

    def test_resolve_external_cname(self):
        self.repo.publish_increment(
            "$ZONE example.com.\n$PREREQ 2024010101\n$SERIAL 2024010102\n"
            "$ADD\next CNAME host.other.example.\n")
        answer = self.repo.resolve("example.com.", "ext", "A")
        self.assertEqual(answer.status, "external")

    def test_resolve_nxname(self):
        answer = self.repo.resolve("example.com.", "nope", "A")
        self.assertEqual(answer.status, "nxname")

    # -- diff -------------------------------------------------------------
    def test_diff_between_versions(self):
        diff = self.repo.diff("example.com.", 2024010100, 2024010101)
        added = {(r.owner, r.rtype, r.rdata) for r in diff.added}
        removed = {(r.owner, r.rtype, r.rdata) for r in diff.removed}
        self.assertIn(("api.example.com.", "A", "192.0.2.50"), added)
        self.assertIn(("www.example.com.", "A", "192.0.2.90"), added)
        self.assertIn(("www.example.com.", "A", "192.0.2.80"), removed)
        self.assertIn(("mail.example.com.", "A", "192.0.2.25"), removed)
        self.assertIn(("_text.example.com.", "TXT", '"v=spf1 -all"'),
                      removed)
        # SOA serial bump shows up in the diff
        self.assertTrue(any(r.rtype == "SOA" for r in diff.added))
        self.assertTrue(any(r.rtype == "SOA" for r in diff.removed))
        # formatted output is usable
        text = diff.format()
        self.assertIn("+ api 600 IN A 192.0.2.50", text)
        self.assertIn("- mail 3600 IN A 192.0.2.25", text)

    def test_diff_reverse(self):
        diff = self.repo.diff("example.com.", 2024010101, 2024010100)
        self.assertTrue(any(r.owner == "mail.example.com."
                            for r in diff.added))

    # -- export -----------------------------------------------------------
    def test_export_roundtrip(self):
        text = self.repo.export_text("example.com.")
        self.assertIn("$ORIGIN example.com.", text)
        other = Repository(os.path.join(self.tmp.name, "other.db"))
        try:
            info = other.publish_master("example.com.", text)
            self.assertEqual(info.serial, 2024010101)
            original = {r.key() for r in self.repo.records("example.com.")}
            exported = {r.key() for r in other.records("example.com.")}
            self.assertEqual(original, exported)
        finally:
            other.close()

    def test_export_old_serial(self):
        text = self.repo.export_text("example.com.", serial=2024010100)
        self.assertIn("2024010100 ; serial", text)
        self.assertIn("mail 3600 IN A 192.0.2.25", text)

    def test_export_file(self):
        path = os.path.join(self.tmp.name, "out.zone")
        self.repo.export_file("example.com.", path=path)
        with open(path) as fh:
            self.assertIn("$ORIGIN example.com.", fh.read())


class UnknownPreservedRepoTest(unittest.TestCase):
    def test_unknown_types_roundtrip_through_repo(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            repo = Repository(os.path.join(tmp.name, "u.db"),
                              preserve_unknown=True)
            master = ("@ 300 IN SOA ns1 hostmaster 7 7200 3600 1209600 300\n"
                      "www 300 IN CAA 0 issue \"ca.example\"\n")
            repo.publish_master("example.com.", master)
            rec = [r for r in repo.records("example.com.")
                   if r.rtype == "CAA"][0]
            self.assertFalse(rec.known)
            self.assertEqual(rec.rdata, '0 issue "ca.example"')
            # exported zone file carries the raw text verbatim
            text = repo.export_text("example.com.")
            self.assertIn('www 300 IN CAA 0 issue "ca.example"', text)
            # and diffs see it too
            repo.publish_increment(
                "$ZONE example.com.\n$PREREQ 7\n$SERIAL 8\n"
                "$DELETE\nwww CAA\n")
            diff = repo.diff("example.com.", 7, 8)
            self.assertEqual([r.rtype for r in diff.removed
                              if r.rtype == "CAA"], ["CAA"])
            repo.close()
        finally:
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
