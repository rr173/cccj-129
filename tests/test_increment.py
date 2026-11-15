"""Increment files: parsing, prerequisite/serial checks, add/replace/
delete semantics, SOA serial maintenance."""

import os
import tempfile
import unittest

from dnsrepo.errors import (CNAMEConflictError, CNAMELoopError, DeltaError,
                            ParseError, PrereqError, SerialError,
                            ValidationError)
from dnsrepo.increment import apply_increment, parse_increment
from dnsrepo.repo import Repository
from dnsrepo.records import serial_gt, soa_fields

from .helpers import INCREMENT_V2, MASTER_V1


def make_repo():
    tmp = tempfile.TemporaryDirectory()
    repo = Repository(os.path.join(tmp.name, "test.db"))
    repo.publish_master("example.com.", MASTER_V1, source_file="v1.zone")
    return tmp, repo


def increment(body):
    return ("$ZONE example.com.\n$PREREQ 2024010100\n$SERIAL 2024010101\n"
            + body)


class SerialArithmeticTest(unittest.TestCase):
    def test_plain_greater(self):
        self.assertTrue(serial_gt(2, 1))
        self.assertFalse(serial_gt(1, 2))
        self.assertFalse(serial_gt(1, 1))

    def test_wraparound(self):
        self.assertTrue(serial_gt(0, 4294967295))
        self.assertTrue(serial_gt(100, 4294967200))
        self.assertFalse(serial_gt(4294967295, 0))

    def test_half_space_is_not_greater(self):
        self.assertFalse(serial_gt(2147483648, 0))
        self.assertFalse(serial_gt(0, 2147483648))


class IncrementParseTest(unittest.TestCase):
    def test_basic_structure(self):
        inc = parse_increment(INCREMENT_V2)
        self.assertEqual(inc.zone, "example.com.")
        self.assertEqual(inc.prereq, 2024010100)
        self.assertEqual(inc.serial, 2024010101)
        self.assertEqual(len(inc.adds), 1)
        self.assertEqual(len(inc.replaces), 1)
        self.assertEqual(len(inc.deletes), 2)
        self.assertEqual(inc.adds[0].line_no, 5)
        self.assertEqual(inc.replaces[0].line_no, 7)

    def test_missing_zone(self):
        with self.assertRaises(ParseError):
            parse_increment("$PREREQ 1\n$SERIAL 2\n$ADD\na A 1.1.1.1\n")

    def test_missing_prereq(self):
        with self.assertRaises(ParseError):
            parse_increment("$ZONE example.com.\n$SERIAL 2\n$END\n")

    def test_missing_serial(self):
        with self.assertRaises(ParseError):
            parse_increment("$ZONE example.com.\n$PREREQ 1\n$END\n")

    def test_record_outside_section(self):
        with self.assertRaises(ParseError):
            parse_increment("$ZONE example.com.\n$PREREQ 1\n$SERIAL 2\n"
                            "a A 1.1.1.1\n")

    def test_zone_must_come_first(self):
        with self.assertRaises(ParseError):
            parse_increment("$ADD\n$ZONE example.com.\n")

    def test_delete_with_ttl_rejected(self):
        with self.assertRaises(ParseError):
            parse_increment(increment("$DELETE\nold 300 A\n"))

    def test_delete_forms(self):
        inc = parse_increment(increment(
            "$DELETE\n"
            "junk\n"
            "old A\n"
            'gone TXT "bye"\n'))
        all_at_name, rrset, specific = inc.deletes
        self.assertIsNone(all_at_name.rtype)
        self.assertEqual(rrset.rtype, "A")
        self.assertIsNone(rrset.rdata)
        self.assertEqual(specific.rdata, '"bye"')

    def test_delete_owner_is_expanded(self):
        inc = parse_increment(increment("$DELETE\nold A\n"))
        self.assertEqual(inc.deletes[0].owner, "old.example.com.")

    def test_relative_names_in_delta(self):
        inc = parse_increment(increment("$ADD\nalias CNAME www\n"))
        self.assertEqual(inc.adds[0].rdata, "www.example.com.")

    def test_duplicate_record_in_delta_rejected(self):
        with self.assertRaises(ParseError):
            parse_increment(increment(
                "$ADD\na A 192.0.2.1\n$REPLACE\na A 192.0.2.1\n"))


class IncrementApplyTest(unittest.TestCase):
    """End-to-end through the repository (baseline needed)."""

    def setUp(self):
        self.tmp, self.repo = make_repo()

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def publish(self, body, **kw):
        return self.repo.publish_increment(increment(body), **kw)

    def test_prereq_mismatch_rejected(self):
        text = ("$ZONE example.com.\n$PREREQ 1999010100\n"
                "$SERIAL 2024010101\n$END\n")
        with self.assertRaises(PrereqError):
            self.repo.publish_increment(text)
        # nothing published
        self.assertEqual(self.repo.current("example.com.").serial, 2024010100)

    def test_no_baseline_rejected(self):
        text = ("$ZONE unknown.example.\n$PREREQ 1\n$SERIAL 2\n$END\n")
        with self.assertRaises(PrereqError):
            self.repo.publish_increment(text)

    def test_serial_must_increase(self):
        text = ("$ZONE example.com.\n$PREREQ 2024010100\n"
                "$SERIAL 2024010100\n$END\n")
        with self.assertRaises(SerialError):
            self.repo.publish_increment(text)

    def test_add_replace_delete(self):
        info = self.repo.publish_increment(INCREMENT_V2,
                                           source_file="v2.inc")
        self.assertEqual(info.serial, 2024010101)
        self.assertEqual(info.kind, "increment")
        recs = self.repo.records("example.com.")
        by_key = {(r.owner, r.rtype, r.rdata) for r in recs}
        # added
        self.assertIn(("api.example.com.", "A", "192.0.2.50"), by_key)
        # replaced: old www addresses gone, new one present
        self.assertNotIn(("www.example.com.", "A", "192.0.2.80"), by_key)
        self.assertNotIn(("www.example.com.", "A", "192.0.2.81"), by_key)
        self.assertIn(("www.example.com.", "A", "192.0.2.90"), by_key)
        # deleted: mail A and the whole _text name
        self.assertNotIn(("mail.example.com.", "A", "192.0.2.25"), by_key)
        self.assertFalse(any(r.owner == "_text.example.com." for r in recs))
        # untouched records survive
        self.assertIn(("ns1.example.com.", "A", "192.0.2.1"), by_key)

    def test_soa_serial_auto_bumped(self):
        self.repo.publish_increment(INCREMENT_V2)
        soa = [r for r in self.repo.records("example.com.")
               if r.rtype == "SOA"][0]
        fields = soa_fields(soa.rdata)
        self.assertEqual(fields[2], 2024010101)   # serial bumped
        self.assertEqual(fields[3], 7200)         # other fields kept
        self.assertIsNone(soa.line_no)            # synthesized

    def test_explicit_soa_replace_matching_serial(self):
        self.publish("$REPLACE\n@ IN SOA ns1 hostmaster "
                     "2024010101 14400 3600 1209600 300\n")
        soa = [r for r in self.repo.records("example.com.")
               if r.rtype == "SOA"][0]
        self.assertEqual(soa_fields(soa.rdata)[3], 14400)

    def test_explicit_soa_replace_wrong_serial(self):
        with self.assertRaises(SerialError):
            self.publish("$REPLACE\n@ IN SOA ns1 hostmaster "
                         "2024010999 7200 3600 1209600 300\n")

    def test_deleting_soa_is_rejected(self):
        with self.assertRaises(ValidationError):
            self.publish("$DELETE\n@ SOA\n")

    def test_delete_nonexistent_record(self):
        with self.assertRaises(DeltaError):
            self.publish("$DELETE\nnosuchname A\n")

    def test_delete_specific_record(self):
        self.publish('$DELETE\nwww A 192.0.2.80\n')
        recs = self.repo.records("example.com.")
        datas = {r.rdata for r in recs if r.owner == "www.example.com."
                 and r.rtype == "A"}
        self.assertEqual(datas, {"192.0.2.81"})

    def test_add_existing_record_rejected(self):
        with self.assertRaises(DeltaError):
            self.publish("$ADD\nns1 A 192.0.2.1\n")

    def test_add_and_replace_same_rrset_rejected(self):
        with self.assertRaises(DeltaError):
            self.publish("$ADD\nwww A 192.0.2.99\n"
                         "$REPLACE\nwww A 192.0.2.100\n")

    def test_delete_and_replace_same_rrset_rejected(self):
        with self.assertRaises(DeltaError):
            self.publish("$DELETE\nwww A\n$REPLACE\nwww A 192.0.2.100\n")

    def test_delta_creating_cname_conflict_rejected(self):
        with self.assertRaises(CNAMEConflictError):
            self.publish("$ADD\nalias TXT \"oops\"\n")

    def test_delta_creating_cname_loop_rejected(self):
        with self.assertRaises(CNAMELoopError):
            self.publish("$ADD\nloop1 CNAME loop2\nloop2 CNAME loop1\n")

    def test_delta_ttl_inheritance(self):
        # no $TTL in increment: TTL falls back to baseline SOA minimum
        self.publish("$ADD\nbare A 192.0.2.77\n")
        rec = [r for r in self.repo.records("example.com.")
               if r.owner == "bare.example.com."][0]
        self.assertEqual(rec.ttl, 300)
        # explicit $TTL in the increment wins
        text = ("$ZONE example.com.\n$PREREQ 2024010101\n"
                "$SERIAL 2024010102\n$TTL 42\n$ADD\nb2 A 192.0.2.78\n")
        self.repo.publish_increment(text)
        rec = [r for r in self.repo.records("example.com.")
               if r.owner == "b2.example.com."][0]
        self.assertEqual(rec.ttl, 42)

    def test_chained_increments(self):
        self.repo.publish_increment(INCREMENT_V2)
        text = ("$ZONE example.com.\n$PREREQ 2024010101\n"
                "$SERIAL 2024010102\n$ADD\napi2 A 192.0.2.51\n")
        self.repo.publish_increment(text)
        self.assertEqual(self.repo.current("example.com.").serial,
                         2024010102)
        # stale prereq after the chain moved on
        with self.assertRaises(PrereqError):
            self.repo.publish_increment(INCREMENT_V2)


class ApplyIncrementUnitTest(unittest.TestCase):
    """apply_increment as a pure function over record lists."""

    def test_pure_application(self):
        from dnsrepo.zonefile import parse_master
        base = parse_master(MASTER_V1, "example.com.").records
        inc = parse_increment(INCREMENT_V2)
        new = apply_increment(base, inc, "example.com.")
        self.assertTrue(any(r.owner == "api.example.com." for r in new))
        self.assertFalse(any(r.owner == "mail.example.com."
                             and r.rtype == "A" for r in new))


if __name__ == "__main__":
    unittest.main()
