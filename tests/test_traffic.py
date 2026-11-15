"""Offline flow attribution batch: hand-checkable cases first, then an
independent brute-force cross-check and a generated large run."""

import json
import os
import random
import tempfile
import unittest
from unittest import mock

from dnsrepo.errors import BatchError
from dnsrepo.repo import Repository
from dnsrepo.traffic import DETAIL_FILE, SUMMARY_FILE, allocate, attribute_flows

from . import bruteforce
from .helpers import INCREMENT_V2, MASTER_V1

WIDE = {"cidr": "10.0.0.0/8", "owner": "A",
        "valid_from_ms": 0, "valid_to_ms": 100}
NARROW = {"cidr": "10.0.0.0/16", "owner": "B",
          "valid_from_ms": 20, "valid_to_ms": 40}
NARROWER = {"cidr": "10.0.0.0/24", "owner": "C",
            "valid_from_ms": 30, "valid_to_ms": 35}


def flow(flow_id="f1", dst_ip="10.0.0.1", start_ms=10, end_ms=110, bytes=17):
    return {"flow_id": flow_id, "dst_ip": dst_ip, "start_ms": start_ms,
            "end_ms": end_ms, "bytes": bytes}


class BatchCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.output = os.path.join(self.dir, "out")

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, rows):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            for row in rows:
                if isinstance(row, str):
                    fh.write(row + "\n")
                else:
                    fh.write(json.dumps(row) + "\n")
        return path

    def run_batch(self, flows, owners, **kwargs):
        flows_path = self.write("flows.jsonl", flows)
        owners_path = self.write("owners.jsonl", owners)
        return attribute_flows(flows_path, owners_path, self.output, **kwargs)

    def details(self, result=None):
        path = os.path.join(self.output, DETAIL_FILE)
        with open(path, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh]

    def summary(self):
        with open(os.path.join(self.output, SUMMARY_FILE),
                  encoding="utf-8") as fh:
            return json.load(fh)


class HandComputedTest(BatchCase):
    def test_wide_narrow_and_narrower_six_fragments(self):
        result = self.run_batch([flow()], [WIDE, NARROW, NARROWER])
        rows = self.details(result)
        self.assertEqual(
            [(r["start_ms"], r["end_ms"], r["status"], r["owners"],
              r["bytes"]) for r in rows],
            [(10, 20, "assigned", ["A"], 2),
             (20, 30, "assigned", ["B"], 2),
             (30, 35, "assigned", ["C"], 1),
             (35, 40, "assigned", ["B"], 1),
             (40, 100, "assigned", ["A"], 10),
             (100, 110, "unassigned", [], 1)])
        self.assertEqual(sum(r["bytes"] for r in rows), 17)
        # fragments tile the connection exactly
        for before, after in zip(rows, rows[1:]):
            self.assertEqual(before["end_ms"], after["start_ms"])

    def test_mid_connection_fallback_to_wide_prefix(self):
        # The narrow prefix expires while the wide one is still valid.
        result = self.run_batch([flow(bytes=30)], [WIDE, NARROW])
        rows = self.details(result)
        self.assertEqual([(r["start_ms"], r["end_ms"], r["owners"])
                          for r in rows],
                         [(10, 20, ["A"]), (20, 40, ["B"]),
                          (40, 100, ["A"]), (100, 110, [])])
        # 900/100 = 9, 600/100 = 6, 1800/100 = 18, 300/100 = 3 exactly
        self.assertEqual([r["bytes"] for r in rows], [3, 6, 18, 3])

    def test_time_endpoints_are_half_open(self):
        # Validity [20, 40): active exactly at 20, gone exactly at 40.
        result = self.run_batch([flow(start_ms=20, end_ms=40, bytes=9)],
                                [NARROW])
        rows = self.details(result)
        self.assertEqual([(r["start_ms"], r["end_ms"], r["status"])
                          for r in rows], [(20, 40, "assigned")])

    def test_connection_ending_at_validity_start_is_unassigned(self):
        result = self.run_batch([flow(start_ms=0, end_ms=20, bytes=4)],
                                [NARROW])
        rows = self.details(result)
        self.assertEqual([(r["start_ms"], r["end_ms"], r["status"])
                          for r in rows], [(0, 20, "unassigned")])

    def test_same_prefix_multiple_owners_is_ambiguous(self):
        other = {"cidr": "10.0.0.0/8", "owner": "Z",
                 "valid_from_ms": 40, "valid_to_ms": 60}
        result = self.run_batch([flow(bytes=100)], [WIDE, other])
        rows = self.details(result)
        self.assertEqual(
            [(r["start_ms"], r["end_ms"], r["status"], r["owners"])
             for r in rows],
            [(10, 40, "assigned", ["A"]),
             (40, 60, "ambiguous", ["A", "Z"]),
             (60, 100, "assigned", ["A"]),
             (100, 110, "unassigned", [])])
        # ambiguous bytes are reported but assigned to no candidate
        owner_total = self.summary()["owner_bytes"]
        self.assertEqual(owner_total, {"A": 70})
        self.assertEqual(self.summary()["status_bytes"]["ambiguous"], 20)

    def test_ambiguity_does_not_fall_back_to_wider_prefix(self):
        # Z wins on the narrower prefix alone but ties with A at /8?  No:
        # /24 is narrower, so it wins outright; the /8 tie is irrelevant.
        deep = {"cidr": "10.0.0.0/24", "owner": "C",
                "valid_from_ms": 20, "valid_to_ms": 30}
        result = self.run_batch([flow(bytes=10)], [WIDE, NARROW, deep])
        rows = self.details(result)
        self.assertEqual([(r["start_ms"], r["end_ms"], r["owners"])
                          for r in rows],
                         [(10, 20, ["A"]), (20, 30, ["C"]),
                          (30, 40, ["B"]), (40, 100, ["A"]),
                          (100, 110, [])])

    def test_duplicate_rows_of_one_owner_do_not_make_ambiguity(self):
        duplicate = dict(NARROW)   # same owner, same span
        repeated = {"cidr": "10.0.0.0/8", "owner": "A",
                    "valid_from_ms": 50, "valid_to_ms": 60}
        result = self.run_batch([flow(bytes=17)],
                                [WIDE, duplicate, NARROW, repeated])
        rows = self.details(result)
        self.assertEqual([(r["start_ms"], r["end_ms"], r["status"],
                           r["owners"], r["bytes"]) for r in rows],
                         [(10, 20, "assigned", ["A"], 2),
                          (20, 40, "assigned", ["B"], 3),
                          (40, 100, "assigned", ["A"], 10),
                          (100, 110, "unassigned", [], 2)])

    def test_irrelevant_boundaries_are_merged_and_remainder_unchanged(self):
        # D's /8 copy and the wider /4 both end inside the connection but
        # are hidden by B; they must not cut a fragment.
        hidden = {"cidr": "0.0.0.0/0", "owner": "A",
                  "valid_from_ms": 0, "valid_to_ms": 25}
        noisy = {"cidr": "10.0.0.0/8", "owner": "B",
                 "valid_from_ms": 20, "valid_to_ms": 40}
        plain = self.run_batch([flow(bytes=17)], [WIDE, NARROW])
        self.output = os.path.join(self.dir, "noisy")
        noisy_result = self.run_batch([flow(bytes=17)], [WIDE, NARROW,
                                                         hidden, noisy])
        self.assertEqual([(r["start_ms"], r["end_ms"], r["bytes"])
                          for r in self.details(noisy_result)],
                         [(10, 20, 2), (20, 40, 3), (40, 100, 10),
                          (100, 110, 2)])
        self.assertEqual(self.summary()["owner_bytes"],
                         {"A": 12, "B": 3})
        self.assertEqual(plain.fragments, noisy_result.fragments)

    def test_utf8_bom_and_blank_lines_are_tolerated(self):
        path = os.path.join(self.dir, "bom.jsonl")
        with open(path, "wb") as fh:
            fh.write(b"\xef\xbb\xbf" + json.dumps(flow()).encode("utf-8"))
            fh.write(b"\n\n")
        owners = self.write("owners.jsonl", [WIDE])
        result = attribute_flows(path, owners, self.output)
        self.assertEqual(result.flows, 1)
        self.assertEqual([(r["start_ms"], r["owners"])
                          for r in self.details(result)],
                         [(10, ["A"]), (100, [])])

    def test_zero_byte_fragments_are_kept(self):
        result = self.run_batch([flow(bytes=0)], [WIDE, NARROW, NARROWER])
        rows = self.details(result)
        self.assertEqual(len(rows), 6)
        self.assertEqual([r["bytes"] for r in rows], [0, 0, 0, 0, 0, 0])

    def test_bytes_all_go_to_the_longest_fragment_on_ties(self):
        # Two equal-length fragments: the earlier start wins the remainder.
        a = {"cidr": "10.0.0.0/8", "owner": "A",
             "valid_from_ms": 0, "valid_to_ms": 10}
        b = {"cidr": "10.0.0.0/8", "owner": "B",
             "valid_from_ms": 10, "valid_to_ms": 20}
        result = self.run_batch(
            [{"flow_id": "f", "dst_ip": "10.0.0.1", "start_ms": 0,
              "end_ms": 20, "bytes": 1}], [a, b])
        self.assertEqual([r["bytes"] for r in self.details(result)], [1, 0])

    def test_empty_flow_file_gives_empty_details(self):
        result = self.run_batch([], [WIDE])
        self.assertEqual(self.details(result), [])
        summary = self.summary()
        self.assertEqual(summary["flows"], 0)
        self.assertEqual(summary["bytes"], 0)
        self.assertEqual(summary["status_bytes"],
                         {"assigned": 0, "ambiguous": 0, "unassigned": 0})

    def test_summary_counts_statuses_and_owners(self):
        flows = [flow("f1", start_ms=10, end_ms=110, bytes=17),
                 flow("f2", "10.0.0.2", 0, 10, bytes=5),
                 flow("f3", "192.0.2.9", 0, 10, bytes=3)]
        result = self.run_batch(flows, [WIDE, NARROW, NARROWER])
        summary = self.summary()
        self.assertEqual(self.details(result)[0]["flow_id"], "f1")
        self.assertEqual(summary["status_bytes"],
                         {"assigned": 21, "ambiguous": 0, "unassigned": 4})
        self.assertEqual(summary["owner_bytes"],
                         {"A": 17, "B": 3, "C": 1})
        self.assertEqual(summary["bytes"], 25)


class AddressFamilyTest(BatchCase):
    def test_ipv6_high_bits_and_slash_zero(self):
        owners = [
            {"cidr": "::/0", "owner": "v6root",
             "valid_from_ms": 0, "valid_to_ms": 1000},
            {"cidr": "2001:db8::/32", "owner": "doc",
             "valid_from_ms": 0, "valid_to_ms": 1000},
            {"cidr": "2001:db8:1::/64", "owner": "doc-sub",
             "valid_from_ms": 0, "valid_to_ms": 500},
        ]
        flows = [flow("v6", "2001:db8:1::1", 0, 100, bytes=10),
                 flow("v4", "203.0.113.1", 0, 100, bytes=5)]
        result = self.run_batch(flows, owners)
        rows = self.details(result)
        v6 = [r for r in rows if r["flow_id"] == "v6"]
        v4 = [r for r in rows if r["flow_id"] == "v4"]
        # The /64 outlives the connection, so the /32 never wins here.
        self.assertEqual([(r["end_ms"], r["owners"]) for r in v6],
                         [(100, ["doc-sub"])])
        # ::/0 is IPv6 only: it must not claim the IPv4 connection
        self.assertEqual([(r["status"], r["owners"]) for r in v4],
                         [("unassigned", [])])

    def test_ipv4_mapped_ipv6_is_not_ipv4(self):
        owners = [{"cidr": "192.0.2.0/24", "owner": "v4",
                   "valid_from_ms": 0, "valid_to_ms": 100}]
        result = self.run_batch([flow("mapped", "::ffff:192.0.2.1",
                                     0, 10, bytes=4)], owners)
        rows = self.details(result)
        self.assertEqual([(r["status"], r["owners"]) for r in rows],
                         [("unassigned", [])])
        # ... and an IPv6 range covers it instead
        owners.append({"cidr": "::ffff:192.0.2.0/120", "owner": "v6",
                       "valid_from_ms": 0, "valid_to_ms": 100})
        self.output = os.path.join(self.dir, "mapped2")
        result = self.run_batch([flow("mapped", "::ffff:192.0.2.1",
                                     0, 10, bytes=4)], owners)
        self.assertEqual([(r["status"], r["owners"])
                          for r in self.details(result)],
                         [("assigned", ["v6"])])

    def test_non_nibble_aligned_prefixes(self):
        # /25, /30 and /36 keys must not collide with the other half of
        # the enclosing nibble.
        owners = [
            {"cidr": "10.0.0.0/25", "owner": "low",
             "valid_from_ms": 0, "valid_to_ms": 100},
            {"cidr": "10.0.0.128/25", "owner": "high",
             "valid_from_ms": 0, "valid_to_ms": 100},
            {"cidr": "2001:db8::/36", "owner": "v6low",
             "valid_from_ms": 0, "valid_to_ms": 100},
            {"cidr": "2001:db8:f000::/36", "owner": "v6high",
             "valid_from_ms": 0, "valid_to_ms": 100},
        ]
        flows = [flow("low", "10.0.0.5", 0, 10, 1),
                 flow("high", "10.0.0.200", 0, 10, 1),
                 flow("v6low", "2001:db8::1", 0, 10, 1),
                 flow("v6high", "2001:db8:ffff::1", 0, 10, 1)]
        result = self.run_batch(flows, owners)
        self.assertEqual([(r["flow_id"], r["owners"])
                          for r in self.details(result)],
                         [("low", ["low"]), ("high", ["high"]),
                          ("v6low", ["v6low"]), ("v6high", ["v6high"])])

    def test_ipv4_zero_prefix(self):
        owners = [{"cidr": "0.0.0.0/0", "owner": "all",
                   "valid_from_ms": 0, "valid_to_ms": 100}]
        result = self.run_batch([flow("any", "198.51.100.7", 0, 10, 3)],
                                owners)
        self.assertEqual([(r["owners"], r["bytes"])
                          for r in self.details(result)],
                         [(["all"], 3)])


class ValidationTest(BatchCase):
    def assert_rejected(self, flows, owners, fragment, line=None):
        with self.assertRaises(BatchError) as caught:
            self.run_batch(flows, owners)
        self.assertIn(fragment, str(caught.exception))
        if line is not None:
            self.assertEqual(caught.exception.line, line)
        # a rejected batch leaves no deliverable directory behind
        self.assertFalse(os.path.exists(self.output))
        self.assertEqual([n for n in os.listdir(self.dir)
                          if n.startswith(".dnsrepo-traffic-")], [])

    def test_duplicate_flow_id_rejects_whole_batch(self):
        self.assert_rejected([flow("dup"), flow("ok", "10.0.0.2"),
                              flow("dup", "10.0.0.3")], [WIDE],
                             "duplicate flow_id", line=3)

    def test_bad_json_reports_line(self):
        self.assert_rejected([flow(), "{not json"], [WIDE], "invalid JSON",
                             line=2)

    def test_non_integer_times_and_bytes(self):
        for field, value in [("start_ms", 1.5), ("end_ms", "2"),
                             ("bytes", None), ("bytes", True)]:
            bad = flow()
            bad[field] = value
            self.assert_rejected([bad], [WIDE],
                                 "%s must be an integer" % field, line=1)

    def test_bytes_must_not_be_negative(self):
        self.assert_rejected([flow(bytes=-1)], [WIDE], "bytes must be >= 0")

    def test_start_must_precede_end(self):
        self.assert_rejected([flow(start_ms=10, end_ms=10)], [WIDE],
                             "start_ms must be less than end_ms")

    def test_flow_id_must_be_non_empty(self):
        self.assert_rejected([flow("")], [WIDE],
                             "flow_id must be a non-empty string")

    def test_bad_dst_ip(self):
        self.assert_rejected([flow(dst_ip="10.0.0.256")], [WIDE],
                             "dst_ip")

    def test_cidr_with_host_bits_rejected(self):
        self.assert_rejected([flow()],
                             [{"cidr": "10.0.0.1/24", "owner": "A",
                               "valid_from_ms": 0, "valid_to_ms": 10}],
                             "not a canonical network", line=1)

    def test_malformed_cidr_rejected(self):
        for cidr in ["10.0.0.0/33", "2001:db8::/129", "10.0.0.0/24/8",
                     "banana", ""]:
            self.assert_rejected([flow()],
                                 [{"cidr": cidr, "owner": "A",
                                   "valid_from_ms": 0, "valid_to_ms": 10}],
                                 "cidr", line=1)

    def test_ownership_half_open_and_owner_rules(self):
        self.assert_rejected([flow()],
                             [{"cidr": "10.0.0.0/8", "owner": "",
                               "valid_from_ms": 0, "valid_to_ms": 10}],
                             "owner must be a non-empty string")
        self.assert_rejected([flow()],
                             [{"cidr": "10.0.0.0/8", "owner": "A",
                               "valid_from_ms": 10, "valid_to_ms": 10}],
                             "valid_from_ms must be less than valid_to_ms",
                             line=1)

    def test_missing_field_rejected_with_line(self):
        self.assert_rejected(["{}"], [], "missing field", line=1)

    def test_total_bytes_beyond_64_bit_is_rejected(self):
        big = flow(bytes=2 ** 63 - 1)
        self.assert_rejected([big, flow("f2", bytes=2)], [WIDE],
                             "exact 64-bit accounting range", line=2)

    def test_output_directory_created_only_after_success(self):
        result = self.run_batch([flow()], [WIDE])
        self.assertEqual(sorted(os.listdir(self.output)),
                         [DETAIL_FILE, SUMMARY_FILE])
        self.assertEqual(result.output, self.output)

    def test_existing_output_refused(self):
        os.mkdir(self.output)
        with self.assertRaises(BatchError) as caught:
            self.run_batch([flow()], [WIDE])
        self.assertIn("already exists", str(caught.exception))
        self.assertEqual(os.listdir(self.output), [])

    def test_failure_mid_batch_leaves_no_output(self):
        # Force a failure after validation: the delivery must not happen.
        with mock.patch("dnsrepo.traffic._attribute",
                        side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                self.run_batch([flow()], [WIDE])
        self.assertFalse(os.path.exists(self.output))
        self.assertEqual([n for n in os.listdir(self.dir)
                          if n.startswith(".dnsrepo-traffic-")], [])

    def test_unknown_serial_rejects_batch(self):
        db = os.path.join(self.dir, "repo.db")
        with Repository(db) as repo:
            repo.publish_master("example.com.", MASTER_V1)
        with self.assertRaises(BatchError) as caught:
            self.run_batch([flow()], [WIDE], repo_path=db,
                           zone="example.com.", serial=42)
        self.assertIn("no published version with serial 42",
                      str(caught.exception))
        self.assertFalse(os.path.exists(self.output))

    def test_unknown_zone_rejects_batch(self):
        db = os.path.join(self.dir, "repo.db")
        with Repository(db) as repo:
            repo.publish_master("example.com.", MASTER_V1)
        with self.assertRaises(BatchError) as caught:
            self.run_batch([flow()], [WIDE], repo_path=db,
                           zone="nope.example.", serial=2024010100)
        self.assertIn("not found", str(caught.exception))

    def test_partial_label_arguments_rejected(self):
        with self.assertRaises(BatchError):
            self.run_batch([flow()], [WIDE], zone="example.com.")


class DnsLabelTest(BatchCase):
    def build_repo(self):
        db = os.path.join(self.dir, "repo.db")
        repo = Repository(db)
        repo.publish_master("example.com.", MASTER_V1)
        repo.publish_increment(INCREMENT_V2)
        return db, repo

    def test_historical_version_labels_are_pinned(self):
        db, repo = self.build_repo()
        try:
            # 192.0.2.80 is www in both versions; 192.0.2.90 only exists
            # in the second.  192.0.2.25 is mail in the first only; later
            # it is gone, and it was never a CNAME target.
            old = dict(flow("old", "192.0.2.25", 0, 10, 1))
            new = dict(flow("new", "192.0.2.90", 0, 10, 1))
            flows = [old, new]
            result = self.run_batch(flows, [], repo_path=db,
                                    zone="example.com.", serial=2024010100)
            rows = self.details(result)
            self.assertEqual([r["dns_owners"] for r in rows],
                             [["mail.example.com."], []])
            self.assertEqual(self.summary()["dns_version"],
                             {"zone": "example.com.", "serial": 2024010100})
        finally:
            repo.close()

    def test_labels_deduplicated_sorted_and_family_specific(self):
        db, repo = self.build_repo()
        try:
            self.output = os.path.join(self.dir, "second")
            result = self.run_batch(
                [flow("a", "192.0.2.90", 0, 10, 1),
                 flow("b", "192.0.2.25", 0, 10, 1)],
                [], repo_path=db, zone="example.com.", serial=2024010101)
            rows = self.details(result)
            self.assertEqual([r["dns_owners"] for r in rows],
                             [["www.example.com."], []])
        finally:
            repo.close()

    def test_current_head_change_does_not_affect_pinned_version(self):
        db, repo = self.build_repo()
        try:
            # Publish a third version where www no longer has the address.
            repo.publish_master(
                "example.com.",
                MASTER_V1.replace("192.0.2.80", "192.0.2.200")
                         .replace("192.0.2.81", "192.0.2.201")
                         .replace("2024010100", "2024010102"))
            result = self.run_batch([flow("a", "192.0.2.80", 0, 10, 1)],
                                    [], repo_path=db, zone="example.com.",
                                    serial=2024010100)
            self.assertEqual(self.details(result)[0]["dns_owners"],
                             ["www.example.com."])
        finally:
            repo.close()

    def test_batch_never_writes_to_repository(self):
        db, repo = self.build_repo()
        try:
            with open(db, "rb") as fh:
                before = fh.read()
            head = repo.current("example.com.").serial
            self.run_batch([flow("a", "192.0.2.80", 0, 10, 1)], [WIDE],
                           repo_path=db, zone="example.com.",
                           serial=2024010100)
            self.assertEqual(repo.current("example.com.").serial, head)
            with open(db, "rb") as fh:
                self.assertEqual(fh.read(), before)
        finally:
            repo.close()

    def test_labels_ignored_for_other_family(self):
        db, repo = self.build_repo()
        try:
            result = self.run_batch([flow("a", "::ffff:192.0.2.80",
                                          0, 10, 1)],
                                    [], repo_path=db, zone="example.com.",
                                    serial=2024010100)
            self.assertEqual(self.details(result)[0]["dns_owners"], [])
        finally:
            repo.close()


class BruteForceCrossCheckTest(unittest.TestCase):
    """Compare the indexed batch with an independent millisecond scan."""

    def test_random_small_batches_match_enumeration(self):
        rng = random.Random(20241115)
        for case in range(25):
            with self.subTest(case=case):
                self._one_case(rng, case)

    def _one_case(self, rng, seed):
        networks = ["10.0.0.0/8", "10.0.0.0/16", "10.0.0.0/24",
                    "10.0.0.0/25", "10.0.1.0/24"]
        rows = []
        owners = ["A", "B", "C"]
        for _ in range(rng.randint(1, 6)):
            rows.append({
                "cidr": rng.choice(networks),
                "owner": rng.choice(owners),
                "valid_from_ms": rng.randint(0, 20),
                "valid_to_ms": rng.randint(21, 40),
            })
        flows = []
        expected = []
        for index in range(rng.randint(1, 4)):
            item = {
                "flow_id": "f%d" % index,
                "dst_ip": rng.choice(["10.0.0.5", "10.0.0.9", "10.0.1.7"]),
                "start_ms": rng.randint(0, 10),
                "end_ms": rng.randint(11, 40),
                "bytes": rng.randint(0, 60),
            }
            flows.append(item)
            expected.append(bruteforce.attribute(item, rows))
        with tempfile.TemporaryDirectory() as tmp:
            flows_path = os.path.join(tmp, "flows.jsonl")
            owners_path = os.path.join(tmp, "owners.jsonl")
            with open(flows_path, "w", encoding="utf-8") as fh:
                for item in flows:
                    fh.write(json.dumps(item) + "\n")
            with open(owners_path, "w", encoding="utf-8") as fh:
                for row in rows:
                    fh.write(json.dumps(row) + "\n")
            output = os.path.join(tmp, "out")
            attribute_flows(flows_path, owners_path, output)
            with open(os.path.join(output, DETAIL_FILE),
                      encoding="utf-8") as fh:
                actual = [json.loads(line) for line in fh]
        by_flow = {}
        for row in actual:
            by_flow.setdefault(row["flow_id"], []).append(
                (row["start_ms"], row["end_ms"], row["status"],
                 tuple(row["owners"]), row["bytes"]))
        for item, want in zip(flows, expected):
            self.assertEqual(by_flow[item["flow_id"]], want)
            self.assertEqual(sum(amount for *_, amount in want),
                             item["bytes"])


class AllocationTest(unittest.TestCase):
    def test_largest_remainder_rules(self):
        # 10 bytes over lengths 1, 1, 1 -> remainders tie, earliest wins.
        pieces = [(0, 1, "assigned", ("A",)), (5, 6, "assigned", ("A",)),
                  (9, 10, "assigned", ("A",))]
        self.assertEqual(allocate(10, pieces), [4, 3, 3])
        # Uneven lengths: floor 3 each for 100/7, remainder to the two
        # earliest of the three equal remainders.
        pieces = [(0, 3, "assigned", ("A",)), (3, 6, "assigned", ("A",)),
                  (6, 7, "assigned", ("A",))]
        amounts = allocate(100, pieces)
        self.assertEqual(sum(amounts), 100)
        self.assertEqual(amounts, [43, 43, 14])
        self.assertTrue(all(isinstance(a, int) for a in amounts))

    def test_zero_bytes_and_single_fragment(self):
        pieces = [(0, 5, "assigned", ("A",)), (5, 9, "unassigned", ())]
        self.assertEqual(allocate(0, pieces), [0, 0])
        self.assertEqual(allocate(7, [(2, 9, "assigned", ("A",))]), [7])


class LargeGeneratedTest(unittest.TestCase):
    """200k ownership rows and 200k connections through disk indexes."""

    def test_generated_large_batch(self):
        rng = random.Random(7)
        with tempfile.TemporaryDirectory() as tmp:
            owners_path = os.path.join(tmp, "owners.jsonl")
            flows_path = os.path.join(tmp, "flows.jsonl")
            with open(owners_path, "w", encoding="utf-8") as fh:
                for index in range(200000):
                    octet = index % 256
                    third = (index // 256) % 256
                    fh.write(json.dumps({
                        "cidr": "10.%d.%d.0/24" % (octet, third),
                        "owner": "owner-%d" % (index % 500),
                        "valid_from_ms": rng.randint(0, 900),
                        "valid_to_ms": rng.randint(1000, 2000),
                    }) + "\n")
            with open(flows_path, "w", encoding="utf-8") as fh:
                for index in range(200000):
                    octet = index % 256
                    third = (index // 256) % 256
                    start = rng.randint(0, 1000)
                    fh.write(json.dumps({
                        "flow_id": "flow-%d" % index,
                        "dst_ip": "10.%d.%d.%d" % (octet, third,
                                                   index % 254 + 1),
                        "start_ms": start,
                        "end_ms": start + rng.randint(1, 500),
                        "bytes": rng.randint(0, 10 ** 6),
                    }) + "\n")
            output = os.path.join(tmp, "out")
            result = attribute_flows(flows_path, owners_path, output)
            self.assertEqual(result.flows, 200000)
            self.assertEqual(result.ownership_rows, 200000)
            with open(os.path.join(output, SUMMARY_FILE),
                      encoding="utf-8") as fh:
                summary = json.load(fh)
            self.assertEqual(summary["status_bytes"].values()
                             and sum(summary["status_bytes"].values()),
                             summary["bytes"])
            with open(os.path.join(output, DETAIL_FILE),
                      encoding="utf-8") as fh:
                lines = sum(1 for _ in fh)
            self.assertEqual(lines, summary["fragments"])
            self.assertGreater(lines, 200000)


if __name__ == "__main__":
    unittest.main()
