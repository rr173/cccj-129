"""Offline CT observation import: hand-checkable cases, an independent
reference cross-check and a generated 200k-observation run."""

import json
import os
import random
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from dnsrepo.ct import (FINDINGS_FILE, NOTES_FILE, SUMMARY_FILE,
                        import_ct_observations, normalize_name)
from dnsrepo.errors import BatchError
from dnsrepo.repo import Repository

from . import ct_reference
from .helpers import INCREMENT_V2, MASTER_V1

CERT_A = "a" * 64
CERT_B = "b" * 64
CERT_C = "c" * 64
CERT_D = "d" * 64


def observation(source="ct-a", observed_at_ms=1000, certificate_sha256=CERT_A,
                dns_names=None):
    return {
        "source": source,
        "observed_at_ms": observed_at_ms,
        "certificate_sha256": certificate_sha256,
        "dns_names": ["new.example.com."] if dns_names is None else dns_names,
    }


class CtCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.output = os.path.join(self.dir, "out")
        self.db = os.path.join(self.dir, "repo.db")
        with Repository(self.db) as repo:
            repo.publish_master("example.com.", MASTER_V1)

    def tearDown(self):
        self.tmp.cleanup()

    def publish_increment(self):
        with Repository(self.db) as repo:
            repo.publish_increment(INCREMENT_V2)

    def write(self, rows, name="observations.jsonl"):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(row if isinstance(row, str) else json.dumps(row))
                fh.write("\n")
        return path

    def run_import(self, rows, serial=2024010100):
        path = self.write(rows)
        return import_ct_observations(path, self.output, self.db,
                                      "example.com.", serial)

    def findings_of(self, rows, serial=2024010100):
        self.run_import(rows, serial=serial)
        return self.findings()

    def findings(self):
        with open(os.path.join(self.output, FINDINGS_FILE),
                  encoding="utf-8") as fh:
            return [json.loads(line) for line in fh]

    def summary(self):
        with open(os.path.join(self.output, SUMMARY_FILE),
                  encoding="utf-8") as fh:
            return json.load(fh)


class NormalizationTest(unittest.TestCase):
    def check(self, raw, expected):
        self.assertEqual(normalize_name(raw, "f.jsonl", 7), expected)

    def test_case_root_dot_and_idna_are_normalized(self):
        for raw in ["WWW.Example.COM.", "www.example.com", "www.EXAMPLE.com"]:
            self.check(raw, "www.example.com.")
        self.check("BÜCHER.example.com.", "xn--bcher-kva.example.com.")
        self.check("bücher.example.com", "xn--bcher-kva.example.com.")
        self.check("xn--bcher-kva.example.com", "xn--bcher-kva.example.com.")
        self.check("XN--BCHER-KVA.example.com.",
                   "xn--bcher-kva.example.com.")
        self.check("*.Example.com.", "*.example.com.")
        self.check("Bücher.Example.COM", "xn--bcher-kva.example.com.")

    def test_invalid_names_rejected_with_location(self):
        bad = ["", ".", "a..example.com", "*.", "a.*.example.com",
               "www.*.example.com", "*.*.example.com", "bad name.example.com",
               "foo_bar!.example.com", "xn--invalid-.example.com",
               "xn--.example.com", "a" * 64 + ".example.com",
               ("a." * 128) + "example.com", "a_bücher.example.com"]
        for raw in bad:
            with self.subTest(raw=raw):
                with self.assertRaises(BatchError) as caught:
                    normalize_name(raw, "f.jsonl", 3)
                self.assertEqual(caught.exception.source, "f.jsonl")
                self.assertEqual(caught.exception.line, 3)

    def test_reference_rejects_the_same_bad_names(self):
        # The independent reference agrees on validity, not just on output.
        for raw in ["a..example.com", "x.*.example.com", "*.*.example.com",
                    "bad name", "xn--", "a" * 64 + ".example.com",
                    "a_bücher.example.com"]:
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    ct_reference.normalize(raw)


class HandComputedTest(CtCase):
    def test_cross_source_certificate_and_in_certificate_duplicates(self):
        # One certificate seen by two sources and twice inside one source;
        # one line repeats a name inside its own dns_names array.  Still
        # one certificate, one evidence row per (source, cert) and one
        # overall first/last span.
        rows = [
            observation("ct-a", 1000, CERT_A,
                        ["new.example.com", "NEW.example.com."]),
            observation("ct-b", 2000, CERT_A, ["new.example.com."]),
            observation("ct-a", 5000, CERT_A, ["new.example.com."]),
        ]
        result = self.run_import(rows)
        found = self.findings()
        self.assertEqual(len(found), 1)
        entry = found[0]
        self.assertEqual(entry["name"], "new.example.com.")
        self.assertFalse(entry["wildcard"])
        self.assertEqual(entry["first_observed_at_ms"], 1000)
        self.assertEqual(entry["last_observed_at_ms"], 5000)
        self.assertEqual(entry["certificate_count"], 1)
        self.assertEqual(entry["certificates"], [CERT_A])
        self.assertEqual(entry["sources"], ["ct-a", "ct-b"])
        self.assertEqual(
            [(e["source"], e["certificate_sha256"],
              e["first_observed_at_ms"], e["last_observed_at_ms"],
              e["observations"]) for e in entry["evidence"]],
            [("ct-a", CERT_A, 1000, 5000, 2),
             ("ct-b", CERT_A, 2000, 2000, 1)])
        self.assertEqual(result.observations, 3)
        self.assertEqual(result.duplicates, 0)
        # One name occurrence per observation, not one per array entry:
        # line 1 repeats the same name twice but contributes one.
        self.assertEqual(self.summary()["findings"]["observations"], 3)

    def test_identical_duplicate_lines_are_folded(self):
        rows = [observation("ct-a", 1000, CERT_A, ["new.example.com"]),
                observation("ct-a", 1000, CERT_A, ["new.example.com"]),
                # Same key, same set, different order/spelling/case.
                observation("ct-a", 1000, CERT_A.upper(),
                            ["NEW.EXAMPLE.COM."]),
                observation("ct-a", 1000, CERT_A, ["new.example.com"])]
        result = self.run_import(rows)
        self.assertEqual(result.observations, 1)
        self.assertEqual(result.duplicates, 3)
        entry = self.findings()[0]
        self.assertEqual(entry["first_observed_at_ms"], 1000)
        self.assertEqual(entry["last_observed_at_ms"], 1000)
        self.assertEqual([e["observations"] for e in entry["evidence"]], [1])
        self.assertEqual(self.summary()["input"]["duplicate_observations"], 3)
        self.assertEqual(self.summary()["sources"]["ct-a"],
                         {"observations": 1, "duplicate_observations": 3,
                          "certificates": 1, "findings": 1,
                          "first_observed_at_ms": 1000,
                          "last_observed_at_ms": 1000})

    def test_internationalized_equivalents_merge(self):
        rows = [
            observation("ct-a", 1000, CERT_A,
                        ["bücher.example.com.", "BÜCHER.example.com"]),
            observation("ct-b", 2000, CERT_B,
                        ["xn--bcher-kva.example.com"]),
        ]
        found = self.findings_of(rows)
        self.assertEqual([entry["name"] for entry in found],
                         ["xn--bcher-kva.example.com."])
        self.assertEqual(found[0]["certificates"], [CERT_A, CERT_B])
        self.assertEqual(found[0]["sources"], ["ct-a", "ct-b"])
        self.assertEqual(found[0]["first_observed_at_ms"], 1000)
        self.assertEqual(found[0]["last_observed_at_ms"], 2000)

    def test_root_dot_and_case_do_not_split_findings(self):
        rows = [observation("ct-a", 1000, CERT_A,
                            ["Deep.New.Place.Example.Com"]),
                observation("ct-b", 2000, CERT_B,
                            ["deep.new.place.example.com."])]
        found = self.findings_of(rows)
        self.assertEqual([entry["name"] for entry in found],
                         ["deep.new.place.example.com."])
        self.assertEqual(found[0]["first_observed_at_ms"], 1000)
        self.assertEqual(found[0]["last_observed_at_ms"], 2000)

    def test_zone_label_boundary(self):
        rows = [observation(
            dns_names=["example.net.evil", "notexample.com",
                       "example.com.evil.", "evil.example.com.",
                       "example.com.", "a.example.com."])]
        found = self.findings_of(rows)
        # Only the apex-boundary lookalikes are on the right side of the
        # dot: example.net.evil, notexample.com and example.com.evil are
        # outside.  evil.example.com. and a.example.com. are genuine new
        # names; the apex itself is suppressed.
        self.assertEqual([entry["name"] for entry in found],
                         ["a.example.com.", "evil.example.com."])
        excluded = self.summary()["excluded"]
        self.assertEqual(excluded["zone_apex"], 1)
        self.assertEqual(excluded["out_of_zone"], 3)
        self.assertEqual(excluded["existing"], 0)

    def test_existing_names_and_cname_are_not_findings(self):
        # www, ns1, mail and _text exist as direct owners; alias is a CNAME
        # owner too.  The CNAME target "www" is not evidence by itself.
        rows = [observation(dns_names=["www.example.com", "mail.example.com.",
                                       "alias.example.com", "_text.example.com",
                                       "ns1.example.com."])]
        result = self.run_import(rows)
        self.assertEqual(self.findings(), [])
        self.assertEqual(result.excluded["existing"], 5)
        self.assertEqual(self.summary()["findings"]["names"], 0)

    def test_historical_serial_is_pinned(self):
        self.publish_increment()
        rows = [observation(dns_names=["api.example.com", "mail.example.com",
                                       "www.example.com"])]
        self.run_import(rows, serial=2024010100)
        old = {entry["name"] for entry in self.findings()}
        self.output = os.path.join(self.dir, "out2")
        self.run_import(rows, serial=2024010101)
        new = {entry["name"] for entry in self.findings()}
        # api was added in 2024010101; mail was deleted there.  The older
        # version still knows mail (suppressed) and does not know api.
        self.assertEqual(old, {"api.example.com."})
        self.assertEqual(new, {"mail.example.com."})
        self.assertEqual(self.summary()["zone"],
                         {"zone": "example.com.", "serial": 2024010101,
                          "records": self.summary()["zone"]["records"],
                          "existing_names":
                          self.summary()["zone"]["existing_names"]})

    def test_wildcard_is_kept_and_not_expanded(self):
        rows = [observation("ct-a", 1000, CERT_A, ["*.example.com"]),
                observation("ct-b", 2000, CERT_B,
                            ["www.example.com", "*.deep.example.com."])]
        found = self.findings_of(rows)
        # Both wildcards are clues in their own right; www exists and is
        # suppressed, and no concrete name is invented for either wildcard.
        self.assertEqual([(entry["name"], entry["wildcard"])
                          for entry in found],
                         [("*.deep.example.com.", True),
                          ("*.example.com.", True)])
        self.assertEqual(found[0]["certificates"], [CERT_B])
        self.assertEqual(found[0]["evidence"][0]["source"], "ct-b")
        self.assertEqual(found[1]["certificates"], [CERT_A])
        self.assertEqual(self.summary()["findings"]["wildcard"], 2)
        self.assertEqual(self.summary()["findings"]["plain"], 0)

    def test_same_name_plain_and_wildcard_stay_separate(self):
        rows = [observation("ct-a", 1000, CERT_A,
                            ["deep.example.com", "*.deep.example.com"])]
        found = self.findings_of(rows)
        self.assertEqual([(entry["name"], entry["wildcard"])
                          for entry in found],
                         [("*.deep.example.com.", True),
                          ("deep.example.com.", False)])
        self.assertEqual(found[0]["first_observed_at_ms"], 1000)
        self.assertEqual(found[1]["first_observed_at_ms"], 1000)

    def test_empty_input_yields_empty_findings(self):
        path = self.write([])
        result = import_ct_observations(path, self.output, self.db,
                                        "example.com.", 2024010100)
        self.assertEqual(self.findings(), [])
        summary = self.summary()
        self.assertEqual(summary["findings"], {
            "names": 0, "wildcard": 0, "plain": 0, "observations": 0,
            "certificates": 0})
        self.assertEqual(summary["input"]["observations"], 0)
        self.assertEqual(summary["input"]["lines"], 0)
        self.assertEqual(summary["observed_at_ms"], {"min": None, "max": None})
        self.assertEqual(summary["sources"], {})
        self.assertEqual(result.findings, 0)
        self.assertEqual(sorted(os.listdir(self.output)),
                         [FINDINGS_FILE, NOTES_FILE, SUMMARY_FILE])

    def test_empty_dns_names_array_is_a_name_less_observation(self):
        # An observation with no names is valid but contributes no name
        # occurrences, so it neither creates findings nor breaks the
        # observation accounting.
        rows = [observation(dns_names=[]),
                observation("ct-b", 2000, CERT_B, ["new.example.com"])]
        result = self.run_import(rows)
        self.assertEqual(result.observations, 2)
        self.assertEqual([entry["name"] for entry in self.findings()],
                         ["new.example.com."])
        summary = self.summary()
        self.assertEqual(summary["findings"]["observations"], 1)
        self.assertEqual(summary["sources"]["ct-a"]["observations"], 1)
        self.assertEqual(summary["sources"]["ct-a"]["findings"], 0)

    def test_blank_lines_and_bom_are_ignored(self):
        path = os.path.join(self.dir, "bom.jsonl")
        with open(path, "wb") as fh:
            fh.write(b"\xef\xbb\xbf"
                     + json.dumps(observation()).encode("utf-8") + b"\n\n")
        import_ct_observations(path, self.output, self.db, "example.com.",
                               2024010100)
        self.assertEqual([entry["name"] for entry in self.findings()],
                         ["new.example.com."])
        self.assertEqual(self.summary()["input"]["lines"], 1)

    def test_multiple_input_files_are_merged(self):
        first = self.write([observation("ct-a", 1000, CERT_A,
                                        ["one.example.com"])], "one.jsonl")
        second = self.write([observation("ct-b", 2000, CERT_A,
                                         ["one.example.com"])], "two.jsonl")
        result = import_ct_observations([first, second], self.output,
                                        self.db, "example.com.", 2024010100)
        self.assertEqual(result.observations, 2)
        entry = self.findings()[0]
        self.assertEqual(entry["sources"], ["ct-a", "ct-b"])
        self.assertEqual(entry["first_observed_at_ms"], 1000)
        self.assertEqual(entry["last_observed_at_ms"], 2000)
        self.assertEqual(self.summary()["input"]["files"], [first, second])


class ValidationTest(CtCase):
    def assert_rejected(self, rows, fragment, line=None):
        with self.assertRaises(BatchError) as caught:
            self.run_import(rows)
        self.assertIn(fragment, str(caught.exception))
        if line is not None:
            self.assertEqual(caught.exception.line, line)
        self.assertFalse(os.path.exists(self.output))
        self.assertEqual([n for n in os.listdir(self.dir)
                          if n.startswith(".dnsrepo-ct-")], [])

    def test_missing_fields_report_file_and_line(self):
        for field in ("source", "observed_at_ms", "certificate_sha256",
                      "dns_names"):
            with self.subTest(field=field):
                bad = observation()
                del bad[field]
                self.assert_rejected(
                    [observation(), bad],
                    "observations.jsonl:2: missing field %r" % field, line=2)

    def test_wrong_types_report_line(self):
        cases = {
            "source": [None, "", 7],
            "observed_at_ms": [1.5, "2", True, None, 2 ** 63],
            "certificate_sha256": [7, None, "a" * 63, "g" * 64, "a" * 65],
            "dns_names": ["new.example.com", 5, None],
        }
        for field, values in cases.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    bad = observation()
                    bad[field] = value
                    self.assert_rejected([observation(), bad],
                                         "observations.jsonl:2", line=2)

    def test_invalid_name_reported_with_line(self):
        for name in ["a..example.com", "x.*.example.com", "*.*.example.com",
                     "bad name", "xn--", "-" * 64 + ".example.com"]:
            with self.subTest(name=name):
                self.assert_rejected(
                    [observation(), observation(dns_names=[name])],
                    "observations.jsonl:2", line=2)

    def test_non_object_json_reports_line(self):
        self.assert_rejected([observation(), "[1, 2]"],
                             "expected a JSON object", line=2)
        self.assert_rejected([observation(), "{not json"],
                             "invalid JSON", line=2)

    def test_conflicting_duplicate_key_rejects_batch(self):
        rows = [observation("ct-a", 1000, CERT_A, ["one.example.com"]),
                observation("ct-a", 1000, CERT_A, ["two.example.com"])]
        with self.assertRaises(BatchError) as caught:
            self.run_import(rows)
        message = str(caught.exception)
        self.assertIn("conflicting duplicate observation key", message)
        self.assertIn("observations.jsonl:1", message)
        self.assertEqual(os.path.basename(caught.exception.source),
                         "observations.jsonl")
        self.assertEqual(caught.exception.line, 2)
        self.assertFalse(os.path.exists(self.output))

    def test_conflicting_duplicate_across_input_files(self):
        first = self.write([observation("ct-a", 1000, CERT_A,
                                        ["one.example.com"])], "one.jsonl")
        second = self.write([observation("ct-a", 1000, CERT_A,
                                         ["two.example.com"])], "two.jsonl")
        with self.assertRaises(BatchError) as caught:
            import_ct_observations([first, second], self.output, self.db,
                                   "example.com.", 2024010100)
        self.assertIn("%s:1" % first, str(caught.exception))
        self.assertEqual(caught.exception.source, second)
        self.assertEqual(caught.exception.line, 1)
        self.assertFalse(os.path.exists(self.output))

    def test_unknown_zone_and_serial_reject_batch(self):
        with self.assertRaises(BatchError) as caught:
            self.run_import([observation()], serial=42)
        self.assertIn("no published version with serial 42",
                      str(caught.exception))
        with self.assertRaises(BatchError):
            import_ct_observations(self.write([observation()]), self.output,
                                   self.db, "nope.example.", 2024010100)
        self.assertFalse(os.path.exists(self.output))

    def test_missing_repository_rejected(self):
        with self.assertRaises(BatchError) as caught:
            import_ct_observations(self.write([observation()]), self.output,
                                   os.path.join(self.dir, "missing.db"),
                                   "example.com.", 2024010100)
        self.assertIn("does not exist", str(caught.exception))
        self.assertFalse(os.path.exists(self.output))

    def test_existing_output_refused(self):
        os.mkdir(self.output)
        with self.assertRaises(BatchError) as caught:
            self.run_import([observation()])
        self.assertIn("already exists", str(caught.exception))
        self.assertEqual(os.listdir(self.output), [])

    def test_failure_mid_batch_leaves_no_output(self):
        with mock.patch("dnsrepo.ct._load_input",
                        side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                self.run_import([observation()])
        self.assertFalse(os.path.exists(self.output))
        self.assertEqual([n for n in os.listdir(self.dir)
                          if n.startswith(".dnsrepo-ct-")], [])

    def test_repository_not_modified_by_any_run(self):
        with open(self.db, "rb") as fh:
            before = fh.read()
        self.run_import([observation(dns_names=["new.example.com"])])
        with open(self.db, "rb") as fh:
            self.assertEqual(fh.read(), before)
        self.assertEqual([n for n in os.listdir(self.dir)
                          if n.startswith("repo.db")], ["repo.db"])


class DeterminismTest(CtCase):
    ROWS = [
        observation("ct-b", 3000, CERT_B,
                    ["b.example.com", "a.example.com"]),
        observation("ct-a", 1000, CERT_A, ["c.example.com"]),
        observation("ct-a", 2000, CERT_A, ["a.example.com"]),
        observation("ct-b", 4000, CERT_C, ["*.d.example.com"]),
        observation("ct-a", 1000, CERT_A, ["c.example.com"]),
    ]

    def snapshot(self, rows, name):
        self.output = os.path.join(self.dir, name)
        self.run_import(rows)
        with open(os.path.join(self.output, FINDINGS_FILE),
                  encoding="utf-8") as fh:
            findings = fh.read()
        with open(os.path.join(self.output, SUMMARY_FILE),
                  encoding="utf-8") as fh:
            summary = json.load(fh)
        return findings, summary

    def test_reordering_and_duplicates_do_not_change_output(self):
        base_findings, base_summary = self.snapshot(self.ROWS, "base")
        shuffled = list(self.ROWS)
        random.Random(3).shuffle(shuffled)
        shuffled.extend(self.ROWS[1:3])   # more exact duplicate lines
        other_findings, other_summary = self.snapshot(shuffled, "other")
        self.assertEqual(base_findings, other_findings)
        for key in ("findings", "certificates", "excluded", "zone"):
            self.assertEqual(base_summary[key], other_summary[key])
        self.assertEqual(base_summary["observed_at_ms"],
                         other_summary["observed_at_ms"])
        # Only the duplicate-line counters differ, as they must.
        self.assertLessEqual(base_summary["input"]["observations"],
                             other_summary["input"]["observations"])

    def test_idempotent_output_is_byte_identical(self):
        first = self.snapshot(self.ROWS, "one")
        second = self.snapshot(self.ROWS, "two")
        self.assertEqual(first, second)


class CliTest(CtCase):
    def test_ct_import_command(self):
        from dnsrepo.cli import main
        path = self.write([observation(dns_names=["new.example.com"])])
        code = main(["--db", self.db, "ct-import", path, self.output,
                     "--repo", self.db, "--zone", "example.com.",
                     "--serial", "2024010100"])
        self.assertEqual(code, 0)
        self.assertEqual([entry["name"] for entry in self.findings()],
                         ["new.example.com."])
        # A second run must refuse the existing directory.
        self.assertEqual(main(["--db", self.db, "ct-import", path,
                               self.output, "--repo", self.db,
                               "--zone", "example.com.",
                               "--serial", "2024010100"]), 1)

    def test_ct_import_requires_repo_zone_and_serial(self):
        from dnsrepo.cli import build_parser
        parser = build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["ct-import", "a.jsonl", "out"])


class ReferenceCrossCheckTest(unittest.TestCase):
    """Compare the disk-indexed batch with an independent dict model."""

    ZONE_TEXT = """\
$ORIGIN example.com.
$TTL 3600
@   IN  SOA ns1.example.com. hostmaster.example.com. (
        2024010100 7200 3600 1209600 300 )
    IN  NS  ns1.example.com.
www     A       192.0.2.80
mail    A       192.0.2.25
alias   CNAME   www
_text   TXT     "v=spf1 -all"
"""

    def test_random_small_batches_match_reference(self):
        rng = random.Random(20240101)
        for case in range(30):
            with self.subTest(case=case):
                self._one_case(rng)

    def _one_case(self, rng):
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "repo.db")
            with Repository(db) as repo:
                repo.publish_master("example.com.", self.ZONE_TEXT)
                existing = {rec.owner for rec in
                            repo.records("example.com.", 2024010100)}

            pools = ["www.example.com", "alias.example.com",
                     "new.example.com", "bücher.example.com",
                     "xn--bcher-kva.example.com.", "*.example.com",
                     "*.deep.example.com", "example.com",
                     "example.net.evil", "a.b.example.com",
                     "DEEP.Example.COM.", "example.com.evil"]
            certs = [CERT_A, CERT_B, CERT_C, CERT_D]
            sources = ["ct-a", "ct-b", "ct-c"]
            rows = []
            used = set()
            for _ in range(rng.randint(1, 8)):
                source = rng.choice(sources)
                cert = rng.choice(certs)
                when = rng.choice([1000, 2000, 3000])
                while (source, cert, when) in used:
                    when += 1
                used.add((source, cert, when))
                rows.append({
                    "source": source,
                    "observed_at_ms": when,
                    "certificate_sha256": cert,
                    "dns_names": [rng.choice(pools)
                                  for _ in range(rng.randint(1, 3))],
                })
            # Duplicate some lines verbatim; the reference folds them too.
            for row in list(rows):
                if rng.random() < 0.35:
                    rows.append(json.loads(json.dumps(row)))
            rng.shuffle(rows)

            expected, stats = ct_reference.import_reference(
                rows, "example.com.", existing)

            path = os.path.join(tmp, "obs.jsonl")
            with open(path, "w", encoding="utf-8") as fh:
                for row in rows:
                    fh.write(json.dumps(row) + "\n")
            output = os.path.join(tmp, "out")
            result = import_ct_observations(path, output, db,
                                            "example.com.", 2024010100)
            with open(os.path.join(output, FINDINGS_FILE),
                      encoding="utf-8") as fh:
                actual = [json.loads(line) for line in fh]
            with open(os.path.join(output, SUMMARY_FILE),
                      encoding="utf-8") as fh:
                summary = json.load(fh)

            self.assertEqual(actual, expected)
            self.assertEqual(result.observations, stats["observations"])
            self.assertEqual(result.duplicates, stats["duplicates"])
            self.assertEqual(summary["excluded"], stats["excluded"])
            self.assertEqual(sorted(summary["sources"]), stats["sources"])
            for entry in actual:
                self.assertEqual(entry["certificate_count"],
                                 len(entry["certificates"]))
                for field in ("certificates", "sources"):
                    self.assertEqual(entry[field], sorted(entry[field]))
                self.assertEqual(
                    entry["evidence"],
                    sorted(entry["evidence"],
                           key=lambda e: (e["source"],
                                          e["certificate_sha256"])))


class LargeGeneratedTest(unittest.TestCase):
    """200k observations with repeated certificates and names."""

    def test_generated_large_batch(self):
        rng = random.Random(99)
        existing = {"example.com.", "ns1.example.com.", "ns2.example.com.",
                    "mail.example.com.", "www.example.com.",
                    "alias.example.com.", "_text.example.com."}
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "repo.db")
            with Repository(db) as repo:
                repo.publish_master("example.com.", MASTER_V1)
            path = os.path.join(tmp, "obs.jsonl")

            # Generate and independently tally in one pass.  Every 40th
            # line is a verbatim copy of the line 25 rows earlier, so the
            # input carries real duplicate keys with identical names.
            recent = {}
            keys = {}
            duplicates = 0
            times = []
            certs = set()
            expected = {}
            line_count = 0
            with open(path, "w", encoding="utf-8") as fh:
                for index in range(200000):
                    if index % 40 == 25 and (index - 25) in recent:
                        row = recent[index - 25]
                    else:
                        source = "ct-%s" % "abcd"[index % 4]
                        cert = ("%016x" % rng.randrange(5000)) * 4
                        when = rng.randrange(1_000_000)
                        if index % 5 == 0:
                            name = "host%d.example.com" % rng.randrange(50)
                            names = [name, name.upper() + "."]
                        else:
                            names = ["h%d.example.com" % rng.randrange(20000)
                                     for _ in range(rng.randint(1, 3))]
                        while (source, cert, when) in keys:
                            # Keep accidental key reuse out of play: only
                            # the deliberate copies below may repeat keys.
                            when = rng.randrange(1_000_000)
                        row = {"source": source, "observed_at_ms": when,
                               "certificate_sha256": cert, "dns_names": names}
                        recent[index] = row
                        recent.pop(index - 60, None)
                    line_count += 1
                    fh.write(json.dumps(row) + "\n")
                    normalized = sorted({ct_reference.normalize(n)
                                         for n in row["dns_names"]})
                    key = (row["source"], row["certificate_sha256"],
                           row["observed_at_ms"])
                    if key in keys:
                        self.assertEqual(keys[key], normalized)
                        duplicates += 1
                        continue
                    keys[key] = normalized
                    when = row["observed_at_ms"]
                    times.append(when)
                    certs.add(row["certificate_sha256"])
                    for name in normalized:
                        if name == "example.com." or name in existing:
                            continue
                        bucket = expected.setdefault(
                            name, [when, when, set(), set(), {}])
                        bucket[0] = min(bucket[0], when)
                        bucket[1] = max(bucket[1], when)
                        bucket[2].add(row["certificate_sha256"])
                        bucket[3].add(row["source"])
                        evidence = bucket[4].setdefault(
                            (row["source"], row["certificate_sha256"]),
                            [when, when, 0])
                        evidence[0] = min(evidence[0], when)
                        evidence[1] = max(evidence[1], when)
                        evidence[2] += 1

            # The batch runs in a fresh interpreter so its peak RSS can be
            # measured.  ru_maxrss survives fork/exec of the test process and
            # would report the parent's high-water mark, so read VmHWM from
            # /proc/self/status instead: it belongs to the new address space.
            script = (
                "import sys\n"
                "from dnsrepo.ct import import_ct_observations\n"
                "result = import_ct_observations(sys.argv[1], sys.argv[2],"
                " sys.argv[3], 'example.com.', 2024010100)\n"
                "for line in open('/proc/self/status'):\n"
                "    if line.startswith('VmHWM:'):\n"
                "        print('PEAK', line.split()[1])\n")
            output = os.path.join(tmp, "out")
            completed = subprocess.run(
                [sys.executable, "-c", script, path, output, db],
                capture_output=True, text=True, cwd=os.path.dirname(
                    os.path.dirname(os.path.abspath(__file__))),
                env=dict(os.environ, PYTHONPATH=os.path.dirname(
                    os.path.dirname(os.path.abspath(__file__)))))
            self.assertEqual(completed.returncode, 0, completed.stderr)
            peak_kb = int(completed.stdout.split()[-1])
            with open(os.path.join(output, SUMMARY_FILE),
                      encoding="utf-8") as fh:
                summary = json.load(fh)

            self.assertEqual(summary["input"]["lines"], line_count)
            self.assertEqual(summary["input"]["observations"], len(keys))
            self.assertEqual(summary["input"]["duplicate_observations"],
                             duplicates)
            self.assertGreater(duplicates, 0)
            self.assertEqual(summary["certificates"]["observed"], len(certs))
            self.assertEqual(summary["findings"]["names"], len(expected))
            self.assertEqual(summary["observed_at_ms"],
                             {"min": min(times), "max": max(times)})

            rows = 0
            previous = None
            with open(os.path.join(output, FINDINGS_FILE),
                      encoding="utf-8") as fh:
                for line in fh:
                    entry = json.loads(line)
                    rows += 1
                    name = entry["name"]
                    if previous is not None:
                        self.assertLess(previous, name)
                    previous = name
                    bucket = expected[name]
                    self.assertEqual(entry["first_observed_at_ms"], bucket[0])
                    self.assertEqual(entry["last_observed_at_ms"], bucket[1])
                    self.assertEqual(entry["certificate_count"],
                                     len(bucket[2]))
                    self.assertEqual(entry["certificates"],
                                     sorted(bucket[2]))
                    self.assertEqual(entry["sources"], sorted(bucket[3]))
                    self.assertEqual(
                        [(e["source"], e["certificate_sha256"],
                          e["first_observed_at_ms"],
                          e["last_observed_at_ms"], e["observations"])
                         for e in entry["evidence"]],
                        [(source, cert, ev[0], ev[1], ev[2])
                         for (source, cert), ev in
                         sorted(bucket[4].items())])
            self.assertEqual(rows, len(expected))
            # Streaming with a 16 MB SQLite cache must stay far below the
            # size of the 37 MB input itself (observed: ~35 MB).
            self.assertLess(peak_kb, 128 * 1024, peak_kb)


if __name__ == "__main__":
    unittest.main()
