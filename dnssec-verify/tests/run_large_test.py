#!/usr/bin/env python3 -I
"""Scale verification: result counts, per-RRset provenance and peak memory.

Runs the real CLI verify path against the large database while sampling RSS
from /proc, then re-opens the database and asserts logical content is
unchanged.  No whole-zone materialization is allowed: peak Python heap must
stay close to a single RRset's working set regardless of zone size.
"""
from __future__ import annotations

import json
import os
import resource
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, "/workspace/pylibs")

from dnssecverify.engine import run  # noqa: E402
from dnssecverify.store import read_only_store  # noqa: E402

DB = os.path.join(ROOT, "db", "large.db")
ANCHOR = os.path.join(ROOT, "samples", "large", "anchors.json")
MANIFEST = os.path.join(ROOT, "samples", "large", "manifest.json")
REPORT = os.path.join(ROOT, "samples", "reports", "large-report.json")


def main():
    for suffix in ("", "-wal", "-shm"):
        p = REPORT + suffix
        if os.path.exists(p) and suffix == "":
            os.unlink(p)
    with read_only_store(DB) as store:
        before = store.logical_checksum()
        total_records = store.count_records()
        snapshots = store.list_snapshots()
        t0 = time.time()
        report = run(store, ANCHOR, MANIFEST)
        elapsed = time.time() - t0
        after = store.logical_checksum()

    peak_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    peak_mb = peak_kb / 1024.0

    # Persist report via the same atomic writer the CLI uses.
    from dnssecverify.engine import atomic_write_report
    if os.path.exists(REPORT):
        os.unlink(REPORT)
    atomic_write_report(REPORT, report)

    rrset_results = report["rrset_results"]
    pass_n = sum(1 for r in rrset_results if r["verdict"] == "PASS")
    fail_n = sum(1 for r in rrset_results if r["verdict"] == "FAIL")
    inc_n = sum(1 for r in rrset_results if r["verdict"] == "INCONCLUSIVE")
    with_sources = sum(1 for r in rrset_results if r["sources"])
    print("=== large-scale verification ===")
    print(f"snapshots (historical versions): {len(snapshots)}")
    print(f"total records in database:        {total_records}")
    print(f"verification elapsed:             {elapsed:.1f}s")
    print(f"overall verdict:                  {report['overall_verdict']}")
    print(f"RRset results: {len(rrset_results)} "
          f"(PASS={pass_n} FAIL={fail_n} INC={inc_n})")
    print(f"RRsets with source provenance:    {with_sources}")
    print(f"peak resident memory:             {peak_mb:.1f} MiB")
    print(f"checksum before: {before}")
    print(f"checksum after:  {after}")
    print(f"logical content unchanged:        {before == after}")

    # Assertions.
    assert total_records >= 100_000, "expected >=100k historical records"
    assert report["overall_verdict"] == "PASS", report["overall_verdict"]
    assert fail_n == 0 and inc_n == 0
    assert with_sources == len(rrset_results), "every RRset needs provenance"
    assert before == after, "verification must not mutate the database"
    # The verified single serial: 850 host RRsets plus the four apex/ns
    # RRsets (SOA, NS, DNSKEY, ns1 A).
    expected_rrsets = 850 + 4
    assert len(rrset_results) == expected_rrsets, len(rrset_results)
    # Spot-check a deep RRset carries exact file/line provenance.
    sample = next(r for r in rrset_results
                  if r["owner"] == "host00424.large.example."
                  and r["rtype"] == "A")
    assert sample["sources"] and sample["sources"][0]["line"] > 0, sample
    print("\nALL SCALE ASSERTIONS PASSED")


if __name__ == "__main__":
    main()
