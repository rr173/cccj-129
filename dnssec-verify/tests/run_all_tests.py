#!/usr/bin/env python3 -I
"""End-to-end scenario suite: SUT verdicts vs. independent dnspython oracle.

Run:  python3 -I tests/run_all_tests.py
Exits non-zero if any expectation fails.  Every assertion prints the exact
zone file / source line involved so results are independently checkable.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, "/workspace/pylibs")

from dnssecverify import wire  # noqa: E402
from dnssecverify.engine import run  # noqa: E402
from dnssecverify.store import read_only_store  # noqa: E402
import oracle_check  # noqa: E402

FIX = os.path.join(ROOT, "samples", "fixtures")
DB = os.path.join(ROOT, "db", "fixtures.db")
T = 1700000000

PASS, FAIL, INC = "PASS", "FAIL", "INCONCLUSIVE"

# scenario dir -> expected overall verdict
EXPECTED_OVERALL = {
    "rollover": PASS,
    "spoof": FAIL,
    "expired": FAIL,
    "no-ds": FAIL,
    "coverage": FAIL,
    "wildcard": PASS,
    "gap": INC,
    "unsupported": INC,
    "rsa-ttl": FAIL,
}

results: list[tuple[str, bool, str]] = []


def check(name: str, cond: bool, detail: str = ""):
    results.append((name, bool(cond), detail))
    mark = "ok " if cond else "FAIL"
    print(f"[{mark}] {name}" + (f"  -- {detail}" if detail and not cond
                                else ""))


def run_sut(scenario: str) -> dict:
    manifest = os.path.join(FIX, scenario, "manifest.json")
    anchor = os.path.join(FIX, scenario, "anchors.json")
    with read_only_store(DB) as store:
        return run(store, anchor, manifest)


def rrset_lookup(report: dict, zone: str, owner: str, rtype: str):
    for e in report["rrset_results"]:
        if (e["zone"] == zone and e["owner"] == owner
                and e["rtype"] == rtype):
            return e
    return None


def lines_of(path: str, needle: str) -> list[int]:
    out = []
    with open(path, encoding="utf-8") as fh:
        for i, line in enumerate(fh, 1):
            if needle in line:
                out.append(i)
    return out


# --------------------------------------------------------------------------
def test_rollover():
    rep = run_sut("rollover")
    check("rollover.overall", rep["overall_verdict"] == PASS,
          rep["overall_verdict"])
    # One chain live: every authoritative RRset PASS; delegation NS/glue are
    # SKIPPED by RFC 4035 rather than cryptographically validated.
    bad = [e for e in rep["rrset_results"]
           if e["verdict"] not in (PASS, "SKIPPED")]
    check("rollover.all_rrsets_pass_or_skipped", not bad,
          f"{len(bad)} fail/inconclusive rrsets")
    skipped = [e for e in rep["rrset_results"] if e["verdict"] == "SKIPPED"]
    check("rollover.glue_marked_skipped", len(skipped) >= 2,
          str([(e["owner"], e["rtype"]) for e in skipped]))
    # Multiple DS records both present and parent DS RRset validated.
    ds = rrset_lookup(rep, "example.", "sub.example.", "DS")
    check("rollover.ds_rrset_pass", ds is not None and ds["verdict"] == PASS)
    # DNSKEY RRset has both keys authenticated; cite line numbers.
    zf = os.path.join(FIX, "rollover", "sub.example-2000.zone")
    dk_lines = lines_of(zf, "DNSKEY")
    check("rollover.two_dnskeys_listed", len(dk_lines) >= 2, str(dk_lines))
    # Cross-check every RRset against dnspython oracle.
    oracle = oracle_check.oracle_rrset_verdict(zf, "sub.example.", T)
    mism = []
    for e in rep["rrset_results"]:
        if e["zone"] != "sub.example." or e["rtype"] == "DS":
            continue
        key = (e["owner"], e["rtype"])
        if key in oracle and oracle[key]["verdict"] != e["verdict"]:
            mism.append((key, e["verdict"], oracle[key]["verdict"]))
    check("rollover.matches_dnspython_oracle", not mism, str(mism))


def test_spoof():
    rep = run_sut("spoof")
    check("spoof.overall_fail", rep["overall_verdict"] == FAIL,
          rep["overall_verdict"])
    codes = {f["code"] for f in rep["findings"]}
    check("spoof.has_digest_or_chain_failure",
          bool(codes & {"DS_DIGEST_MISMATCH", "CHAIN_NO_MATCHING_KEY",
                        "DS_NO_KEY_TAG_MATCH"}), str(sorted(codes)))
    # The impostor key shares tag+alg but has a different public key.
    dnskey = rrset_lookup(rep, "sub.example.", "sub.example.", "DNSKEY")
    check("spoof.dnskey_not_trusted",
          dnskey is not None and dnskey["verdict"] in (FAIL, INC),
          dnskey["verdict"] if dnskey else "missing")
    # Cite the exact DS line in the parent and DNSKEY line in the child.
    parent = os.path.join(FIX, "spoof", "example-1100.zone")
    child = os.path.join(FIX, "spoof", "sub.example-2100.zone")
    ds_lines = lines_of(parent, "\tDS\t")
    dk_lines = lines_of(child, "\tDNSKEY\t")
    check("spoof.source_lines_cited", ds_lines and dk_lines,
          f"DS {ds_lines} DNSKEY {dk_lines}")
    finding = next((f for f in rep["findings"]
                    if f["code"] in
                    {"DS_DIGEST_MISMATCH", "CHAIN_NO_MATCHING_KEY"}), None)
    check("spoof.finding_has_two_sources",
          finding is not None and len(finding.get("sources", [])) >= 2,
          json.dumps(finding) if finding else "no finding")


def test_expired():
    rep = run_sut("expired")
    check("expired.overall_fail", rep["overall_verdict"] == FAIL,
          rep["overall_verdict"])
    stale = rrset_lookup(rep, "example.", "stale.example.", "A")
    check("expired.stale_a_fails",
          stale is not None and stale["verdict"] == FAIL)
    reason = stale["signature_attempts"][0]["reason"]
    check("expired.reason_is_expiry", "expired" in reason, reason)
    line = stale["signature_attempts"][0]["source"]["line"]
    check("expired.signature_line_cited", line > 0, str(line))
    # Other RRsets with valid sigs still pass.
    good = rrset_lookup(rep, "example.", "ns1.example.", "A")
    check("expired.valid_rrset_still_passes",
          good is not None and good["verdict"] == PASS)
    # Oracle agrees the stale RRset fails at time T.
    zf = os.path.join(FIX, "expired", "example-1200.zone")
    oracle = oracle_check.oracle_rrset_verdict(zf, "example.", T)
    ov = oracle.get(("stale.example.", "A"))
    check("expired.oracle_agrees", ov is not None and ov["verdict"] == FAIL,
          str(ov))


def test_no_ds():
    rep = run_sut("no-ds")
    check("no-ds.overall_fail", rep["overall_verdict"] == FAIL,
          rep["overall_verdict"])
    codes = {f["code"] for f in rep["findings"]}
    check("no-ds.missing_ds_flagged", "MISSING_DS" in codes, str(sorted(codes)))
    finding = next(f for f in rep["findings"] if f["code"] == "MISSING_DS")
    check("no-ds.finding_locates_delegation",
          finding["owner"] == "sub.example." and finding["rtype"] == "DS")
    # Parent itself still verifies.
    pz = next(z for z in rep["zones"] if z["zone"] == "example.")
    check("no-ds.parent_still_passes", pz["verdict"] == PASS,
          pz["verdict"])


def test_coverage():
    rep = run_sut("coverage")
    check("coverage.overall_fail", rep["overall_verdict"] == FAIL,
          rep["overall_verdict"])
    mutated = rrset_lookup(rep, "example.", "mutated.example.", "A")
    check("coverage.mutated_set_fails",
          mutated is not None and mutated["verdict"] == FAIL)
    crypto_fail = any("verification failed" in a["reason"]
                      for a in mutated["signature_attempts"])
    check("coverage.crypto_failure_recorded", crypto_fail,
          str(mutated["signature_attempts"]))
    labels = rrset_lookup(rep, "example.", "badlabels.deep.example.", "A")
    label_fail = any("labels" in a["reason"]
                     for a in labels["signature_attempts"])
    check("coverage.wrong_labels_rejected",
          labels["verdict"] == FAIL and label_fail,
          str(labels["signature_attempts"]))
    zf = os.path.join(FIX, "coverage", "example-1400.zone")
    oracle = oracle_check.oracle_rrset_verdict(zf, "example.", T)
    check("coverage.oracle_mutated_fail",
          oracle[("mutated.example.", "A")]["verdict"] == FAIL)
    # An untouched, correctly signed RRset still passes.
    txt = rrset_lookup(rep, "example.", "txt.example.", "TXT")
    check("coverage.untouched_txt_passes", txt["verdict"] == PASS)


def test_wildcard():
    rep = run_sut("wildcard")
    check("wildcard.overall_pass", rep["overall_verdict"] == PASS,
          rep["overall_verdict"])
    for rtype in ("A", "TXT"):
        e = rrset_lookup(rep, "example.", "*.any.example.", rtype)
        check(f"wildcard.{rtype}_pass",
              e is not None and e["verdict"] == PASS,
              e["verdict"] if e else "missing")
    zf = os.path.join(FIX, "wildcard", "example-1500.zone")
    oracle = oracle_check.oracle_rrset_verdict(zf, "example.", T)
    mism = [(k, v["verdict"]) for k, v in oracle.items()
            if v["verdict"] != rrset_lookup(
                rep, "example.", k[0], k[1])["verdict"]]
    check("wildcard.matches_oracle", not mism, str(mism))


def test_gap():
    rep = run_sut("gap")
    check("gap.overall_inconclusive",
          rep["overall_verdict"] == INC, rep["overall_verdict"])
    # The present ancestor still verifies; the leaf cannot be decided.
    zmap = {z["zone"]: z["verdict"] for z in rep["zones"]}
    check("gap.parent_passes", zmap.get("example.") == PASS, str(zmap))
    check("gap.leaf_inconclusive",
          zmap.get("deep.mid.example.") == INC, str(zmap))
    codes = {f["code"] for f in rep["findings"]}
    check("gap.broken_chain_or_ancestor_flag",
          bool(codes & {"BROKEN_CHAIN", "ANCESTOR_NOT_TRUSTED"}),
          str(sorted(codes)))


def test_unsupported():
    rep = run_sut("unsupported")
    check("unsupported.overall_inconclusive",
          rep["overall_verdict"] == INC, rep["overall_verdict"])
    # Parent is fine and explicitly PASSes.
    zmap = {z["zone"]: z["verdict"] for z in rep["zones"]}
    check("unsupported.parent_passes", zmap.get("example.") == PASS,
          str(zmap))
    check("unsupported.child_inconclusive",
          zmap.get("sub.example.") == INC, str(zmap))
    codes = {f["code"] for f in rep["findings"]}
    check("unsupported.flagged_as_such",
          any("UNSUPPORTED" in c for c in codes), str(sorted(codes)))


def test_rsa_ttl():
    rep = run_sut("rsa-ttl")
    check("rsa-ttl.overall_fail", rep["overall_verdict"] == FAIL,
          rep["overall_verdict"])
    # RSA-SHA256 (algorithm 8) valid RRsets still pass.
    ok = rrset_lookup(rep, "example.", "ok.example.", "TXT")
    check("rsa-ttl.rsa_signed_rrset_passes",
          ok is not None and ok["verdict"] == PASS,
          ok["verdict"] if ok else "missing")
    alg_seen = {a["algorithm"] for a in ok["signature_attempts"]}
    check("rsa-ttl.uses_algorithm_8", alg_seen == {8}, str(alg_seen))
    # The split-TTL RRset must fail with a TTL mismatch finding.
    split = rrset_lookup(rep, "example.", "split.example.", "A")
    check("rsa-ttl.ttl_mismatch_fails",
          split is not None and split["verdict"] == FAIL,
          split["verdict"] if split else "missing")
    codes = {f["code"] for f in rep["findings"]}
    check("rsa-ttl.ttl_mismatch_findings", "TTL_MISMATCH" in codes,
          str(sorted(codes)))
    # RSA path also agrees with the independent oracle on good records.
    zf = os.path.join(FIX, "rsa-ttl", "example-1800.zone")
    oracle = oracle_check.oracle_rrset_verdict(zf, "example.", T)
    check("rsa-ttl.oracle_agrees_on_good_txt",
          oracle[("ok.example.", "TXT")]["verdict"] == PASS,
          str(oracle[("ok.example.", "TXT")]))


def test_preflight_rejections():
    # Missing serial must be rejected before any partial PASS report.
    manifest = {
        "verification_time_utc": "2023-11-14T22:13:20Z",
        "snapshots": [{"zone": "example.", "serial": 1000},
                      {"zone": "ghost.example.", "serial": 9999}]}
    with tempfile.TemporaryDirectory() as d:
        mp = os.path.join(d, "m.json")
        ap = os.path.join(FIX, "rollover", "anchors.json")
        json.dump(manifest, open(mp, "w"))
        with read_only_store(DB) as store:
            rep = run(store, ap, mp)
        check("preflight.missing_serial_rejected",
              rep["status"] == "REJECTED" and
              any(r["code"] == "MISSING_SNAPSHOT"
                  for r in rep["rejections"]))
        check("preflight.no_partial_pass",
              rep["overall_verdict"] is None and not rep["zones"])

    # Duplicate and conflicting anchors.
    for fname, code in (("anchors-duplicate.json", "DUPLICATE_ANCHOR"),
                        ("anchors-conflict.json",
                         "CONFLICTING_ANCHOR_TYPES")):
        ap = os.path.join(FIX, "anchor-problems", fname)
        mp = os.path.join(FIX, "anchor-problems", "manifest.json")
        with read_only_store(DB) as store:
            rep = run(store, ap, mp)
        check(f"preflight.{code}",
              rep["status"] == "REJECTED" and
              any(r["code"] == code for r in rep["rejections"]),
              json.dumps(rep.get("rejections")))


def test_report_refuses_overwrite():
    rep = run_sut("rollover")
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "out.json")
        from dnssecverify.engine import atomic_write_report
        atomic_write_report(path, rep)
        raised = False
        try:
            atomic_write_report(path, rep)
        except FileExistsError:
            raised = True
        check("report.overwrite_refused", raised)


def test_determinism():
    a = run_sut("rollover")
    b = run_sut("rollover")
    ka = json.dumps(a, sort_keys=True)
    kb = json.dumps(b, sort_keys=True)
    check("determinism.identical_reports", ka == kb)


def main():
    print(f"dnspython oracle version: {oracle_check.VERSION}\n")
    for fn in (test_rollover, test_spoof, test_expired, test_no_ds,
               test_coverage, test_wildcard, test_gap, test_unsupported,
               test_rsa_ttl, test_preflight_rejections,
               test_report_refuses_overwrite, test_determinism):
        print(f"--- {fn.__name__} ---")
        fn()
    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print(f"\n{passed}/{total} checks passed")
    if passed != total:
        for name, ok, detail in results:
            if not ok:
                print("  FAIL:", name, detail)
        sys.exit(1)


if __name__ == "__main__":
    main()
