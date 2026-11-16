"""Command line interface for the offline DNSSEC verifier."""
from __future__ import annotations

import argparse
import json
import sys

sys.path.insert(0, "/workspace/pylibs")

from .engine import atomic_write_report, run
from .store import IngestStore, StoreError, read_only_store
from .zonefile import ZoneFileError, parse_zone_file


def _cmd_load(args) -> int:
    store = IngestStore(args.database)
    try:
        header, records = parse_zone_file(
            args.snapshot, declared_zone=args.zone,
            declared_serial=args.serial)
        if store.snapshot_exists(header["zone"], header["serial"]):
            print(f"REFUSED: {header['zone']}={header['serial']} already "
                  f"exists; versions are immutable", file=sys.stderr)
            return 2
        count = store.ingest_records(header, records)
        print(json.dumps({"loaded": True, "zone": header["zone"],
                          "serial": header["serial"], "records": count,
                          "source": header["source"]}, indent=2))
        return 0
    finally:
        store.close()


def _cmd_verify(args) -> int:
    with read_only_store(args.database) as store:
        before = store.logical_checksum()
        result = run(store, args.anchor, args.manifest)
        after = store.logical_checksum()
    result["db_checksum_before"] = before
    result["db_checksum_after"] = after
    result["db_unchanged"] = before == after

    # A rejected run (bad anchors, missing serial, broken preflight) must not
    # leave behind anything that looks like a completed verification report.
    if result["status"] == "REJECTED":
        print(json.dumps({
            "status": "REJECTED",
            "overall_verdict": None,
            "report_written": False,
            "rejections": result["rejections"],
            "db_unchanged": result["db_unchanged"],
        }, indent=2))
        return 3

    try:
        atomic_write_report(args.report, result)
    except FileExistsError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({
        "status": result["status"],
        "overall_verdict": result.get("overall_verdict"),
        "report": args.report,
        "db_unchanged": result["db_unchanged"],
    }, indent=2))
    return 0 if result["overall_verdict"] == "PASS" else 1


def _cmd_list(args) -> int:
    with read_only_store(args.database) as store:
        out = {"snapshots": [
            {"zone": z, "serial": s,
             "records": store.count_records(z, s),
             "meta": store.snapshot_meta(z, s)}
            for z, s in store.list_snapshots()]}
    print(json.dumps(out, indent=2))
    return 0


def _cmd_checksum(args) -> int:
    with read_only_store(args.database) as store:
        print(json.dumps(store.logical_checksum(), indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dnssec-verify",
        description="Offline DNSSEC chain-of-trust verification over "
                    "historical signed zone snapshots (read-only).")
    sub = p.add_subparsers(dest="command", required=True)

    ld = sub.add_parser("load", help="ingest one zone snapshot file")
    ld.add_argument("--database", required=True)
    ld.add_argument("--snapshot", required=True)
    ld.add_argument("--zone", help="override zone apex if no $ORIGIN")
    ld.add_argument("--serial", type=int, help="override expected serial")
    ld.set_defaults(func=_cmd_load)

    vf = sub.add_parser("verify", help="verify a manifest against an anchor")
    vf.add_argument("--database", required=True)
    vf.add_argument("--anchor", required=True)
    vf.add_argument("--manifest", required=True)
    vf.add_argument("--report", required=True)
    vf.set_defaults(func=_cmd_verify)

    ls = sub.add_parser("list", help="list stored snapshots")
    ls.add_argument("--database", required=True)
    ls.set_defaults(func=_cmd_list)

    cs = sub.add_parser("checksum", help="print logical DB content checksum")
    cs.add_argument("--database", required=True)
    cs.set_defaults(func=_cmd_checksum)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ZoneFileError, StoreError, FileNotFoundError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
