#!/usr/bin/env python3 -I
"""Load every fixture snapshot into one SQLite database (idempotent)."""
import glob
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, "/workspace/pylibs")

from dnssecverify.store import IngestStore  # noqa: E402
from dnssecverify.zonefile import parse_zone_file  # noqa: E402

DB = os.path.join(ROOT, "db", "fixtures.db")
FIX = os.path.join(ROOT, "samples", "fixtures")


def main():
    if os.path.exists(DB):
        for suffix in ("", "-wal", "-shm"):
            p = DB + suffix
            if os.path.exists(p):
                os.unlink(p)
    store = IngestStore(DB)
    total = 0
    try:
        for path in sorted(glob.glob(os.path.join(FIX, "*", "*.zone"))):
            header, records = parse_zone_file(path)
            if store.snapshot_exists(header["zone"], header["serial"]):
                print(f"skip existing {header['zone']}={header['serial']}")
                continue
            n = store.ingest_records(header, records)
            total += n
            print(f"loaded {os.path.relpath(path, ROOT):45s} "
                  f"{header['zone']:22s} serial={header['serial']:6d} "
                  f"records={n}")
    finally:
        store.close()
    print("TOTAL records loaded:", total)


if __name__ == "__main__":
    main()
