#!/usr/bin/env python3 -I
"""Build a large historical zone (>=100k records) for scale verification.

To keep signing cost bounded while exercising every code path, the zone
contains many serials and many RRsets; each RRset carries one real RRSIG.
Records are streamed into the store through the normal loader path.
"""
from __future__ import annotations

import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, "/workspace/pylibs")

from dnssecverify import wire  # noqa: E402
from dnssecverify.zonefile import RawRecord, parse_zone_file  # noqa: E402
from dnssecverify.store import IngestStore  # noqa: E402
from make_snapshots import (  # noqa: E402
    TTL, generate_key, make_dnskey, make_ds, sign_rrset, soa_rdata,
    write_anchor_json,
)

DB = os.path.join(ROOT, "db", "large.db")
ZONE = "large.example."
# 120 serials x ~850 host records each => ~102k authoritative records,
# plus per-RRset RRSIGs, SOA/NS/DNSKEY and delegation/DS overhead.
SERIALS = 120
HOSTS_PER_SERIAL = 850


def build():
    if os.path.exists(DB):
        for suffix in ("", "-wal", "-shm"):
            p = DB + suffix
            if os.path.exists(p):
                os.unlink(p)
    priv = generate_key(13)
    key = make_dnskey(priv, 13)
    anchor = make_ds(ZONE, key)
    anchor_dir = os.path.join(ROOT, "samples", "large")
    os.makedirs(anchor_dir, exist_ok=True)
    write_anchor_json(os.path.join(anchor_dir, "anchors.json"),
                      ZONE, anchor, "DS", "large-scale anchor")
    T = 1700000000
    store = IngestStore(DB)
    total = 0
    started = time.time()
    try:
        for serial in range(2023000001, 2023000001 + SERIALS):
            records: list[RawRecord] = []
            src = f"{ZONE}={serial} (synthetic large snapshot)"
            line = 0

            def add(owner, rtype, rdata, ttl=TTL):
                nonlocal line
                line += 1
                records.append(RawRecord(
                    ZONE, serial, owner, rtype, wire.CLASS_IN, ttl, rdata,
                    src, line))

            # Apex trio.
            soa = soa_rdata(ZONE, serial)
            add(ZONE, wire.TYPES["SOA"], soa)
            add(ZONE, wire.TYPES["NS"], {"target": f"ns1.{ZONE}"})
            add(ZONE, wire.TYPES["DNSKEY"], key)
            add(f"ns1.{ZONE}", wire.TYPES["A"], {"address": "192.0.2.10"})
            for i in range(HOSTS_PER_SERIAL):
                owner = f"host{i:05d}.{ZONE}"
                rdata = {"address": f"203.0.113.{i % 250 + 1}"}
                add(owner, wire.TYPES["A"], rdata)
            # Sign every distinct RRset exactly once (real ECDSA signatures).
            rrsig_records: list[RawRecord] = []

            def attach_sig(owner, rtype, rdata_list, ttl=TTL):
                nonlocal line
                sig = sign_rrset(priv, key, ZONE, owner, rtype, rdata_list,
                                 T - 86400, T + 86400, original_ttl=ttl)
                line += 1
                rrsig_records.append(RawRecord(
                    ZONE, serial, owner, wire.TYPES["RRSIG"], wire.CLASS_IN,
                    TTL, sig, src, line))

            attach_sig(ZONE, wire.TYPES["SOA"], [soa])
            attach_sig(ZONE, wire.TYPES["NS"],
                       [{"target": f"ns1.{ZONE}"}])
            attach_sig(ZONE, wire.TYPES["DNSKEY"], [key])
            attach_sig(f"ns1.{ZONE}", wire.TYPES["A"],
                       [{"address": "192.0.2.10"}])
            # One signature per host RRset: this is the dominant cost.
            for i in range(HOSTS_PER_SERIAL):
                owner = f"host{i:05d}.{ZONE}"
                attach_sig(owner, wire.TYPES["A"],
                           [{"address": f"203.0.113.{i % 250 + 1}"}])
            all_records = records + rrsig_records
            n = store.ingest_records(
                {"zone": ZONE, "serial": serial,
                 "default_ttl": TTL, "source": src}, all_records)
            total += n
            if serial % 20 == 2023000001 - 1 + 20:
                print(f"  ...{serial}: cumulative {total} records, "
                      f"{time.time()-started:.0f}s")
    finally:
        store.close()
    print(f"TOTAL ingested records: {total} in {time.time()-started:.0f}s")
    # Manifest for a single mid-range serial verification.
    import json
    manifest = {
        "verification_time_utc": "2023-11-14T22:13:20Z",
        "snapshots": [{"zone": ZONE, "serial": 2023000001 + SERIALS // 2}]}
    with open(os.path.join(anchor_dir, "manifest.json"),
              "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)


if __name__ == "__main__":
    build()
