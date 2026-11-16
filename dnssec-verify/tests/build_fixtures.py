"""Build all signed-zone fixture scenarios used by the test suite.

All signatures are real cryptographic signatures produced with the
``cryptography`` library; no code from the package under test is used to
*generate* expected verdicts.  Every fixture directory is self-contained.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, "/workspace/pylibs")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from dnssecverify import wire  # noqa: E402
from make_snapshots import (  # noqa: E402
    TTL, generate_key, make_dnskey, make_ds, render_record, sign_rrset,
    soa_rdata, write_anchor_json, write_zone,
)

# Fixed verification instant: 2023-11-14T22:13:20Z
T = 1700000000
VALID_IN, VALID_OUT = T - 86400, T + 86400
EXPIRED_IN, EXPIRED_OUT = T - 172800, T - 3600
FUTURE_IN, FUTURE_OUT = T + 3600, T + 172800

ROOT = os.path.join(os.path.dirname(HERE), "samples", "fixtures")


class ZoneBuilder:
    """Accumulate RR lines and RRSIG lines, tracking source line numbers."""

    def __init__(self, zone: str, serial: int):
        self.zone = zone
        self.serial = serial
        self.lines: list[str] = []
        # (owner, rtype) -> list of 1-based line numbers holding members
        self.member_lines: dict[tuple, list[int]] = {}
        self.sig_lines: dict[tuple, list[int]] = {}

    def add(self, owner: str, rtype_name: str, rdata: dict, ttl: int = TTL):
        rtype = wire.TYPES[rtype_name]
        self.lines.append(render_record(owner, ttl, rtype_name, rdata,
                                        self.zone))
        self.member_lines.setdefault((owner, rtype), []).append(len(self.lines))
        return self

    def add_sig(self, sig: dict, owner: str):
        rtype = wire.TYPES["RRSIG"]
        self.lines.append(render_record(owner, TTL, "RRSIG", sig, self.zone))
        self.sig_lines.setdefault(
            (owner, sig["type_covered"]), []).append(len(self.lines))
        return self

    def apex_soa(self):
        self.add(self.zone, "SOA", soa_rdata(self.zone, self.serial))
        return self

    def write(self, directory: str, name: str) -> str:
        path = os.path.join(directory, name)
        return write_zone(path, self.zone, self.serial, self.lines)


def sign_and_attach(builder: ZoneBuilder, owner: str, rtype_name: str,
                    rdata_list: list[dict], signers: list,
                    validity=("valid",)):
    """Sign an RRset with one or more (priv, dnskey) pairs.

    validity entries: "valid", "expired", "future".
    """
    rtype = wire.TYPES[rtype_name]
    windows = {"valid": (VALID_IN, VALID_OUT),
               "expired": (EXPIRED_IN, EXPIRED_OUT),
               "future": (FUTURE_IN, FUTURE_OUT)}
    for (priv, dk), kind in zip(signers, validity):
        inc, exp = windows[kind]
        sig = sign_rrset(priv, dk, builder.zone, owner, rtype, rdata_list,
                         inc, exp)
        builder.add_sig(sig, owner)


def fresh_key(algorithm: int = 13, flags: int = 257):
    priv = generate_key(algorithm)
    return priv, make_dnskey(priv, algorithm, flags)


def write_manifest(path: str, entries: list[tuple[str, int]]):
    doc = {"verification_time_utc": "2023-11-14T22:13:20Z",
           "snapshots": [{"zone": z, "serial": s} for z, s in entries]}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)


# --------------------------------------------------------------------------
# Scenario A: rollover, two DS / two DNSKEY / multiple RRSIG, one chain live
# --------------------------------------------------------------------------
def scenario_rollover(directory: str):
    os.makedirs(directory, exist_ok=True)
    parent_priv, parent_key = fresh_key(13)
    old_priv, old_key = fresh_key(13)
    new_priv, new_key = fresh_key(13)

    parent = ZoneBuilder("example.", 1000).apex_soa()
    parent_ns = {"target": "ns1.example."}
    parent.add("example.", "NS", parent_ns)
    parent.add("example.", "DNSKEY", parent_key)
    parent.add("ns1.example.", "A", {"address": "192.0.2.10"})
    # Delegation to sub.example. with DS for BOTH child keys (rollover).
    sub_ns = {"target": "ns1.sub.example."}
    parent.add("sub.example.", "NS", sub_ns)
    parent.add("ns1.sub.example.", "A", {"address": "192.0.2.20"})
    ds_old = make_ds("sub.example.", old_key)
    ds_new = make_ds("sub.example.", new_key)
    parent.add("sub.example.", "DS", ds_old)
    parent.add("sub.example.", "DS", ds_new)
    # Parent signatures.
    sign_and_attach(parent, "example.", "SOA",
                    [soa_rdata("example.", 1000)], [(parent_priv, parent_key)])
    sign_and_attach(parent, "example.", "NS", [parent_ns],
                    [(parent_priv, parent_key)])
    sign_and_attach(parent, "example.", "DNSKEY", [parent_key],
                    [(parent_priv, parent_key)])
    sign_and_attach(parent, "ns1.example.", "A",
                    [{"address": "192.0.2.10"}],
                    [(parent_priv, parent_key)])
    sign_and_attach(parent, "sub.example.", "DS", [ds_old, ds_new],
                    [(parent_priv, parent_key)])
    parent.write(directory, "example-1000.zone")

    child = ZoneBuilder("sub.example.", 2000).apex_soa()
    child_ns = {"target": "ns1.sub.example."}
    child.add("sub.example.", "NS", child_ns)
    child.add("sub.example.", "DNSKEY", old_key)
    child.add("sub.example.", "DNSKEY", new_key)
    child.add("www.sub.example.", "A", {"address": "198.51.100.7"})
    child.add("www.sub.example.", "A", {"address": "198.51.100.8"})
    child.add("info.sub.example.", "TXT", {"strings": ["v=spf1 -all"]})
    child.add("mail.sub.example.", "MX",
              {"preference": 10, "exchange": "mailhub.sub.example."})
    child.add("*.wild.sub.example.", "A", {"address": "203.0.113.9"})
    signers = [(old_priv, old_key), (new_priv, new_key)]
    sign_and_attach(child, "sub.example.", "SOA",
                    [soa_rdata("sub.example.", 2000)], signers,
                    ("expired", "valid"))
    sign_and_attach(child, "sub.example.", "NS", [child_ns], signers,
                    ("expired", "valid"))
    sign_and_attach(child, "sub.example.", "DNSKEY", [old_key, new_key],
                    signers, ("expired", "valid"))
    sign_and_attach(child, "www.sub.example.", "A",
                    [{"address": "198.51.100.7"},
                     {"address": "198.51.100.8"}], signers,
                    ("expired", "valid"))
    sign_and_attach(child, "info.sub.example.", "TXT",
                    [{"strings": ["v=spf1 -all"]}], signers,
                    ("expired", "valid"))
    sign_and_attach(child, "mail.sub.example.", "MX",
                    [{"preference": 10,
                      "exchange": "mailhub.sub.example."}], signers,
                    ("expired", "valid"))
    sign_and_attach(child, "*.wild.sub.example.", "A",
                    [{"address": "203.0.113.9"}], signers,
                    ("expired", "valid"))
    child.write(directory, "sub.example-2000.zone")

    anchor_ds = make_ds("example.", parent_key)
    write_anchor_json(os.path.join(directory, "anchors.json"),
                      "example.", anchor_ds, "DS",
                      "rollover test trust anchor")
    write_manifest(os.path.join(directory, "manifest.json"),
                   [("example.", 1000), ("sub.example.", 2000)])
    return {"parent_key": parent_key, "old_key": old_key, "new_key": new_key}


# --------------------------------------------------------------------------
# Scenario B: same key tag + algorithm, different public key (impostor)
# --------------------------------------------------------------------------
def find_tag_collision(target_tag: int, algorithm: int = 13):
    priv, dk = fresh_key(algorithm)
    while dk["key_tag"] != target_tag:
        priv, dk = fresh_key(algorithm)
    return priv, dk


def scenario_spoof(directory: str, rollover_keys: dict):
    os.makedirs(directory, exist_ok=True)
    parent_priv, parent_key = fresh_key(13)
    real_priv, real_key = fresh_key(13)
    # Generate a *different* key that collides on tag and algorithm number.
    spoof_priv, spoof_key = find_tag_collision(real_key["key_tag"])
    assert spoof_key["pubkey"] != real_key["pubkey"], "collision search failed"
    assert spoof_key["key_tag"] == real_key["key_tag"]
    assert spoof_key["algorithm"] == real_key["algorithm"]

    parent = ZoneBuilder("example.", 1100).apex_soa()
    parent.add("example.", "NS", {"target": "ns1.example."})
    parent.add("example.", "DNSKEY", parent_key)
    parent.add("sub.example.", "NS", {"target": "ns1.sub.example."})
    parent.add("ns1.sub.example.", "A", {"address": "192.0.2.20"})
    # DS was honestly built over the REAL key; the child publishes spoof key.
    ds_real = make_ds("sub.example.", real_key)
    parent.add("sub.example.", "DS", ds_real)
    sign_and_attach(parent, "example.", "SOA",
                    [soa_rdata("example.", 1100)],
                    [(parent_priv, parent_key)])
    sign_and_attach(parent, "example.", "NS",
                    [{"target": "ns1.example."}],
                    [(parent_priv, parent_key)])
    sign_and_attach(parent, "example.", "DNSKEY", [parent_key],
                    [(parent_priv, parent_key)])
    sign_and_attach(parent, "sub.example.", "DS", [ds_real],
                    [(parent_priv, parent_key)])
    parent.write(directory, "example-1100.zone")

    child = ZoneBuilder("sub.example.", 2100).apex_soa()
    child.add("sub.example.", "NS", {"target": "ns1.sub.example."})
    child.add("sub.example.", "DNSKEY", spoof_key)  # impostor publication
    child.add("www.sub.example.", "A", {"address": "198.51.100.77"})
    # RRSIGs made by the real private key cannot match the spoof public key.
    sign_and_attach(child, "sub.example.", "SOA",
                    [soa_rdata("sub.example.", 2100)],
                    [(real_priv, real_key)])
    sign_and_attach(child, "sub.example.", "NS",
                    [{"target": "ns1.sub.example."}],
                    [(real_priv, real_key)])
    sign_and_attach(child, "sub.example.", "DNSKEY", [spoof_key],
                    [(real_priv, real_key)])
    sign_and_attach(child, "www.sub.example.", "A",
                    [{"address": "198.51.100.77"}],
                    [(real_priv, real_key)])
    child.write(directory, "sub.example-2100.zone")

    write_anchor_json(os.path.join(directory, "anchors.json"),
                      "example.", make_ds("example.", parent_key), "DS")
    write_manifest(os.path.join(directory, "manifest.json"),
                   [("example.", 1100), ("sub.example.", 2100)])
    return {"real_tag": real_key["key_tag"],
            "spoof_pubkey": spoof_key["pubkey"].hex()}


# --------------------------------------------------------------------------
# Scenario C: only expired signatures on one RRset
# --------------------------------------------------------------------------
def scenario_expired(directory: str):
    os.makedirs(directory, exist_ok=True)
    priv, key = fresh_key(13)
    z = ZoneBuilder("example.", 1200).apex_soa()
    z.add("example.", "NS", {"target": "ns1.example."})
    z.add("example.", "DNSKEY", key)
    z.add("ns1.example.", "A", {"address": "192.0.2.10"})
    z.add("stale.example.", "A", {"address": "192.0.2.66"})
    sign_and_attach(z, "example.", "SOA",
                    [soa_rdata("example.", 1200)], [(priv, key)])
    sign_and_attach(z, "example.", "NS",
                    [{"target": "ns1.example."}], [(priv, key)])
    sign_and_attach(z, "example.", "DNSKEY", [key], [(priv, key)])
    sign_and_attach(z, "ns1.example.", "A",
                    [{"address": "192.0.2.10"}], [(priv, key)])
    sign_and_attach(z, "stale.example.", "A",
                    [{"address": "192.0.2.66"}], [(priv, key)],
                    ("expired",))
    z.write(directory, "example-1200.zone")
    write_anchor_json(os.path.join(directory, "anchors.json"),
                      "example.", make_ds("example.", key), "DS")
    write_manifest(os.path.join(directory, "manifest.json"),
                   [("example.", 1200)])


# --------------------------------------------------------------------------
# Scenario D: parent has no DS for the child
# --------------------------------------------------------------------------
def scenario_no_ds(directory: str):
    os.makedirs(directory, exist_ok=True)
    ppriv, pkey = fresh_key(13)
    cpriv, ckey = fresh_key(13)
    parent = ZoneBuilder("example.", 1300).apex_soa()
    parent.add("example.", "NS", {"target": "ns1.example."})
    parent.add("example.", "DNSKEY", pkey)
    parent.add("sub.example.", "NS", {"target": "ns1.sub.example."})
    parent.add("ns1.sub.example.", "A", {"address": "192.0.2.20"})
    # Deliberately NO sub.example. DS record.
    sign_and_attach(parent, "example.", "SOA",
                    [soa_rdata("example.", 1300)], [(ppriv, pkey)])
    sign_and_attach(parent, "example.", "NS",
                    [{"target": "ns1.example."}], [(ppriv, pkey)])
    sign_and_attach(parent, "example.", "DNSKEY", [pkey], [(ppriv, pkey)])
    parent.write(directory, "example-1300.zone")

    child = ZoneBuilder("sub.example.", 2300).apex_soa()
    child.add("sub.example.", "NS", {"target": "ns1.sub.example."})
    child.add("sub.example.", "DNSKEY", ckey)
    child.add("www.sub.example.", "A", {"address": "198.51.100.5"})
    sign_and_attach(child, "sub.example.", "SOA",
                    [soa_rdata("sub.example.", 2300)], [(cpriv, ckey)])
    sign_and_attach(child, "sub.example.", "NS",
                    [{"target": "ns1.sub.example."}], [(cpriv, ckey)])
    sign_and_attach(child, "sub.example.", "DNSKEY", [ckey],
                    [(cpriv, ckey)])
    sign_and_attach(child, "www.sub.example.", "A",
                    [{"address": "198.51.100.5"}], [(cpriv, ckey)])
    child.write(directory, "sub.example-2300.zone")
    write_anchor_json(os.path.join(directory, "anchors.json"),
                      "example.", make_ds("example.", pkey), "DS")
    write_manifest(os.path.join(directory, "manifest.json"),
                   [("example.", 1300), ("sub.example.", 2300)])


# --------------------------------------------------------------------------
# Scenario E: signed coverage mismatch (post-signing mutation, bad labels)
# --------------------------------------------------------------------------
def scenario_coverage(directory: str):
    os.makedirs(directory, exist_ok=True)
    priv, key = fresh_key(13)
    z = ZoneBuilder("example.", 1400).apex_soa()
    z.add("example.", "NS", {"target": "ns1.example."})
    z.add("example.", "DNSKEY", key)
    # Signed RRset with address .17 ...
    z.add("mutated.example.", "A", {"address": "192.0.2.17"})
    # ... but a second, unsigned-at-signature-time member is published.
    z.add("mutated.example.", "A", {"address": "192.0.2.18"})
    z.add("txt.example.", "TXT", {"strings": ["signed text"]})
    z.add("badlabels.deep.example.", "A", {"address": "192.0.2.31"})
    sign_and_attach(z, "example.", "SOA",
                    [soa_rdata("example.", 1400)], [(priv, key)])
    sign_and_attach(z, "example.", "NS",
                    [{"target": "ns1.example."}], [(priv, key)])
    sign_and_attach(z, "example.", "DNSKEY", [key], [(priv, key)])
    # Signature only covered the single .17 record.
    sign_and_attach(z, "mutated.example.", "A",
                    [{"address": "192.0.2.17"}], [(priv, key)])
    sign_and_attach(z, "txt.example.", "TXT",
                    [{"strings": ["signed text"]}], [(priv, key)])
    # RRSIG with a deliberately wrong labels field: the owner has 3 labels
    # (badlabels.deep.example.) but the signature claims only 2.
    bad_sig = sign_rrset(priv, key, "example.",
                         "badlabels.deep.example.",
                         wire.TYPES["A"], [{"address": "192.0.2.31"}],
                         VALID_IN, VALID_OUT, labels_override=2)
    z.add_sig(bad_sig, "badlabels.deep.example.")
    z.write(directory, "example-1400.zone")
    write_anchor_json(os.path.join(directory, "anchors.json"),
                      "example.", make_ds("example.", key), "DS")
    write_manifest(os.path.join(directory, "manifest.json"),
                   [("example.", 1400)])


# --------------------------------------------------------------------------
# Scenario F: wildcard owner, correctly labelled
# --------------------------------------------------------------------------
def scenario_wildcard(directory: str):
    os.makedirs(directory, exist_ok=True)
    priv, key = fresh_key(13)
    z = ZoneBuilder("example.", 1500).apex_soa()
    z.add("example.", "NS", {"target": "ns1.example."})
    z.add("example.", "DNSKEY", key)
    z.add("*.any.example.", "A", {"address": "203.0.113.50"})
    z.add("*.any.example.", "TXT", {"strings": ["wildcard txt"]})
    sign_and_attach(z, "example.", "SOA",
                    [soa_rdata("example.", 1500)], [(priv, key)])
    sign_and_attach(z, "example.", "NS",
                    [{"target": "ns1.example."}], [(priv, key)])
    sign_and_attach(z, "example.", "DNSKEY", [key], [(priv, key)])
    sign_and_attach(z, "*.any.example.", "A",
                    [{"address": "203.0.113.50"}], [(priv, key)])
    sign_and_attach(z, "*.any.example.", "TXT",
                    [{"strings": ["wildcard txt"]}], [(priv, key)])
    z.write(directory, "example-1500.zone")
    write_anchor_json(os.path.join(directory, "anchors.json"),
                      "example.", make_ds("example.", key), "DS")
    write_manifest(os.path.join(directory, "manifest.json"),
                   [("example.", 1500)])


# --------------------------------------------------------------------------
# Scenario G: three-level chain with the middle snapshot omitted
# --------------------------------------------------------------------------
def scenario_gap(directory: str):
    os.makedirs(directory, exist_ok=True)
    ppriv, pkey = fresh_key(13)
    mpriv, mkey = fresh_key(13)
    dpriv, dkey = fresh_key(13)

    parent = ZoneBuilder("example.", 1600).apex_soa()
    parent.add("example.", "NS", {"target": "ns1.example."})
    parent.add("example.", "DNSKEY", pkey)
    parent.add("mid.example.", "NS", {"target": "ns1.mid.example."})
    parent.add("ns1.mid.example.", "A", {"address": "192.0.2.30"})
    ds_mid = make_ds("mid.example.", mkey)
    parent.add("mid.example.", "DS", ds_mid)
    sign_and_attach(parent, "example.", "SOA",
                    [soa_rdata("example.", 1600)], [(ppriv, pkey)])
    sign_and_attach(parent, "example.", "NS",
                    [{"target": "ns1.example."}], [(ppriv, pkey)])
    sign_and_attach(parent, "example.", "DNSKEY", [pkey], [(ppriv, pkey)])
    sign_and_attach(parent, "mid.example.", "DS", [ds_mid],
                    [(ppriv, pkey)])
    parent.write(directory, "example-1600.zone")

    middle = ZoneBuilder("mid.example.", 2600).apex_soa()
    middle.add("mid.example.", "NS", {"target": "ns1.mid.example."})
    middle.add("mid.example.", "DNSKEY", mkey)
    middle.add("deep.mid.example.", "NS",
               {"target": "ns1.deep.mid.example."})
    middle.add("ns1.deep.mid.example.", "A", {"address": "192.0.2.40"})
    ds_deep = make_ds("deep.mid.example.", dkey)
    middle.add("deep.mid.example.", "DS", ds_deep)
    sign_and_attach(middle, "mid.example.", "SOA",
                    [soa_rdata("mid.example.", 2600)], [(mpriv, mkey)])
    sign_and_attach(middle, "mid.example.", "NS",
                    [{"target": "ns1.mid.example."}], [(mpriv, mkey)])
    sign_and_attach(middle, "mid.example.", "DNSKEY", [mkey],
                    [(mpriv, mkey)])
    sign_and_attach(middle, "deep.mid.example.", "DS", [ds_deep],
                    [(mpriv, mkey)])
    middle.write(directory, "mid.example-2600.zone")

    deep = ZoneBuilder("deep.mid.example.", 3600).apex_soa()
    deep.add("deep.mid.example.", "NS",
             {"target": "ns1.deep.mid.example."})
    deep.add("deep.mid.example.", "DNSKEY", dkey)
    deep.add("host.deep.mid.example.", "A", {"address": "198.51.100.90"})
    sign_and_attach(deep, "deep.mid.example.", "SOA",
                    [soa_rdata("deep.mid.example.", 3600)],
                    [(dpriv, dkey)])
    sign_and_attach(deep, "deep.mid.example.", "NS",
                    [{"target": "ns1.deep.mid.example."}],
                    [(dpriv, dkey)])
    sign_and_attach(deep, "deep.mid.example.", "DNSKEY", [dkey],
                    [(dpriv, dkey)])
    sign_and_attach(deep, "host.deep.mid.example.", "A",
                    [{"address": "198.51.100.90"}], [(dpriv, dkey)])
    deep.write(directory, "deep.mid.example-3600.zone")

    write_anchor_json(os.path.join(directory, "anchors.json"),
                      "example.", make_ds("example.", pkey), "DS")
    # Manifest deliberately omits mid.example. -> deep cannot be decided.
    write_manifest(os.path.join(directory, "manifest.json"),
                   [("example.", 1600), ("deep.mid.example.", 3600)])


# --------------------------------------------------------------------------
# Scenario H: unsupported algorithm number (99) -> INCONCLUSIVE
# --------------------------------------------------------------------------
def scenario_unsupported(directory: str):
    os.makedirs(directory, exist_ok=True)
    ppriv, pkey = fresh_key(13)
    # Fabricate an algorithm-99 key directly; no signing primitive exists.
    fake_pub = bytes(range(1, 65))
    fake_key = {"flags": 257, "protocol": 3, "algorithm": 99,
                "pubkey": fake_pub,
                "key_tag": wire.key_tag(257, 3, 99, fake_pub)}
    fake_ds = make_ds("sub.example.", fake_key)

    parent = ZoneBuilder("example.", 1700).apex_soa()
    parent.add("example.", "NS", {"target": "ns1.example."})
    parent.add("example.", "DNSKEY", pkey)
    parent.add("sub.example.", "NS", {"target": "ns1.sub.example."})
    parent.add("ns1.sub.example.", "A", {"address": "192.0.2.20"})
    parent.add("sub.example.", "DS", fake_ds)
    sign_and_attach(parent, "example.", "SOA",
                    [soa_rdata("example.", 1700)], [(ppriv, pkey)])
    sign_and_attach(parent, "example.", "NS",
                    [{"target": "ns1.example."}], [(ppriv, pkey)])
    sign_and_attach(parent, "example.", "DNSKEY", [pkey], [(ppriv, pkey)])
    sign_and_attach(parent, "sub.example.", "DS", [fake_ds],
                    [(ppriv, pkey)])
    parent.write(directory, "example-1700.zone")

    child = ZoneBuilder("sub.example.", 2700).apex_soa()
    child.add("sub.example.", "NS", {"target": "ns1.sub.example."})
    child.add("sub.example.", "DNSKEY", fake_key)
    child.add("www.sub.example.", "A", {"address": "198.51.100.5"})
    # Hand-built RRSIG records carrying algorithm 99 and random signature.
    for owner, rtype_name, rdata in [
            ("sub.example.", "SOA", soa_rdata("sub.example.", 2700)),
            ("sub.example.", "NS", {"target": "ns1.sub.example."}),
            ("sub.example.", "DNSKEY", fake_key),
            ("www.sub.example.", "A", {"address": "198.51.100.5"})]:
        sig = {"type_covered": wire.TYPES[rtype_name], "algorithm": 99,
               "labels": wire.name_labels(owner), "original_ttl": TTL,
               "expiration": VALID_OUT, "inception": VALID_IN,
               "key_tag": fake_key["key_tag"], "signer": "sub.example.",
               "signature": b"\x11" * 64}
        child.add_sig(sig, owner)
    child.write(directory, "sub.example-2700.zone")
    write_anchor_json(os.path.join(directory, "anchors.json"),
                      "example.", make_ds("example.", pkey), "DS")
    write_manifest(os.path.join(directory, "manifest.json"),
                   [("example.", 1700), ("sub.example.", 2700)])


# --------------------------------------------------------------------------
# Scenario J: RSA-SHA256 (algorithm 8) plus an intra-RRset TTL disagreement
# --------------------------------------------------------------------------
def scenario_rsa_ttl(directory: str):
    os.makedirs(directory, exist_ok=True)
    priv, key = fresh_key(8)  # RSASHA256
    z = ZoneBuilder("example.", 1800).apex_soa()
    z.add("example.", "NS", {"target": "ns1.example."})
    z.add("example.", "DNSKEY", key)
    z.add("ns1.example.", "A", {"address": "192.0.2.10"})
    z.add("ok.example.", "TXT", {"strings": ["rsa-signed"]})
    # Two members of one RRset carrying different TTLs (illegal under RFC).
    z.add("split.example.", "A", {"address": "192.0.2.41"}, ttl=3600)
    z.add("split.example.", "A", {"address": "192.0.2.42"}, ttl=7200)
    sign_and_attach(z, "example.", "SOA",
                    [soa_rdata("example.", 1800)], [(priv, key)])
    sign_and_attach(z, "example.", "NS",
                    [{"target": "ns1.example."}], [(priv, key)])
    sign_and_attach(z, "example.", "DNSKEY", [key], [(priv, key)])
    sign_and_attach(z, "ns1.example.", "A",
                    [{"address": "192.0.2.10"}], [(priv, key)])
    sign_and_attach(z, "ok.example.", "TXT",
                    [{"strings": ["rsa-signed"]}], [(priv, key)])
    # Signature over the split RRset using the declared 3600 original TTL.
    split_sig = sign_rrset(priv, key, "example.", "split.example.",
                           wire.TYPES["A"],
                           [{"address": "192.0.2.41"},
                            {"address": "192.0.2.42"}],
                           VALID_IN, VALID_OUT, original_ttl=3600)
    z.add_sig(split_sig, "split.example.")
    z.write(directory, "example-1800.zone")
    write_anchor_json(os.path.join(directory, "anchors.json"),
                      "example.", make_ds("example.", key), "DS")
    write_manifest(os.path.join(directory, "manifest.json"),
                   [("example.", 1800)])


# --------------------------------------------------------------------------
# Scenario I: anchor file problems
# --------------------------------------------------------------------------
def scenario_anchor_problems(directory: str, rollover_dir: str):
    os.makedirs(directory, exist_ok=True)
    with open(os.path.join(rollover_dir, "anchors.json"),
              "r", encoding="utf-8") as fh:
        good = json.load(fh)
    dup = {"anchors": good["anchors"] + [dict(good["anchors"][0])]}
    with open(os.path.join(directory, "anchors-duplicate.json"),
              "w", encoding="utf-8") as fh:
        json.dump(dup, fh, indent=2)
    dnskey_anchor = {
        "anchors": [{
            "zone": "example.",
            "record": {"type": "DNSKEY", "flags": 257, "protocol": 3,
                       "algorithm": 13,
                       "pubkey": base64_b64(b"0" * 64)},
            "source": "conflicting dnskey anchor"}]}
    conflict = {"anchors": good["anchors"] + dnskey_anchor["anchors"]}
    with open(os.path.join(directory, "anchors-conflict.json"),
              "w", encoding="utf-8") as fh:
        json.dump(conflict, fh, indent=2)
    write_manifest(os.path.join(directory, "manifest.json"),
                   [("example.", 1000), ("sub.example.", 2000)])


def base64_b64(data: bytes) -> str:
    import base64
    return base64.b64encode(data).decode()


def main():
    rollover_dir = os.path.join(ROOT, "rollover")
    keys = scenario_rollover(rollover_dir)
    scenario_spoof(os.path.join(ROOT, "spoof"), keys)
    scenario_expired(os.path.join(ROOT, "expired"))
    scenario_no_ds(os.path.join(ROOT, "no-ds"))
    scenario_coverage(os.path.join(ROOT, "coverage"))
    scenario_wildcard(os.path.join(ROOT, "wildcard"))
    scenario_gap(os.path.join(ROOT, "gap"))
    scenario_unsupported(os.path.join(ROOT, "unsupported"))
    scenario_rsa_ttl(os.path.join(ROOT, "rsa-ttl"))
    scenario_anchor_problems(os.path.join(ROOT, "anchor-problems"),
                             rollover_dir)
    print("fixtures written under", ROOT)


if __name__ == "__main__":
    main()
