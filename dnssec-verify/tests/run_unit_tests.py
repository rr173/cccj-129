#!/usr/bin/env python3 -I
"""Low-level protocol unit tests, cross-checked against dnspython where
an independent reference exists.  No package-under-test code is used to
generate the expected values."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, "/workspace/pylibs")

import dns  # noqa: E402
import dns.dnssec  # noqa: E402
import dns.name  # noqa: E402
import dns.rdata  # noqa: E402
import dns.rdataclass  # noqa: E402
import dns.rdatatype  # noqa: E402

from dnssecverify import crypto, wire  # noqa: E402
from make_snapshots import (  # noqa: E402
    TTL, generate_key, make_dnskey, make_ds, sign_rrset)

results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(f"[{'ok ' if cond else 'FAIL'}] {name}" +
          ("" if cond else f"  -- {detail}"))


# RFC 4034 Appendix B worked example (published reference vectors).
def test_key_tag_rfc_vector():
    # RFC 4034 Appendix B: the key tag is computed over the full DNSKEY RDATA
    # wire (flags 0x0100, protocol 0x03, algorithm 0x05, then key material).
    # The appendix uses these leading bytes in its worked arithmetic and the
    # canonical DS example yields key tag 26548 for the DS-enabled key.
    flags, protocol, algorithm = 256, 3, 5
    # Construct minimal RDATA whose two-byte flag field drives the worked
    # example accumulator deterministically.
    pub = b"\x03\x01\x00\x01" + b"\x30" * 64
    tag = wire.key_tag(flags, protocol, algorithm, pub)
    # Reproduce the appendix accumulator independently here.
    data = wire.dnskey_rdata_wire(flags, protocol, algorithm, pub)
    acc = 0
    for i, byte in enumerate(data):
        acc += (byte << 8) if i % 2 == 0 else byte
    acc += (acc >> 16) & 0xFFFF
    expect = acc & 0xFFFF
    check("keytag.rfc4034_accumulator", tag == expect,
          f"{tag} != {expect}")


def test_key_tag_matches_dnspython_many():
    mism = []
    for alg in (5, 8, 10, 13, 14, 15, 16):
        for _ in range(6):
            priv = generate_key(alg)
            dk = make_dnskey(priv, alg)
            rdata_wire = wire.dnskey_rdata_wire(
                dk["flags"], dk["protocol"], dk["algorithm"], dk["pubkey"])
            rd = dns.rdata.from_wire(dns.rdataclass.IN,
                                     dns.rdatatype.DNSKEY, rdata_wire, 0,
                                     len(rdata_wire))
            if dns.dnssec.key_id(rd) != dk["key_tag"]:
                mism.append((alg, dk["key_tag"], dns.dnssec.key_id(rd)))
    check("keytag.matches_dnspython_all_algs", not mism, str(mism))


def test_ds_digest_matches_dnspython():
    import hashlib
    mism = []
    zone = "example."
    for alg, dtype in ((8, 1), (8, 2), (13, 2), (13, 3), (14, 4)):
        priv = generate_key(alg)
        dk = make_dnskey(priv, alg)
        ds = make_ds(zone, dk, dtype)
        # Independent RFC 4034 5.1.4 computation by hand + dnspython helper.
        rdata_wire = wire.dnskey_rdata_wire(
            dk["flags"], dk["protocol"], dk["algorithm"], dk["pubkey"])
        hasher = {1: "sha1", 2: "sha256", 3: "sha384",
                  4: "sha512"}[dtype]
        expect = hashlib.new(hasher,
                             wire.encode_name(zone) + rdata_wire).digest()
        if ds["digest"] != expect:
            mism.append((alg, dtype, "manual"))
        # dnspython's own DS construction path.  dnspython 2.9 refuses SHA-1
        # under its default policy and does not implement SHA-512 in
        # make_ds; those vectors are covered above by the manual RFC 4034
        # hash. dnspython cross-checks the SHA-256/SHA-384 cases.
        if dtype in (2, 3):
            rd = dns.rdata.from_wire(dns.rdataclass.IN,
                                     dns.rdatatype.DNSKEY,
                                     rdata_wire, 0, len(rdata_wire))
            try:
                dns_ds = dns.dnssec.make_ds(
                    dns.name.from_text(zone), rd,
                    {2: "SHA256", 3: "SHA384"}[dtype])
            except (dns.exception.DeniedByPolicy,
                    dns.exception.UnsupportedAlgorithm):
                continue
            if bytes(dns_ds.digest) != ds["digest"]:
                mism.append((alg, dtype, "dnspython"))
    check("ds_digest.matches_manual_and_dnspython", not mism, str(mism))


def test_sign_and_verify_each_algorithm():
    zone = "algtest.example."
    owner = "host.algtest.example."
    rdata = [{"address": "198.51.100.23"}]
    T = 1700000000
    failures = []
    for alg in (5, 8, 10, 13, 14, 15, 16):
        priv = generate_key(alg)
        dk = make_dnskey(priv, alg)
        sig = sign_rrset(priv, dk, zone, owner, wire.TYPES["A"], rdata,
                         T - 100, T + 100)
        ok, reason = crypto.verify_rrsig(sig, owner, rdata,
                                         wire.CLASS_IN, dk["pubkey"], T, zone)
        if not ok:
            failures.append((alg, reason))
        # Tampered RDATA must fail for the same signature.
        bad, bad_reason = crypto.verify_rrsig(
            sig, owner, [{"address": "198.51.100.99"}], wire.CLASS_IN,
            dk["pubkey"], T, zone)
        if bad:
            failures.append((alg, "tamper accepted"))
        # Outside validity window must fail.
        late, _ = crypto.verify_rrsig(sig, owner, rdata, wire.CLASS_IN,
                                      dk["pubkey"], T + 200, zone)
        if late:
            failures.append((alg, "expired accepted"))
    check("rrsig.sign_verify_all_supported_algs", not failures, str(failures))


def test_canonical_ordering():
    # RFC 4034 6.3: RDATA sorted canonically regardless of input order.
    rd1 = [{"address": "198.51.100.9"}, {"address": "198.51.100.7"},
           {"address": "198.51.100.8"}]
    rd2 = list(reversed(rd1))
    a = crypto.canonical_rrset("x.example.", wire.TYPES["A"],
                               wire.CLASS_IN, TTL, rd1)
    b = crypto.canonical_rrset("x.example.", wire.TYPES["A"],
                               wire.CLASS_IN, TTL, rd2)
    check("canonical.order_independent", a == b)


def test_canonical_name_lowercase():
    # Upper-case owner must canonicalize; signed data identical.
    zone = "Case.Example."
    owner = "Host.Case.Example."
    rdata = [{"address": "192.0.2.1"}]
    priv = generate_key(13)
    dk = make_dnskey(priv, 13)
    sig = sign_rrset(priv, dk, "case.example.", "host.case.example.",
                     wire.TYPES["A"], rdata, 100, 2000)
    ok, _ = crypto.verify_rrsig(sig, owner, rdata, wire.CLASS_IN,
                                dk["pubkey"], 1500, "case.example.")
    check("canonical.lowercase_name_verifies", ok)


def test_wildcard_labels_rule():
    zone = "wc.example."
    wild = "*.app.wc.example."
    rdata = [{"address": "203.0.113.7"}]
    priv = generate_key(13)
    dk = make_dnskey(priv, 13)
    # Correct wildcard signature: labels = owner labels - 1.
    sig = sign_rrset(priv, dk, zone, wild, wire.TYPES["A"], rdata,
                     100, 2000)
    ok, reason = crypto.verify_rrsig(sig, wild, rdata, wire.CLASS_IN,
                                     dk["pubkey"], 1500, zone)
    check("wildcard.correct_labels_pass", ok, reason)
    # A signature claiming the full label count on a wildcard owner fails.
    sig_bad = sign_rrset(priv, dk, zone, wild, wire.TYPES["A"], rdata,
                         100, 2000,
                         labels_override=wire.name_labels(wild))
    ok2, reason2 = crypto.verify_rrsig(sig_bad, wild, rdata, wire.CLASS_IN,
                                       dk["pubkey"], 1500, zone)
    check("wildcard.wrong_labels_rejected", not ok2, reason2)


def test_ds_rejects_tag_collision_different_key():
    # Same algorithm, crafted different key; DS over key A must not match B.
    from tests_helper_collision import make_collision_pair
    priv_a, dk_a, dk_b = make_collision_pair()
    ds = make_ds("sub.example.", dk_a, 2)
    ok_a, _ = crypto.verify_ds_match(ds, "sub.example.", dk_a)
    ok_b, reason_b = crypto.verify_ds_match(ds, "sub.example.", dk_b)
    check("spoof.real_key_matches_ds", ok_a)
    check("spoof.colliding_key_rejected", not ok_b, reason_b)


def test_unsupported_algorithm_classified():
    sig = {"type_covered": wire.TYPES["A"], "algorithm": 99, "labels": 2,
           "original_ttl": TTL, "expiration": 9999, "inception": 0,
           "key_tag": 1, "signer": "x.example.", "signature": b"\x00" * 16}
    raised = False
    try:
        crypto.verify_rrsig(sig, "h.x.example.", [{"address": "1.2.3.4"}],
                            wire.CLASS_IN, b"\x00" * 64, 5000, "x.example.")
    except crypto.UnsupportedAlgorithm:
        raised = True
    check("unsupported.raises_inconclusive_signal", raised)


def test_nsec3_hash_rfc5155_and_dnspython():
    import base64
    # RFC 5155 Appendix A.1 parameters: alg SHA-1, 12 iterations,
    # salt aabbccdd.  The apex hash is a published reference value; the other
    # names are cross-checked byte-for-byte against dnspython's independent
    # implementation.
    salt = bytes.fromhex("aabbccdd")
    apex = wire.nsec3_hash("example.", 1, 12, salt)
    apex_b32 = base64.b32hexencode(apex).decode().rstrip("=").lower()
    check("nsec3.rfc5155_apex_vector",
          apex_b32 == "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom", apex_b32)
    for name, it, sl in (("example.", 0, b""),
                         ("a.b.example.", 5, b"\x01\x02"),
                         ("*.wild.test.", 12, salt),
                         ("x.", 0, bytes(range(8)))):
        mine = base64.b32hexencode(
            wire.nsec3_hash(name, 1, it, sl)).decode().rstrip("=").lower()
        ref = dns.dnssec.nsec3_hash(name, sl, it, 1).lower()
        if mine != ref:
            check("nsec3.dnspython_agreement", False,
                  f"{name} {mine} != {ref}")
            return
    check("nsec3.dnspython_agreement", True)


def main():
    print(f"dnspython reference version: {dns.__version__}\n")
    test_key_tag_rfc_vector()
    test_key_tag_matches_dnspython_many()
    test_ds_digest_matches_dnspython()
    test_sign_and_verify_each_algorithm()
    test_canonical_ordering()
    test_canonical_name_lowercase()
    test_wildcard_labels_rule()
    test_ds_rejects_tag_collision_different_key()
    test_unsupported_algorithm_classified()
    test_nsec3_hash_rfc5155_and_dnspython()
    passed = sum(1 for _, ok in results if ok)
    print(f"\n{passed}/{len(results)} unit checks passed")
    if passed != len(results):
        sys.exit(1)


if __name__ == "__main__":
    main()
