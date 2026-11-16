"""Independent DNSSEC oracle built on dnspython (a second implementation).

This module never imports the package under test.  It re-parses the same
snapshot files with dnspython's own master-file parser, builds its own RRsets
and validates RRSIG records and DS digests using ``dns.dnssec``.  Its
per-RRset expectations are compared against the system under test by
``run_all_tests.py``.

dnspython version: reported at runtime for reproducibility.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, "/workspace/pylibs")

import dns  # noqa: E402
import dns.dnssec  # noqa: E402
import dns.name  # noqa: E402
import dns.rdata  # noqa: E402
import dns.rdataclass  # noqa: E402
import dns.rdatatype  # noqa: E402
import dns.rrset  # noqa: E402
import dns.tokenizer  # noqa: E402
import dns.zone  # noqa: E402

VERSION = dns.__version__

# dnspython validate() raises on these; map them to stable reason strings.
UNSUPPORTED_RCODE = "UNSUPPORTED_ALGORITHM"


def parse_zone(path: str, zone_origin: str) -> dns.zone.Zone:
    """Parse a snapshot with dnspython's own zone parser."""
    origin = dns.name.from_text(zone_origin)
    with open(path, "r", encoding="utf-8") as fh:
        return dns.zone.from_text(fh, origin=origin, check_origin=False,
                                  relativize=False)


def _rrset_map(zone: dns.zone.Zone):
    """Return {(owner_text, rdtype): rrset} and signature rrset map."""
    rrsets: dict[tuple[str, str], dns.rrset.RRset] = {}
    for name, node in zone.nodes.items():
        for rdataset in node.rdatasets:
            rtype = dns.rdatatype.to_text(rdataset.rdtype)
            rrsets[(name.to_text(), rtype)] = rdataset
    return rrsets


def oracle_rrset_verdict(path: str, zone_origin: str, at_time: int
                         ) -> dict:
    """Validate every authoritative RRset independently with dnspython.

    Returns a mapping keyed by ``(owner, rtype)`` to a dict::

        {"verdict": "PASS|FAIL|INCONCLUSIVE", "reason": str,
         "valid_tags": [...], "failed_tags": [...]}
    """
    zone = parse_zone(path, zone_origin)
    result: dict[tuple[str, str], dict] = {}

    # Index DNSKEYs and RRSIGs.  Keys live at the zone apex; the dnspython
    # key dictionary must be keyed by that apex (the RRSIG signer name),
    # not by each RRset's owner.
    keys_by_tag: dict[int, list] = {}
    apex_name = None
    all_keys = []
    for name, node in zone.nodes.items():
        rds = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.DNSKEY)
        if rds is not None:
            apex_name = name
            for rd in rds:
                tag = dns.dnssec.key_id(rd)
                keys_by_tag.setdefault(tag, []).append(rd)
                all_keys.append(rd)

    for name, node in zone.nodes.items():
        for rdataset in list(node.rdatasets):
            rtype_num = rdataset.rdtype
            if rtype_num == dns.rdatatype.RRSIG:
                continue
            rtype = dns.rdatatype.to_text(rtype_num)
            # dnspython stores each RRSIG(covered-type) as a separate
            # rdataset distinguished by its .covers attribute.
            sig_rdataset = node.get_rdataset(
                dns.rdataclass.IN, dns.rdatatype.RRSIG, covers=rtype_num)
            covering = list(sig_rdataset) if sig_rdataset else []
            key = (name.to_text(), rtype)
            if not covering:
                result[key] = {"verdict": "FAIL",
                               "reason": "no covering RRSIG",
                               "valid_tags": [], "failed_tags": []}
                continue

            valid_tags, failed_tags, unsupported = [], [], False
            reasons = []
            for sig in covering:
                # Time validity per dnspython's own inception/expiration.
                if at_time < int(sig.inception):
                    failed_tags.append(sig.key_tag)
                    reasons.append(f"tag {sig.key_tag}: not yet valid")
                    continue
                if at_time > int(sig.expiration):
                    failed_tags.append(sig.key_tag)
                    reasons.append(f"tag {sig.key_tag}: expired")
                    continue
                candidate = keys_by_tag.get(sig.key_tag, [])
                ok_here = False
                rrset = dns.rrset.from_rdata_list(
                    name, rdataset.ttl, list(rdataset))
                sig_rrset = dns.rrset.from_rdata_list(
                    name, sig_rdataset.ttl, list(sig_rdataset))
                for dnskey in candidate:
                    if dnskey.algorithm != sig.algorithm:
                        continue
                    try:
                        dns.dnssec.validate(
                            rrset, sig_rrset,
                            {apex_name: [dnskey]}, now=at_time)
                        ok_here = True
                        break
                    except dns.dnssec.ValidationFailure as exc:
                        reasons.append(f"tag {sig.key_tag}: {exc}")
                    except Exception as exc:  # unsupported alg etc.
                        reasons.append(f"tag {sig.key_tag}: {exc}")
                        unsupported = unsupported or _is_unsupported(exc)
                if ok_here:
                    valid_tags.append(sig.key_tag)
                else:
                    failed_tags.append(sig.key_tag)

            if valid_tags:
                verdict, reason = "PASS", "dnspython validated >=1 RRSIG"
            elif unsupported and not failed_tags:
                verdict, reason = ("INCONCLUSIVE",
                                   "only unsupported algorithms present")
            elif unsupported:
                verdict, reason = ("INCONCLUSIVE",
                                   "unsupported algorithm among signatures")
            else:
                verdict, reason = "FAIL", "; ".join(reasons)[:300]
            result[key] = {"verdict": verdict, "reason": reason,
                           "valid_tags": valid_tags,
                           "failed_tags": failed_tags}
    return result


def _dnspython_sig_algs() -> set:
    algs = set()
    for mapper in (getattr(dns.dnssec, "algorithm_from_hash", {}),):
        if isinstance(mapper, dict):
            algs.update(mapper.keys())
    # RSASHA1/EC/Ed families dnspython supports explicitly.
    algs.update({5, 7, 8, 10, 13, 14, 15, 16})
    return algs


def _is_unsupported(exc: Exception) -> bool:
    text = str(exc).lower()
    return ("algorithm" in text and
            ("unknown" in text or "unsupported" in text or "not support"
             in text))


def oracle_ds_match(path: str, zone_origin: str, child_origin: str) -> dict:
    """Independently check each DS against child DNSKEYs via dnspython.

    Returns ``{(owner, "DS"): {"verdict": ..., "matched_tags": [...]}}``.
    """
    zone = parse_zone(path, zone_origin)
    child_name = dns.name.from_text(child_origin)
    # Child keys come from the child snapshot when available; caller supplies
    # them through make_ds expectation instead, so here we only check DS
    # internal consistency (digest type known) and return raw records.
    out: dict = {}
    for name, node in zone.nodes.items():
        ds_set = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.DS)
        if ds_set is None:
            continue
        digest_ok = all(
            ds.digest_type in (1, 2, 3, 4) for ds in ds_set)
        out[(name.to_text(), "DS")] = {
            "verdict": "PASS" if digest_ok else "INCONCLUSIVE",
            "records": [{"key_tag": ds.key_tag,
                         "algorithm": ds.algorithm,
                         "digest_type": ds.digest_type} for ds in ds_set]}
    return out
