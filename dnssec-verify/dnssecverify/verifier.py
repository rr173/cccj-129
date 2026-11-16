"""Offline DNSSEC chain-of-trust verification engine.

The engine never performs network I/O.  It reads exact historical snapshots
through one read-only SQLite view and produces a deterministic, fully
attributed verdict structure.

Verdicts (per zone, per RRset and overall):

* ``PASS``         - trust established and every required check succeeded
* ``FAIL``         - cryptographic material exists but does not validate,
                     or an explicit tampering condition was found
* ``INCONCLUSIVE``- required snapshots/material/algorithms are missing, so
                     neither validity nor tampering can be asserted
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import crypto, wire
from .store import SnapshotStore

PASS = "PASS"
FAIL = "FAIL"
INCONCLUSIVE = "INCONCLUSIVE"
# Glue / delegation NS below a zone cut are outside the parent's authoritative
# signature coverage by RFC 4035; they are recorded but never counted as a
# cryptographic PASS.
SKIPPED = "SKIPPED"
# SKIPPED is neutral: it neither taints nor certifies a zone.
_VERDICT_RANK = {PASS: 0, SKIPPED: 0, INCONCLUSIVE: 1, FAIL: 2}


def merge(a: str, b: str) -> str:
    return a if _VERDICT_RANK[a] >= _VERDICT_RANK[b] else b


@dataclass
class Finding:
    level: str                      # FAIL | INCONCLUSIVE | INFO
    code: str
    message: str
    zone: str | None = None
    serial: int | None = None
    owner: str | None = None
    rtype: str | None = None
    key_tag: int | None = None
    sources: list = field(default_factory=list)

    def as_dict(self) -> dict:
        d = {"level": self.level, "code": self.code, "message": self.message}
        for k in ("zone", "serial", "owner", "rtype", "key_tag", "sources"):
            v = getattr(self, k)
            if v is not None and v != []:
                d[k] = v
        return d


def _src(rec) -> dict:
    return {"file": rec.source_file, "line": rec.source_line}


def _src_list(recs) -> list:
    return [_src(r) for r in recs]


def _src_from_provenance(prov: list) -> list:
    return list(prov)


# --------------------------------------------------------------------------
# Trusted key material
# --------------------------------------------------------------------------
@dataclass
class TrustedKey:
    zone: str
    flags: int
    protocol: int
    algorithm: int
    pubkey: bytes
    key_tag: int
    source: dict
    # Zone of the DNSKEY RRset that authenticated this key (for provenance).
    authenticated_in_zone: str | None = None


class Verifier:
    def __init__(self, store: SnapshotStore, anchors: list[dict],
                 at_time: int):
        self.store = store
        self.at_time = at_time
        self.anchors = anchors
        # zone -> list[TrustedKey]
        self.trusted: dict[str, list[TrustedKey]] = {}
        self.findings: list[Finding] = []
        self.rrset_results: list[dict] = []

    # ------------------------------------------------------------------
    # RRSIG verification against an authenticated key set
    # ------------------------------------------------------------------
    def _verify_rrset(self, zone: str, serial: int, owner: str, rtype: int,
                      rclass: int, ttl: int, recs, provenance: list,
                      trusted_keys: list[TrustedKey],
                      is_apex_dnskey: bool = False) -> str:
        type_name = wire.TYPE_NAMES[rtype]
        sigs_holder = self.store.get_rrset(zone, serial, owner,
                                           wire.TYPES["RRSIG"])
        base = {
            "zone": zone, "serial": serial, "owner": owner,
            "rtype": type_name, "ttl": ttl,
            "member_count": len(recs), "sources": provenance,
        }

        if ttl is None:
            verdict, reason = FAIL, ("members of the RRset disagree on TTL; "
                                     "RFC 4034 requires a single TTL")
            self._record(base, verdict, [], reason,
                         Finding(FAIL, "TTL_MISMATCH", reason, zone, serial,
                                 owner, type_name, sources=provenance))
            return verdict

        if sigs_holder is None:
            verdict = FAIL
            reason = "no RRSIG RRset covers this owner name"
            self._record(base, verdict, [], reason,
                         Finding(FAIL, "MISSING_RRSIG", reason, zone, serial,
                                 owner, type_name, sources=provenance))
            return verdict
        sig_recs, sig_ttl, sig_prov = sigs_holder
        sigs = [r.rdata for r in sig_recs
                if r.rdata["type_covered"] == rtype]
        if not sigs:
            verdict = FAIL
            reason = (f"RRSIG RRset exists but no signature covers type "
                      f"{type_name}")
            self._record(base, verdict, _src_list(sig_recs), reason,
                         Finding(FAIL, "RRSIG_TYPE_MISMATCH", reason, zone,
                                 serial, owner, type_name,
                                 sources=_src_list(sig_recs)))
            return verdict

        rdata_list = [r.rdata for r in recs]
        attempts = []
        any_unsupported = False
        any_valid = False
        for sig in sigs:
            sig_src = self._sig_source(sig_recs, sig)
            # Signer apex sanity.
            if wire.canonical_name(sig["signer"]) != wire.canonical_name(zone):
                attempts.append({"key_tag": sig["key_tag"],
                                 "algorithm": sig["algorithm"],
                                 "ok": False,
                                 "reason": f"signer {sig['signer']} is not "
                                           f"zone apex {zone}",
                                 "source": sig_src})
                self.findings.append(Finding(
                    FAIL, "RRSIG_SIGNER_MISMATCH",
                    f"RRSIG tag {sig['key_tag']} signer {sig['signer']} != "
                    f"apex {zone}", zone, serial, owner, type_name,
                    sig["key_tag"], [sig_src]))
                continue
            # Original TTL must be the RRset TTL.
            if sig["original_ttl"] != ttl:
                attempts.append({"key_tag": sig["key_tag"],
                                 "algorithm": sig["algorithm"],
                                 "ok": False,
                                 "reason": f"original TTL "
                                           f"{sig['original_ttl']} != RRset "
                                           f"TTL {ttl}",
                                 "source": sig_src})
                continue
            matching = [k for k in trusted_keys
                        if k.key_tag == sig["key_tag"]
                        and k.algorithm == sig["algorithm"]
                        and k.zone == zone]
            # Key tag + algorithm equality is not identity: only keys whose
            # full public key blob is present in the authenticated set count.
            # Tag collisions cannot occur inside the authenticated set, whose
            # membership was proven via full DS digest / anchor equality.
            matched_key = matching[0] if matching else None
            if matched_key is None:
                if not crypto.algorithm_supported(sig["algorithm"]):
                    any_unsupported = True
                    reason_text = (f"unsupported signature algorithm "
                                   f"{sig['algorithm']}")
                    self.findings.append(Finding(
                        INCONCLUSIVE, "UNSUPPORTED_SIGNATURE_ALGORITHM",
                        f"{owner} {type_name} RRSIG tag {sig['key_tag']}: "
                        f"{reason_text}", zone, serial, owner, type_name,
                        sig["key_tag"], [sig_src]))
                else:
                    reason_text = ("no authenticated DNSKEY with this key "
                                   "tag, algorithm and full public key")
                attempts.append({"key_tag": sig["key_tag"],
                                 "algorithm": sig["algorithm"],
                                 "ok": False, "reason": reason_text,
                                 "source": sig_src})
                continue
            if not crypto.algorithm_supported(sig["algorithm"]):
                any_unsupported = True
                self.findings.append(Finding(
                    INCONCLUSIVE, "UNSUPPORTED_SIGNATURE_ALGORITHM",
                    f"{owner} {type_name} RRSIG tag {sig['key_tag']}: "
                    f"unsupported signature algorithm "
                    f"{sig['algorithm']}", zone, serial, owner, type_name,
                    sig["key_tag"], [sig_src]))
                attempts.append({"key_tag": sig["key_tag"],
                                 "algorithm": sig["algorithm"],
                                 "ok": False,
                                 "reason": f"unsupported signature algorithm "
                                           f"{sig['algorithm']}",
                                 "source": sig_src})
                continue
            try:
                ok, reason = crypto.verify_rrsig(
                    sig, owner, rdata_list, rclass, matched_key.pubkey,
                    self.at_time, zone)
            except crypto.UnsupportedAlgorithm:
                any_unsupported = True
                attempts.append({"key_tag": sig["key_tag"],
                                 "algorithm": sig["algorithm"],
                                 "ok": False,
                                 "reason": "unsupported algorithm",
                                 "source": sig_src})
                continue
            attempts.append({"key_tag": sig["key_tag"],
                             "algorithm": sig["algorithm"],
                             "ok": ok, "reason": reason,
                             "source": sig_src})
            if ok:
                any_valid = True
            else:
                level = (INCONCLUSIVE if reason.startswith("unsupported")
                         else FAIL)
                self.findings.append(Finding(
                    level, "RRSIG_INVALID",
                    f"{owner} {type_name} RRSIG tag {sig['key_tag']}: "
                    f"{reason}", zone, serial, owner, type_name,
                    sig["key_tag"], [sig_src, matched_key.source]))

        if any_valid:
            verdict = PASS
            reason = "at least one RRSIG validated with an authenticated key"
        elif any_unsupported and all(
                (not crypto.algorithm_supported(a["algorithm"]))
                or a["reason"].startswith("unsupported")
                for a in attempts):
            verdict = INCONCLUSIVE
            reason = ("all covering signatures use algorithms this verifier "
                      "does not support")
        else:
            verdict = FAIL
            reason = ("no RRSIG over this RRset validates with an "
                      "authenticated DNSKEY at the requested time")
        self._record(base, verdict, attempts, reason)
        return verdict

    @staticmethod
    def _sig_source(sig_recs, sig) -> dict:
        for rec in sig_recs:
            if rec.rdata is sig:
                return _src(rec)
        return {"file": "?", "line": 0}

    def _record(self, base: dict, verdict: str, attempts: list,
                reason: str, extra_finding: Finding | None = None):
        entry = dict(base)
        entry.update({"verdict": verdict, "reason": reason,
                      "signature_attempts": attempts})
        self.rrset_results.append(entry)
        if extra_finding is not None:
            self.findings.append(extra_finding)

    # ------------------------------------------------------------------
    # Zone processing
    # ------------------------------------------------------------------
    def verify_zone(self, zone: str, serial: int,
                    parent_zone: str | None,
                    parent_serial: int | None) -> str:
        """Verify one snapshot, given an already trusted parent zone."""
        zone_verdict = PASS

        # 1. Authenticate the child DNSKEY RRset.
        dnskey_holder = self.store.get_rrset(
            zone, serial, zone, wire.TYPES["DNSKEY"])
        if dnskey_holder is None:
            reason = f"zone {zone} serial {serial} has no apex DNSKEY RRset"
            self.findings.append(Finding(
                INCONCLUSIVE, "NO_DNSKEY", reason, zone, serial, zone,
                "DNSKEY"))
            self._record({"zone": zone, "serial": serial, "owner": zone,
                          "rtype": "DNSKEY", "ttl": None, "member_count": 0,
                          "sources": []}, INCONCLUSIVE, [], reason)
            return INCONCLUSIVE
        dnskey_recs, dnskey_ttl, dnskey_prov = dnskey_holder
        candidate_keys = []
        for rec in dnskey_recs:
            rd = rec.rdata
            tag = wire.key_tag(rd["flags"], rd["protocol"], rd["algorithm"],
                               rd["pubkey"])
            candidate_keys.append({
                "flags": rd["flags"], "protocol": rd["protocol"],
                "algorithm": rd["algorithm"], "pubkey": rd["pubkey"],
                "key_tag": tag, "rec": rec})

        # 2. Establish at least one authenticated key for this zone.
        newly_trusted: list[TrustedKey] = []
        if parent_zone is None:
            # Anchor zone: trust comes from the submitted anchor records.
            newly_trusted = self._anchor_keys(zone, candidate_keys)
            if not newly_trusted:
                reason = ("no trust anchor authenticates any DNSKEY in the "
                          "anchor zone")
                self.findings.append(Finding(
                    FAIL, "ANCHOR_NO_MATCH", reason, zone, serial, zone,
                    "DNSKEY", sources=dnskey_prov))
                self._record({"zone": zone, "serial": serial, "owner": zone,
                              "rtype": "DNSKEY", "ttl": dnskey_ttl,
                              "member_count": len(dnskey_recs),
                              "sources": dnskey_prov}, FAIL, [], reason)
                return FAIL
        else:
            chain = self._ds_chain(parent_zone, parent_serial, zone, serial,
                                   candidate_keys, dnskey_prov)
            if chain is None:
                # Parent material itself could not be decided.
                self._record({"zone": zone, "serial": serial, "owner": zone,
                              "rtype": "DNSKEY", "ttl": dnskey_ttl,
                              "member_count": len(dnskey_recs),
                              "sources": dnskey_prov}, INCONCLUSIVE, [],
                             "trust cannot be established: parent-side "
                             "verification material is missing or uses an "
                             "unsupported algorithm")
                return INCONCLUSIVE
            if not chain:
                self._record({"zone": zone, "serial": serial, "owner": zone,
                              "rtype": "DNSKEY", "ttl": dnskey_ttl,
                              "member_count": len(dnskey_recs),
                              "sources": dnskey_prov}, FAIL, [],
                             "no DS record authenticates any child DNSKEY")
                return FAIL
            newly_trusted = chain

        # 3. The apex DNSKEY RRset itself must carry a valid self-signature by
        #    at least one authenticated key (RFC 4034 2.2).
        dnskey_verdict = self._verify_rrset(
            zone, serial, zone, wire.TYPES["DNSKEY"], wire.CLASS_IN,
            dnskey_ttl, dnskey_recs, dnskey_prov, newly_trusted,
            is_apex_dnskey=True)
        zone_verdict = merge(zone_verdict, dnskey_verdict)
        if dnskey_verdict != PASS:
            # Self-signature failed: only keep keys independently anchored by
            # DS/anchor material, but the zone verdict is already tainted.
            pass
        self.trusted[zone] = newly_trusted

        # 4. Every authoritative RRset, grouped exactly as stored.
        cuts = self.store.delegation_points(zone, serial)
        for owner, rtype, rclass, ttl, recs, prov in self.store.iter_rrsets(
                zone, serial):
            if rtype == wire.TYPES["RRSIG"]:
                continue
            if owner == zone and rtype == wire.TYPES["DNSKEY"]:
                continue  # handled above
            if self._is_glue_or_delegation(zone, owner, rtype, cuts):
                self._record({"zone": zone, "serial": serial, "owner": owner,
                              "rtype": wire.TYPE_NAMES[rtype], "ttl": ttl,
                              "member_count": len(recs), "sources": prov},
                             SKIPPED, [],
                             "skipped: parent-side glue/NS below a zone cut "
                             "is not signed by the parent (RFC 4035); the "
                             "DS RRset at the cut is still verified")
                continue
            verdict = self._verify_rrset(
                zone, serial, owner, rtype, rclass, ttl, recs, prov,
                newly_trusted)
            zone_verdict = merge(zone_verdict, verdict)
        return zone_verdict

    # ------------------------------------------------------------------
    # Trust anchor handling
    # ------------------------------------------------------------------
    def _anchor_keys(self, zone: str, candidate_keys: list[dict]
                     ) -> list[TrustedKey]:
        trusted: list[TrustedKey] = []
        for anchor in self.anchors:
            if anchor["zone"] != zone:
                continue
            if anchor["rtype"] == wire.TYPES["DNSKEY"]:
                for key in candidate_keys:
                    rd = anchor["rdata"]
                    if (key["algorithm"] == rd["algorithm"]
                            and key["pubkey"] == rd["pubkey"]
                            and key["flags"] == rd["flags"]
                            and key["protocol"] == rd["protocol"]):
                        trusted.append(TrustedKey(
                            zone=zone, flags=key["flags"],
                            protocol=key["protocol"],
                            algorithm=key["algorithm"],
                            pubkey=key["pubkey"], key_tag=key["key_tag"],
                            source={"file": anchor["source"], "line": 0},
                            authenticated_in_zone=zone))
            else:  # DS anchor
                for key in candidate_keys:
                    try:
                        ok, _ = crypto.verify_ds_match(
                            anchor["rdata"], zone, key)
                    except crypto.UnsupportedAlgorithm:
                        self.findings.append(Finding(
                            INCONCLUSIVE, "UNSUPPORTED_DS_DIGEST",
                            f"anchor DS uses unsupported digest type "
                            f"{anchor['rdata']['digest_type']}", zone,
                            sources=[{"file": anchor["source"], "line": 0}]))
                        continue
                    if ok:
                        trusted.append(TrustedKey(
                            zone=zone, flags=key["flags"],
                            protocol=key["protocol"],
                            algorithm=key["algorithm"],
                            pubkey=key["pubkey"], key_tag=key["key_tag"],
                            source={"file": anchor["source"], "line": 0},
                            authenticated_in_zone=zone))
        # Deduplicate on full public key.
        return _dedupe_keys(trusted)

    # ------------------------------------------------------------------
    # Parent DS -> child DNSKEY chain
    # ------------------------------------------------------------------
    def _ds_chain(self, parent_zone: str, parent_serial: int,
                  child_zone: str, child_serial: int,
                  candidate_keys: list[dict],
                  child_dnskey_prov: list) -> list[TrustedKey] | None:
        ds_holder = self.store.get_rrset(
            parent_zone, parent_serial, child_zone, wire.TYPES["DS"])
        if ds_holder is None:
            reason = (f"parent zone {parent_zone}={parent_serial} has no DS "
                      f"RRset for delegation {child_zone}")
            self.findings.append(Finding(
                FAIL, "MISSING_DS", reason, parent_zone, parent_serial,
                child_zone, "DS"))
            self._record({"zone": child_zone, "serial": child_serial,
                          "owner": child_zone, "rtype": "DS", "ttl": None,
                          "member_count": 0,
                          "sources": [self.store.snapshot_meta(
                              parent_zone, parent_serial)]},
                         FAIL, [], reason)
            return []

        ds_recs, ds_ttl, ds_prov = ds_holder
        # The parent's DS RRset must itself validate under parent's keys.
        parent_keys = self.trusted.get(parent_zone, [])
        if not parent_keys:
            self.findings.append(Finding(
                INCONCLUSIVE, "PARENT_UNTRUSTED",
                f"no authenticated keys available for parent {parent_zone}",
                parent_zone, parent_serial))
            return None
        ds_verdict = self._verify_rrset(
            parent_zone, parent_serial, child_zone, wire.TYPES["DS"],
            wire.CLASS_IN, ds_ttl, ds_recs, ds_prov, parent_keys)
        if ds_verdict == INCONCLUSIVE:
            return None
        if ds_verdict != PASS:
            return []

        trusted: list[TrustedKey] = []
        unsupported_digest = False
        tag_alg_matched = False
        for ds_rec in ds_recs:
            ds = ds_rec.rdata
            for key in candidate_keys:
                if ds["algorithm"] != key["algorithm"]:
                    continue
                if ds["key_tag"] != key["key_tag"]:
                    continue
                tag_alg_matched = True
                try:
                    ok, reason = crypto.verify_ds_match(ds, child_zone, key)
                except crypto.UnsupportedAlgorithm:
                    unsupported_digest = True
                    self.findings.append(Finding(
                        INCONCLUSIVE, "UNSUPPORTED_DS_DIGEST",
                        f"DS at {child_zone} uses unsupported digest type "
                        f"{ds['digest_type']}", parent_zone, parent_serial,
                        child_zone, "DS", ds["key_tag"], [_src(ds_rec)]))
                    continue
                if ok:
                    trusted.append(TrustedKey(
                        zone=child_zone, flags=key["flags"],
                        protocol=key["protocol"],
                        algorithm=key["algorithm"], pubkey=key["pubkey"],
                        key_tag=key["key_tag"], source=_src(ds_rec),
                        authenticated_in_zone=parent_zone))
                else:
                    self.findings.append(Finding(
                        FAIL, "DS_DIGEST_MISMATCH",
                        f"DS tag {ds['key_tag']} alg {ds['algorithm']} at "
                        f"{child_zone} does not digest the matching DNSKEY "
                        f"wire data ({reason})", parent_zone, parent_serial,
                        child_zone, "DS", ds["key_tag"],
                        [_src(ds_rec), _src(key["rec"])]))
        trusted = _dedupe_keys(trusted)
        if trusted:
            return trusted
        if not tag_alg_matched:
            # No DS references any present key at all.
            if unsupported_digest:
                return None
            self.findings.append(Finding(
                FAIL, "DS_NO_KEY_TAG_MATCH",
                f"no DNSKEY in {child_zone}={child_serial} shares key tag "
                f"and algorithm with an authenticated DS record",
                parent_zone, parent_serial, child_zone, "DS",
                sources=ds_prov + child_dnskey_prov))
            return []
        if unsupported_digest:
            return None
        # Tag+alg matched but every full digest failed -> explicit tamper.
        self.findings.append(Finding(
            FAIL, "CHAIN_NO_MATCHING_KEY",
            f"no DNSKEY in {child_zone}={child_serial} matches any "
            f"authenticated DS record (digest mismatch)", parent_zone,
            parent_serial, child_zone, "DS",
            sources=ds_prov + child_dnskey_prov))
        return []

    def _is_glue_or_delegation(self, zone: str, owner: str, rtype: int,
                               cuts: set[str]) -> bool:
        for cut in cuts:
            if owner == cut and rtype in (wire.TYPES["NS"],):
                return True
            if (wire.is_subdomain(owner, cut)
                    and rtype in (wire.TYPES["A"], wire.TYPES["AAAA"])):
                return True
        return False


def _dedupe_keys(keys: list[TrustedKey]) -> list[TrustedKey]:
    seen: set[bytes] = set()
    out: list[TrustedKey] = []
    for key in keys:
        marker = bytes([key.algorithm]) + key.pubkey
        if marker in seen:
            continue
        seen.add(marker)
        out.append(key)
    return out
