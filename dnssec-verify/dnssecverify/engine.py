"""End-to-end verification orchestration and deterministic reporting."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass

from . import verifier as vmod, wire
from .store import SnapshotStore, _encode_rdata
from .verifier import FAIL, INCONCLUSIVE, PASS, Verifier, merge
from .zonefile import load_trust_anchor


class ManifestError(Exception):
    pass


@dataclass
class Target:
    zone: str
    serial: int


def load_manifest(path: str) -> tuple[list[Target], int]:
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict):
        raise ManifestError("manifest must be a JSON object")
    at = doc.get("verification_time_utc")
    if not isinstance(at, str):
        raise ManifestError("manifest needs 'verification_time_utc'")
    at_time = _parse_utc(at)
    raw = doc.get("snapshots")
    if not isinstance(raw, list) or not raw:
        raise ManifestError("manifest needs a non-empty 'snapshots' list")
    targets: list[Target] = []
    seen: set[tuple[str, int]] = set()
    for i, item in enumerate(raw):
        if not isinstance(item, dict) or "zone" not in item or "serial" not in item:
            raise ManifestError(f"snapshots[{i}] needs 'zone' and 'serial'")
        zone = wire.name_to_text(None, item["zone"])
        serial = int(item["serial"])
        key = (zone, serial)
        if key in seen:
            raise ManifestError(
                f"snapshots[{i}]: duplicate entry for {zone}={serial}")
        seen.add(key)
        targets.append(Target(zone, serial))
    return targets, at_time


def _parse_utc(text: str) -> int:
    import calendar
    import datetime
    t = text.strip()
    if t.endswith("Z"):
        t = t[:-1] + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(t)
    except ValueError as exc:
        raise ManifestError(f"bad UTC timestamp {text!r}: {exc}") from exc
    if dt.tzinfo is None:
        raise ManifestError(
            f"timestamp {text!r} must carry a UTC offset (use Z or +00:00)")
    return calendar.timegm(dt.utctimetuple())


def check_anchors(anchor_doc: dict) -> list[dict]:
    """Reject duplicate or mutually conflicting trust anchors.

    Exact duplicates (same zone + identical record) are rejected with their
    positions.  Two anchors of different types on the same zone are also a
    conflict.  Multiple distinct DS records on one zone are legal (rollover).
    """
    errors = []
    by_zone: dict[str, list[dict]] = {}
    exact: dict[tuple, list[str]] = {}
    for anchor in anchor_doc["anchors"]:
        by_zone.setdefault(anchor["zone"], []).append(anchor)
        sig = (anchor["zone"], anchor["rtype"],
               json.dumps(_encode_rdata(anchor["rdata"]), sort_keys=True))
        exact.setdefault(sig, []).append(anchor["source"])
    for sig, locations in exact.items():
        if len(locations) > 1:
            errors.append({
                "code": "DUPLICATE_ANCHOR",
                "message": f"duplicate trust anchor for {sig[0]} "
                           f"({wire.TYPE_NAMES[sig[1]]})",
                "locations": locations,
            })
    for zone, anchors in by_zone.items():
        kinds = {a["rtype"] for a in anchors}
        if len(kinds) > 1:
            errors.append({
                "code": "CONFLICTING_ANCHOR_TYPES",
                "message": f"zone {zone} has both DS and DNSKEY trust "
                           f"anchors; submit exactly one anchor form",
                "locations": [a["source"] for a in anchors],
            })
    return errors


def _zone_depth(name: str) -> int:
    return wire.name_labels(name)


def _chain_order(targets: list[Target]) -> list[Target]:
    """Order snapshots from the trust-anchor apex toward leaf zones."""
    return sorted(targets, key=lambda t: (_zone_depth(t.zone), t.zone,
                                         t.serial))


def _parent_target(targets: list[Target], zone: str) -> Target | None:
    """Nearest ancestor present in the manifest (may skip missing zones)."""
    labels = wire.split_labels(zone)
    for i in range(1, len(labels)):
        parent = ".".join(labels[i:]) + "."
        for t in targets:
            if t.zone == parent:
                return t
    return None


def _immediate_parent_target(targets: list[Target],
                             zone: str) -> Target | None:
    """The direct parent zone, only if its snapshot is in the manifest.

    Chain continuity is defined on the immediate delegation parent, not on
    any higher ancestor, so a missing intermediate zone must be detected.
    """
    labels = wire.split_labels(zone)
    if len(labels) < 2:
        return None
    parent = ".".join(labels[1:]) + "."
    for t in targets:
        if t.zone == parent:
            return t
    return None


def preflight(store: SnapshotStore, targets: list[Target],
              anchor_doc: dict) -> tuple[list[dict], list[dict]]:
    """Checks that must settle before verification starts.

    Returns ``(rejections, broken_chains)``.  A *rejection* (missing serial,
    anchor zone absent from the manifest) aborts the whole run and never
    produces a partial PASS.  A *broken chain* is a recoverable condition:
    the reachable part of the tree still verifies and the cut-off zone is
    reported INCONCLUSIVE rather than as tampered data.
    """
    errors = []
    broken = []
    # Every requested serial must exist.
    for t in targets:
        if not store.snapshot_exists(t.zone, t.serial):
            errors.append({
                "code": "MISSING_SNAPSHOT",
                "message": f"no stored snapshot for {t.zone}={t.serial}",
                "zone": t.zone, "serial": t.serial,
            })
    # Anchors reference a zone that is part of the manifest.
    anchor_zones = {a["zone"] for a in anchor_doc["anchors"]}
    target_zones = {t.zone for t in targets}
    for zone in sorted(anchor_zones - target_zones):
        errors.append({
            "code": "ANCHOR_ZONE_NOT_IN_MANIFEST",
            "message": f"trust anchor zone {zone} has no matching snapshot "
                       f"in the manifest",
            "zone": zone,
        })
    # Continuity: every non-anchor zone needs its *immediate* delegation
    # parent snapshot present; a missing intermediate is INCONCLUSIVE.
    for t in targets:
        if t.zone in anchor_zones:
            continue
        parent = _immediate_parent_target(targets, t.zone)
        if parent is None:
            broken.append({
                "code": "BROKEN_CHAIN",
                "message": f"no ancestor snapshot exists between the trust "
                           f"anchor and {t.zone}",
                "zone": t.zone, "serial": t.serial,
            })
    return errors, broken


def run(store: SnapshotStore, anchor_path: str, manifest_path: str) -> dict:
    anchor_doc = load_trust_anchor(anchor_path)
    targets, at_time = load_manifest(manifest_path)

    anchor_errors = check_anchors(anchor_doc)
    flight_errors, broken_chains = preflight(store, targets, anchor_doc)
    if anchor_errors or flight_errors:
        return {
            "status": "REJECTED",
            "verification_time_utc": _iso(at_time),
            "rejections": anchor_errors + flight_errors,
            "zones": [], "rrset_results": [], "findings": [],
            "overall_verdict": None,
        }

    ver = Verifier(store, anchor_doc["anchors"], at_time)
    ordered = _chain_order(targets)
    broken_zones = {b["zone"] for b in broken_chains}
    for b in broken_chains:
        ver.findings.append(vmod.Finding(
            INCONCLUSIVE, "BROKEN_CHAIN", b["message"], b["zone"],
            b["serial"]))
    zone_verdicts: dict[str, str] = {}
    zone_reports: list[dict] = []

    for t in ordered:
        parent = _immediate_parent_target(ordered, t.zone)
        is_anchor = t.zone in {a["zone"] for a in anchor_doc["anchors"]}
        if t.zone in broken_zones or (
                parent is None and not is_anchor):
            # No ancestor snapshot in the manifest: cannot decide, never FAIL.
            zone_verdicts[t.zone] = INCONCLUSIVE
            ver.rrset_results.append({
                "zone": t.zone, "serial": t.serial, "owner": t.zone,
                "rtype": "DNSKEY", "ttl": None, "member_count": 0,
                "sources": [], "verdict": INCONCLUSIVE,
                "reason": "missing intermediate ancestor snapshot; the chain "
                          "cannot be evaluated",
                "signature_attempts": []})
            continue
        p_zone = parent.zone if parent else None
        p_serial = parent.serial if parent else None
        if p_zone is not None and zone_verdicts.get(p_zone) in (
                FAIL, INCONCLUSIVE):
            verdict = INCONCLUSIVE
            ver.findings.append(vmod.Finding(
                INCONCLUSIVE, "ANCESTOR_NOT_TRUSTED",
                f"ancestor {p_zone} verdict is "
                f"{zone_verdicts[p_zone]}; {t.zone} cannot be evaluated",
                t.zone, t.serial))
            ver.rrset_results.append({
                "zone": t.zone, "serial": t.serial, "owner": t.zone,
                "rtype": "DNSKEY", "ttl": None, "member_count": 0,
                "sources": [], "verdict": INCONCLUSIVE,
                "reason": f"ancestor {p_zone} is not trusted",
                "signature_attempts": []})
        else:
            verdict = ver.verify_zone(t.zone, t.serial, p_zone, p_serial)
        zone_verdicts[t.zone] = verdict

    for t in ordered:
        rrsets = [r for r in ver.rrset_results if r["zone"] == t.zone]
        zone_reports.append({
            "zone": t.zone, "serial": t.serial,
            "verdict": zone_verdicts[t.zone],
            "rrset_count": len(rrsets),
            "rrset_verdicts": {
                PASS: sum(1 for r in rrsets if r["verdict"] == PASS),
                FAIL: sum(1 for r in rrsets if r["verdict"] == FAIL),
                INCONCLUSIVE: sum(
                    1 for r in rrsets if r["verdict"] == INCONCLUSIVE),
                "SKIPPED": sum(
                    1 for r in rrsets if r["verdict"] == "SKIPPED"),
            },
        })

    overall = PASS
    for verdict in zone_verdicts.values():
        overall = merge(overall, verdict)

    return {
        "status": "OK",
        "verification_time_utc": _iso(at_time),
        "overall_verdict": overall,
        "zones": zone_reports,
        "rrset_results": sorted(
            ver.rrset_results,
            key=lambda r: (r["zone"], r["owner"],
                           wire.TYPES[r["rtype"]] if r["rtype"] in wire.TYPES
                           else 0, r["serial"])),
        "findings": sorted(
            (f.as_dict() for f in ver.findings),
            key=lambda d: (d.get("zone", ""), d.get("owner", ""),
                           d.get("code", ""), str(d.get("sources", "")))),
    }


def _iso(epoch: int) -> str:
    import datetime
    return (datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%SZ"))


def atomic_write_report(path: str, payload: dict) -> None:
    """Write the report atomically; refuse to overwrite an existing one."""
    if os.path.exists(path):
        raise FileExistsError(f"report already exists: {path}")
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    tmp = os.path.join(directory, f".{os.path.basename(path)}.tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
