"""Independent brute-force reference for CT observation import.

This deliberately shares no code with ``dnsrepo.ct`` other than the zone
boundary predicate.  It normalizes names by splitting, lowercasing and
encoding each label, then folds everything into plain Python dicts and
sorts at the end.  It enumerates the same rules naively (no SQL, no
streaming) and is only usable for tiny hand-checkable inputs.
"""

from dnsrepo.names import in_zone


def normalize(raw):
    """Naive canonical form; raises ValueError for anything invalid."""
    if not isinstance(raw, str) or raw == "":
        raise ValueError("empty")
    body = raw[:-1] if raw.endswith(".") else raw
    if body == "":
        raise ValueError("empty label")
    out = []
    for position, label in enumerate(body.split(".")):
        if label == "":
            raise ValueError("empty label")
        if label == "*":
            if position != 0 or out.count("*"):
                raise ValueError("bad wildcard")
            if len(body.split(".")) == 1:
                raise ValueError("empty label")
            out.append("*")
        elif label.isascii():
            lowered = label.lower()
            if len(lowered) > 63:
                raise ValueError("label too long")
            if lowered.startswith("xn--"):
                decoded = lowered.encode("ascii").decode("idna")
                if decoded.encode("idna").decode("ascii") != lowered:
                    raise ValueError("bad A-label")
            elif any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789-_"
                     for ch in lowered):
                raise ValueError("bad character")
            out.append(lowered)
        else:
            encoded = label.lower().encode("idna").decode("ascii")
            if not encoded or len(encoded) > 63:
                raise ValueError("label too long")
            if encoded.startswith("xn--"):
                if any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789-"
                       for ch in encoded) or len(encoded) == 4:
                    raise ValueError("bad A-label")
            elif any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789-_"
                     for ch in encoded):
                raise ValueError("bad character")
            out.append(encoded)
    name = ".".join(out) + "."
    if len(name) - 1 > 253:
        raise ValueError("too long")
    return name


def import_reference(rows, zone, existing):
    """Return ``(findings, stats)`` computed with plain dicts.

    *rows* are already-validated observation dicts with normalized-
    friendly fields; *existing* is the set of owner names in the pinned
    version.
    """
    observations = {}
    duplicates = 0
    names_by_key = {}
    for row in rows:
        names = sorted({normalize(name) for name in row["dns_names"]})
        key = (row["source"], row["certificate_sha256"].lower(),
               row["observed_at_ms"])
        if key in names_by_key:
            if names_by_key[key] != names:
                raise ValueError("conflict")
            duplicates += 1
            continue
        names_by_key[key] = names
        observations[key] = names

    findings = {}
    excluded = {"out_of_zone": 0, "zone_apex": 0, "existing": 0}
    for (source, cert, observed_at), names in observations.items():
        for name in names:
            if name == zone:
                excluded["zone_apex"] += 1
                continue
            if not in_zone(name, zone):
                excluded["out_of_zone"] += 1
                continue
            if name in existing:
                excluded["existing"] += 1
                continue
            entry = findings.setdefault(name, {
                "name": name,
                "wildcard": name.startswith("*."),
                "first": observed_at,
                "last": observed_at,
                "certs": set(),
                "sources": set(),
                "evidence": {},
            })
            entry["first"] = min(entry["first"], observed_at)
            entry["last"] = max(entry["last"], observed_at)
            entry["certs"].add(cert)
            entry["sources"].add(source)
            ev = entry["evidence"].setdefault((source, cert),
                                              [observed_at, observed_at, 0])
            ev[0] = min(ev[0], observed_at)
            ev[1] = max(ev[1], observed_at)
            ev[2] += 1

    result = []
    for name in sorted(findings):
        entry = findings[name]
        result.append({
            "name": name,
            "wildcard": entry["wildcard"],
            "first_observed_at_ms": entry["first"],
            "last_observed_at_ms": entry["last"],
            "certificate_count": len(entry["certs"]),
            "certificates": sorted(entry["certs"]),
            "sources": sorted(entry["sources"]),
            "evidence": [
                {"source": source, "certificate_sha256": cert,
                 "first_observed_at_ms": ev[0],
                 "last_observed_at_ms": ev[1],
                 "observations": ev[2]}
                for (source, cert), ev in sorted(entry["evidence"].items())
            ],
        })
    stats = {
        "observations": len(observations),
        "duplicates": duplicates,
        "excluded": excluded,
        "sources": sorted({key[0] for key in observations}),
    }
    return result, stats
