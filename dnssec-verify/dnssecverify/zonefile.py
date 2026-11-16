"""Parser for signed zone snapshot files (RFC 1035 master-file syntax).

Every emitted record carries its source file and 1-based line number so the
verifier can cite exact provenance in reports.  Only the DNSSEC-relevant
directives ``$ORIGIN`` and ``$TTL`` are honoured.
"""
from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass

from . import wire


class ZoneFileError(Exception):
    """Raised with file path and line number on malformed input."""


@dataclass
class RawRecord:
    zone: str
    serial: int
    owner: str
    rtype: int
    rclass: int
    ttl: int
    rdata: dict
    source_file: str
    source_line: int

    def key(self) -> tuple:
        return (self.owner, self.rtype, self.rclass)


def _as_int_ttl(token: str) -> int:
    upper = token.upper()
    if upper.isdigit():
        return int(upper)
    units = {"S": 1, "M": 60, "H": 3600, "D": 86400, "W": 604800}
    total = 0
    num = ""
    for ch in upper:
        if ch.isdigit():
            num += ch
        elif ch in units and num:
            total += int(num) * units[ch]
            num = ""
        else:
            raise ZoneFileError(f"invalid TTL {token!r}")
    if num:
        total += int(num)
    return total


def _looks_like_ttl(token: str) -> bool:
    if not token:
        return False
    num = ""
    for ch in token.upper():
        if ch.isdigit():
            num += ch
        elif ch in "SMHDW" and num:
            num = ""
        else:
            return False
    return True


def parse_zone_file(path: str, declared_zone: str | None = None,
                    declared_serial: int | None = None):
    """Parse one snapshot file into ``(header, records)``.

    The apex SOA must exist; its serial is the snapshot serial unless an
    explicit serial was declared.
    """
    source = os.path.abspath(path)
    origin = (wire.name_to_text(None, declared_zone)
              if declared_zone else None)
    default_ttl: int | None = None
    records: list[RawRecord] = []
    last_owner: str | None = None
    serial: int | None = declared_serial

    logical_parts: list[str] = []
    start_lineno = 0
    depth = 0

    def finalize(lineno: int):
        nonlocal last_owner, serial
        text = " ".join(logical_parts)
        logical_parts.clear()
        tokens = wire.tokenize_line(text)
        if not tokens:
            return
        rec = _parse_record(tokens, origin, default_ttl, last_owner, source,
                            start_lineno)
        last_owner = rec.owner
        if rec.rtype == wire.TYPES["SOA"]:
            if rec.owner != origin:
                raise ZoneFileError(
                    f"{source}:{lineno}: SOA owner {rec.owner} is not the "
                    f"zone apex {origin}")
            soa_serial = rec.rdata["serial"]
            if serial is None:
                serial = soa_serial
            elif serial != soa_serial:
                raise ZoneFileError(
                    f"{source}:{lineno}: SOA serial {soa_serial} does not "
                    f"match declared serial {serial}")
        records.append(rec)

    with open(source, "r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            stripped = raw.strip()
            if depth == 0 and (not stripped or stripped.startswith(";")):
                continue
            if depth == 0 and stripped.upper().startswith("$"):
                directive = wire.tokenize_line(stripped)
                name = directive[0].upper()
                if name == "$ORIGIN":
                    if len(directive) != 2:
                        raise ZoneFileError(
                            f"{source}:{lineno}: $ORIGIN needs one name")
                    origin = wire.name_to_text(origin, directive[1])
                elif name == "$TTL":
                    if len(directive) != 2:
                        raise ZoneFileError(
                            f"{source}:{lineno}: $TTL needs one value")
                    default_ttl = _as_int_ttl(directive[1])
                else:
                    raise ZoneFileError(
                        f"{source}:{lineno}: unsupported directive {name}")
                continue

            depth += raw.count("(") - raw.count(")")
            if depth < 0:
                raise ZoneFileError(f"{source}:{lineno}: unmatched ')'")
            if not logical_parts:
                start_lineno = lineno
            logical_parts.append(stripped)
            if depth == 0:
                finalize(lineno)

    if depth != 0:
        raise ZoneFileError(f"{source}: unclosed parenthesis at EOF")
    if origin is None:
        raise ZoneFileError(
            f"{source}: no $ORIGIN directive and no declared zone")
    if not records:
        raise ZoneFileError(f"{source}: contains no records")
    if serial is None:
        raise ZoneFileError(f"{source}: snapshot has no SOA serial")

    for rec in records:
        rec.zone = origin
        rec.serial = serial
        if rec.rclass != wire.CLASS_IN:
            raise ZoneFileError(
                f"{rec.source_file}:{rec.source_line}: only class IN "
                f"snapshots are supported")
    header = {"zone": origin, "serial": serial,
              "default_ttl": default_ttl, "source": source}
    return header, records


def _parse_record(tokens: list[str], origin: str | None,
                  default_ttl: int | None, last_owner: str | None,
                  source: str, lineno: int) -> RawRecord:
    idx = 0
    owner: str | None = None
    ttl: int | None = None
    rclass: int | None = None
    rtype: int | None = None

    # RFC 1035 5.1: owner, TTL, class and type may appear in any order.
    while idx < len(tokens):
        tok = tokens[idx]
        upper = tok.upper()
        if upper in wire.TYPES:
            rtype = wire.TYPES[upper]
            idx += 1
            break
        if upper in wire.CLASSES:
            if rclass is not None:
                raise ZoneFileError(
                    f"{source}:{lineno}: duplicate class field")
            rclass = wire.CLASSES[upper]
            idx += 1
            continue
        if tok.isdigit() or _looks_like_ttl(tok):
            if ttl is not None:
                raise ZoneFileError(
                    f"{source}:{lineno}: duplicate TTL field")
            ttl = _as_int_ttl(tok)
            idx += 1
            continue
        if owner is None:
            owner = wire.name_to_text(origin, tok)
            idx += 1
            continue
        raise ZoneFileError(
            f"{source}:{lineno}: unexpected token {tok!r} before RR type")

    if rtype is None:
        raise ZoneFileError(f"{source}:{lineno}: record missing RR type")
    if rclass is None:
        rclass = wire.CLASS_IN
    if ttl is None:
        if default_ttl is None:
            raise ZoneFileError(
                f"{source}:{lineno}: no explicit TTL and no $TTL in effect")
        ttl = default_ttl
    if owner is None:
        owner = last_owner
    if owner is None:
        raise ZoneFileError(f"{source}:{lineno}: record has no owner name")
    if idx >= len(tokens):
        raise ZoneFileError(
            f"{source}:{lineno}: record is missing RDATA")

    try:
        rdata = wire.parse_rdata(rtype, tokens[idx:], origin)
    except wire.WireError as exc:
        raise ZoneFileError(f"{source}:{lineno}: {exc}") from exc
    return RawRecord(zone="", serial=0, owner=owner, rtype=rtype,
                     rclass=rclass, ttl=ttl, rdata=rdata,
                     source_file=source, source_line=lineno)


def load_trust_anchor(path: str) -> dict:
    """Load and validate a trust-anchor JSON document.

    Structure::

        {"anchors": [
          {"zone": "example.",
           "record": {"type": "DS", "key_tag": 1234, "algorithm": 8,
                      "digest_type": 2, "digest": "<hex>"},
           "source": "optional provenance note"},
          {"zone": "example.",
           "record": {"type": "DNSKEY", "flags": 257, "protocol": 3,
                      "algorithm": 13, "pubkey": "<base64>"}}]}
    """
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict) or not isinstance(doc.get("anchors"), list):
        raise ZoneFileError(
            f"{path}: trust anchor file needs an 'anchors' list")
    if not doc["anchors"]:
        raise ZoneFileError(f"{path}: trust anchor file has no anchors")
    anchors = []
    for i, entry in enumerate(doc["anchors"]):
        if (not isinstance(entry, dict) or "zone" not in entry
                or "record" not in entry):
            raise ZoneFileError(
                f"{path}: anchors[{i}] needs 'zone' and 'record'")
        zone = wire.name_to_text(None, entry["zone"])
        rec = entry["record"]
        rtype = str(rec.get("type", "")).upper()
        if rtype == "DS":
            rdata = {
                "key_tag": int(rec["key_tag"]),
                "algorithm": int(rec["algorithm"]),
                "digest_type": int(rec["digest_type"]),
                "digest": bytes.fromhex(rec["digest"]),
            }
        elif rtype == "DNSKEY":
            if "pubkey_hex" in rec:
                pubkey = bytes.fromhex(rec["pubkey_hex"])
            else:
                pubkey = base64.b64decode(rec["pubkey"])
            rdata = {
                "flags": int(rec["flags"]),
                "protocol": int(rec["protocol"]),
                "algorithm": int(rec["algorithm"]),
                "pubkey": pubkey,
            }
        else:
            raise ZoneFileError(
                f"{path}: anchors[{i}] record type must be DS or DNSKEY")
        anchors.append({
            "zone": zone, "rtype": wire.TYPES[rtype], "rdata": rdata,
            "source": str(entry.get("source", f"{path}#anchors[{i}]")),
            "index": i,
        })
    return {"path": os.path.abspath(path), "anchors": anchors}
