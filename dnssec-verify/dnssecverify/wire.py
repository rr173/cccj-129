"""DNS wire format, canonical name forms and RDATA parsing/serialization.

This module is self-contained: it only uses the Python standard library.
All names are stored as text (Fully Qualified, trailing dot) and lower-cased
for canonical comparisons.  RDATA is parsed once into structured Python
objects so that canonical wire encoding never depends on presentation text.
"""
from __future__ import annotations

import base64
import ipaddress
import struct

# --------------------------------------------------------------------------
# Common constants
# --------------------------------------------------------------------------
CLASS_IN = 1
CLASS_ANY = 255
CLASSES = {"IN": CLASS_IN, "ANY": CLASS_ANY}

TYPES = {
    "A": 1, "NS": 2, "SOA": 6, "CNAME": 5, "PTR": 12, "HINFO": 13,
    "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "DS": 43, "RRSIG": 46,
    "NSEC": 47, "DNSKEY": 48, "NSEC3": 50, "NSEC3PARAM": 51,
    "DNAME": 39, "CAA": 257, "TLSA": 52, "HIP": 55, "NAPTR": 35,
}
TYPE_NAMES = {v: k for k, v in TYPES.items()}

# RFC 8624 / RFC 9276 algorithm numbers used by DNSKEY, RRSIG and DS.
SIG_ALGS = {
    5: ("RSASHA1", "rsa", "sha1"),
    7: ("RSASHA1-NSEC3-SHA1", "rsa", "sha1"),
    8: ("RSASHA256", "rsa", "sha256"),
    10: ("RSASHA512", "rsa", "sha512"),
    13: ("ECDSAP256SHA256", "ec", "sha256"),
    14: ("ECDSAP384SHA384", "ec", "sha384"),
    15: ("ED25519", "ed25519", "ed25519"),
    16: ("ED448", "ed448", "ed448"),
}
DIGEST_ALGS = {1: ("SHA-1", "sha1"), 2: ("SHA-256", "sha256"),
               3: ("SHA-384", "sha384"), 4: ("SHA-512", "sha512")}
HASH_ALIASES = {"sha1": "sha1", "sha256": "sha256",
                "sha384": "sha384", "sha512": "sha512"}
NSEC3_FLAGS_OPTOUT = 1


class WireError(ValueError):
    """Raised on malformed presentation text or wire data."""


# --------------------------------------------------------------------------
# Names
# --------------------------------------------------------------------------
def name_to_text(origin_text: str | None, name: str) -> str:
    """Resolve a possibly-relative owner name against an origin.

    ``@`` means the origin itself; a trailing dot marks an FQDN.
    Returned names are always FQDN text with a trailing dot.
    """
    if name == "@":
        if origin_text is None:
            raise WireError("'@' used without an origin")
        return origin_text.lower()
    if name.endswith("."):
        return name.lower()
    if origin_text is None:
        raise WireError(f"relative name {name!r} without an origin")
    if origin_text == ".":
        return (name + ".").lower()
    return (name + "." + origin_text).lower()


def split_labels(name: str) -> list[str]:
    if name == ".":
        return []
    return [lab for lab in name.lower().split(".") if lab]


def encode_name(name: str) -> bytes:
    """Encode a (canonical, lower-case) name in uncompressed wire form."""
    out = bytearray()
    for label in split_labels(name):
        lab = label.encode("ascii") if label.isascii() else label.encode("utf-8")
        if len(lab) > 63:
            raise WireError(f"label too long: {label!r}")
        out.append(len(lab))
        out += lab
    out.append(0)
    return bytes(out)


def canonical_name(name: str) -> str:
    """RFC 4034 section 6.2 canonical name (lower-case, FQDN text)."""
    return name.lower()


def name_labels(name: str) -> int:
    return len(split_labels(name))


def is_subdomain(child: str, parent: str) -> bool:
    cl, pl = split_labels(child), split_labels(parent)
    return len(cl) >= len(pl) and cl[-len(pl):] == pl if pl else True


def common_suffix_zone(name: str, zone: str) -> bool:
    return is_subdomain(name, zone)


# --------------------------------------------------------------------------
# Tokenizer for zone presentation text (RFC 1035 section 5.1)
# --------------------------------------------------------------------------
def tokenize_line(line: str) -> list[str]:
    """Split one physical line into RR tokens.

    Handles quoted strings and comments.  Parentheses are only meaningful as
    line-continuation markers at whitespace boundaries; they are stripped but
    must not break an unquoted token (base64 DNSKEY/RRSIG data may contain
    characters adjacent to them in hand-written files).
    """
    tokens: list[str] = []
    buf = ""
    in_quotes = False
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if in_quotes:
            if ch == '"':
                tokens.append(buf)
                buf = ""
                in_quotes = False
            elif ch == "\\":
                i += 1
                if i < n:
                    buf += line[i]
            else:
                buf += ch
            i += 1
            continue
        if ch == ";":
            break
        if ch == '"':
            if buf:
                tokens.append(buf)
                buf = ""
            in_quotes = True
        elif ch in " \t":
            if buf:
                tokens.append(buf)
                buf = ""
        elif ch in "()":
            # Continuation marker: terminate a pending token but stand alone.
            if buf:
                tokens.append(buf)
                buf = ""
        else:
            buf += ch
        i += 1
    if in_quotes:
        raise WireError("unterminated quoted string")
    if buf:
        tokens.append(buf)
    return tokens


# --------------------------------------------------------------------------
# Low-level encoders
# --------------------------------------------------------------------------
def encode_character_string(value: str) -> bytes:
    data = value.encode("utf-8")
    if len(data) > 255:
        raise WireError("character-string too long")
    return bytes([len(data)]) + data


def encode_u16(value: int) -> bytes:
    if not 0 <= value <= 0xFFFF:
        raise WireError(f"uint16 out of range: {value}")
    return struct.pack("!H", value)


def encode_u32(value: int) -> bytes:
    return struct.pack("!I", value & 0xFFFFFFFF)


def encode_u8(value: int) -> bytes:
    return bytes([value])


def encode_nsec_bitmap(types: list[int]) -> bytes:
    """Encode an NSEC/NSEC3 type bitmap per RFC 4034 section 4.1.2."""
    tset = sorted(set(types))
    if not tset:
        return b""
    windows: dict[int, bytearray] = {}
    for t in tset:
        win, bit = divmod(t, 256)
        if win not in windows:
            windows[win] = bytearray(32)
        windows[win][bit // 8] |= 1 << (7 - bit % 8)
    out = bytearray()
    for win in sorted(windows):
        bm = windows[win]
        last = max(i for i, b in enumerate(bm) if b)
        out.append(win)
        out.append(last + 1)
        out += bm[: last + 1]
    return bytes(out)


def decode_nsec_bitmap(data: bytes) -> list[int]:
    types: list[int] = []
    i = 0
    while i < len(data):
        win = data[i]
        length = data[i + 1]
        if length < 1 or length > 32 or i + 2 + length > len(data):
            raise WireError("bad NSEC type bitmap")
        for off in range(length):
            byte = data[i + 2 + off]
            for bit in range(8):
                if byte & (1 << (7 - bit)):
                    types.append(win * 256 + off * 8 + bit)
        i += 2 + length
    return types


def b64(token: str) -> bytes:
    s = token.replace(" ", "").replace("\t", "")
    try:
        return base64.b64decode(s, validate=True)
    except Exception as exc:  # pragma: no cover - defensive
        raise WireError(f"bad base64: {exc}") from exc


def b16(token: str) -> bytes:
    s = token.strip()
    if s == "-":
        return b""
    try:
        return bytes.fromhex(s)
    except ValueError as exc:
        raise WireError(f"bad hex: {exc}") from exc


# --------------------------------------------------------------------------
# RDATA parsing into structured objects and canonical wire encoding
# --------------------------------------------------------------------------
def _parse_name_field(tok: str, origin: str | None) -> str:
    return name_to_text(origin, tok)


def parse_rdata(rtype: int, tokens: list[str], origin: str | None) -> dict:
    """Parse presentation-form RDATA into a type-specific structure."""
    if rtype == TYPES["A"]:
        ipaddress.IPv4Address(tokens[0])
        return {"address": tokens[0]}
    if rtype == TYPES["AAAA"]:
        ipaddress.IPv6Address(tokens[0])
        return {"address": tokens[0]}
    if rtype in (TYPES["NS"], TYPES["CNAME"], TYPES["PTR"], TYPES["DNAME"]):
        return {"target": _parse_name_field(tokens[0], origin)}
    if rtype == TYPES["SOA"]:
        if len(tokens) != 7:
            raise WireError("SOA needs 7 fields")
        return {
            "mname": _parse_name_field(tokens[0], origin),
            "rname": _parse_name_field(tokens[1], origin),
            "serial": int(tokens[2]), "refresh": int(tokens[3]),
            "retry": int(tokens[4]), "expire": int(tokens[5]),
            "minimum": int(tokens[6]),
        }
    if rtype == TYPES["MX"]:
        return {"preference": int(tokens[0]),
                "exchange": _parse_name_field(tokens[1], origin)}
    if rtype == TYPES["SRV"]:
        return {"priority": int(tokens[0]), "weight": int(tokens[1]),
                "port": int(tokens[2]),
                "target": _parse_name_field(tokens[3], origin)}
    if rtype == TYPES["TXT"]:
        return {"strings": list(tokens)}
    if rtype == TYPES["HINFO"]:
        if len(tokens) != 2:
            raise WireError("HINFO needs 2 character-strings")
        return {"cpu": tokens[0], "os": tokens[1]}
    if rtype == TYPES["CAA"]:
        flags = int(tokens[0])
        tag = tokens[1]
        value = tokens[2]
        return {"flags": flags, "tag": tag, "value": value}
    if rtype == TYPES["TLSA"]:
        return {"usage": int(tokens[0]), "selector": int(tokens[1]),
                "mtype": int(tokens[2]), "data": b64(tokens[3])}
    if rtype == TYPES["NAPTR"]:
        if len(tokens) < 6:
            raise WireError("NAPTR needs >=6 fields")
        return {"order": int(tokens[0]), "preference": int(tokens[1]),
                "flags": tokens[2], "service": tokens[3],
                "regexp": tokens[4],
                "replacement": _parse_name_field(tokens[5], origin)}
    if rtype == TYPES["HIP"]:
        return {"hit": b16(tokens[0]), "pubkey": b64(tokens[1]),
                "rendezvous": [_parse_name_field(t, origin)
                               for t in tokens[2:]]}
    if rtype == TYPES["DS"]:
        if len(tokens) < 4:
            raise WireError("DS needs key-tag, algorithm, digest-type, digest")
        return {"key_tag": int(tokens[0]), "algorithm": int(tokens[1]),
                "digest_type": int(tokens[2]), "digest": b16(
                    "".join(tokens[3:]))}
    if rtype == TYPES["DNSKEY"]:
        if len(tokens) < 4:
            raise WireError("DNSKEY needs flags, protocol, algorithm, key")
        return {"flags": int(tokens[0]), "protocol": int(tokens[1]),
                "algorithm": int(tokens[2]), "pubkey": b64("".join(tokens[3:]))}
    if rtype == TYPES["RRSIG"]:
        if len(tokens) < 9:
            raise WireError("RRSIG needs at least 9 fields")
        covered = TYPES.get(tokens[0].upper())
        if covered is None:
            raise WireError(f"RRSIG covers unknown type {tokens[0]}")
        return {
            "type_covered": covered,
            "algorithm": int(tokens[1]),
            "labels": int(tokens[2]),
            "original_ttl": int(tokens[3]),
            "expiration": int(tokens[4]),
            "inception": int(tokens[5]),
            "key_tag": int(tokens[6]),
            "signer": _parse_name_field(tokens[7], origin),
            "signature": b64("".join(tokens[8:])),
        }
    if rtype == TYPES["NSEC"]:
        return {"next": _parse_name_field(tokens[0], origin),
                "types": [TYPES[t.upper()] for t in tokens[1:]]}
    if rtype == TYPES["NSEC3"]:
        if len(tokens) < 5:
            raise WireError("NSEC3 needs hash alg, flags, iterations, salt, next")
        return {"hash_alg": int(tokens[0]), "flags": int(tokens[1]),
                "iterations": int(tokens[2]), "salt": b16(tokens[3]),
                "next_hash": b16(tokens[4]),
                "types": [TYPES[t.upper()] for t in tokens[5:]]}
    if rtype == TYPES["NSEC3PARAM"]:
        if len(tokens) != 4:
            raise WireError("NSEC3PARAM needs 4 fields")
        return {"hash_alg": int(tokens[0]), "flags": int(tokens[1]),
                "iterations": int(tokens[2]), "salt": b16(tokens[3])}
    raise WireError(f"unsupported RDATA type {TYPE_NAMES.get(rtype, rtype)}")


def encode_rdata(rtype: int, rd: dict) -> bytes:
    """Canonical wire encoding of structured RDATA (RFC 4034 section 6.2)."""
    if rtype == TYPES["A"]:
        return ipaddress.IPv4Address(rd["address"]).packed
    if rtype == TYPES["AAAA"]:
        return ipaddress.IPv6Address(rd["address"]).packed
    if rtype in (TYPES["NS"], TYPES["CNAME"], TYPES["PTR"], TYPES["DNAME"]):
        return encode_name(rd["target"])
    if rtype == TYPES["SOA"]:
        return (encode_name(rd["mname"]) + encode_name(rd["rname"])
                + struct.pack("!IIIII", rd["serial"], rd["refresh"],
                              rd["retry"], rd["expire"], rd["minimum"]))
    if rtype == TYPES["MX"]:
        return encode_u16(rd["preference"]) + encode_name(rd["exchange"])
    if rtype == TYPES["SRV"]:
        return (struct.pack("!HHH", rd["priority"], rd["weight"], rd["port"])
                + encode_name(rd["target"]))
    if rtype == TYPES["TXT"]:
        return b"".join(encode_character_string(s) for s in rd["strings"])
    if rtype == TYPES["HINFO"]:
        return (encode_character_string(rd["cpu"])
                + encode_character_string(rd["os"]))
    if rtype == TYPES["CAA"]:
        tag = rd["tag"].encode("ascii")
        val = rd["value"].encode("utf-8")
        return bytes([rd["flags"], len(tag)]) + tag + val
    if rtype == TYPES["TLSA"]:
        return bytes([rd["usage"], rd["selector"], rd["mtype"]]) + rd["data"]
    if rtype == TYPES["NAPTR"]:
        out = struct.pack("!HH", rd["order"], rd["preference"])
        for key in ("flags", "service", "regexp"):
            out += encode_character_string(rd[key])
        return out + encode_name(rd["replacement"])
    if rtype == TYPES["HIP"]:
        out = bytes([len(rd["hit"]), len(rd["pubkey"]) // 256,
                     len(rd["pubkey"]) % 256]) + rd["hit"] + rd["pubkey"]
        for name in rd["rendezvous"]:
            out += encode_name(name)
        return out
    if rtype == TYPES["DS"]:
        return (encode_u16(rd["key_tag"]) + encode_u8(rd["algorithm"])
                + encode_u8(rd["digest_type"]) + rd["digest"])
    if rtype == TYPES["DNSKEY"]:
        return (encode_u16(rd["flags"]) + encode_u8(rd["protocol"])
                + encode_u8(rd["algorithm"]) + rd["pubkey"])
    if rtype == TYPES["RRSIG"]:
        return (encode_u16(rd["type_covered"]) + encode_u8(rd["algorithm"])
                + encode_u8(rd["labels"]) + encode_u32(rd["original_ttl"])
                + encode_u32(rd["expiration"])
                + encode_u32(rd["inception"]) + encode_u16(rd["key_tag"])
                + encode_name(rd["signer"]) + rd["signature"])
    if rtype == TYPES["NSEC"]:
        return encode_name(rd["next"]) + encode_nsec_bitmap(rd["types"])
    if rtype == TYPES["NSEC3"]:
        salt = rd["salt"]
        return (encode_u8(rd["hash_alg"]) + encode_u8(rd["flags"])
                + struct.pack("!H", rd["iterations"])
                + encode_u8(len(salt)) + salt + rd["next_hash"]
                + encode_nsec_bitmap(rd["types"]))
    if rtype == TYPES["NSEC3PARAM"]:
        salt = rd["salt"]
        return (encode_u8(rd["hash_alg"]) + encode_u8(rd["flags"])
                + struct.pack("!H", rd["iterations"])
                + encode_u8(len(salt)) + salt)
    raise WireError(f"cannot encode type {TYPE_NAMES.get(rtype, rtype)}")


def rdata_presentation(rtype: int, rd: dict) -> str:
    """Re-render structured RDATA to normalized presentation text."""
    if rtype == TYPES["A"] or rtype == TYPES["AAAA"]:
        return rd["address"]
    if rtype in (TYPES["NS"], TYPES["CNAME"], TYPES["PTR"], TYPES["DNAME"]):
        return rd["target"]
    if rtype == TYPES["SOA"]:
        return " ".join(str(rd[k]) for k in
                        ("mname", "rname", "serial", "refresh", "retry",
                         "expire", "minimum"))
    if rtype == TYPES["MX"]:
        return f"{rd['preference']} {rd['exchange']}"
    if rtype == TYPES["SRV"]:
        return (f"{rd['priority']} {rd['weight']} {rd['port']} "
                f"{rd['target']}")
    if rtype == TYPES["TXT"]:
        return " ".join(f'"{s}"' for s in rd["strings"])
    if rtype == TYPES["HINFO"]:
        return f'"{rd["cpu"]}" "{rd["os"]}"'
    if rtype == TYPES["CAA"]:
        return f"{rd['flags']} {rd['tag']} \"{rd['value']}\""
    if rtype == TYPES["TLSA"]:
        return (f"{rd['usage']} {rd['selector']} {rd['mtype']} "
                f"{rd['data'].hex()}")
    if rtype == TYPES["NAPTR"]:
        return (f"{rd['order']} {rd['preference']} \"{rd['flags']}\" "
                f"\"{rd['service']}\" \"{rd['regexp']}\" {rd['replacement']}")
    if rtype == TYPES["HIP"]:
        names = " ".join(rd["rendezvous"])
        return f"{rd['hit'].hex()} {base64.b64encode(rd['pubkey']).decode()} {names}".rstrip()
    if rtype == TYPES["DS"]:
        return (f"{rd['key_tag']} {rd['algorithm']} {rd['digest_type']} "
                f"{rd['digest'].hex()}")
    if rtype == TYPES["DNSKEY"]:
        return (f"{rd['flags']} {rd['protocol']} {rd['algorithm']} "
                f"{base64.b64encode(rd['pubkey']).decode()}")
    if rtype == TYPES["RRSIG"]:
        rd2 = dict(rd)
        rd2["type_covered"] = TYPE_NAMES[rd["type_covered"]]
        rd2["signer"] = rd["signer"]
        return (f"{rd2['type_covered']} {rd['algorithm']} {rd['labels']} "
                f"{rd['original_ttl']} {rd['expiration']} {rd['inception']} "
                f"{rd['key_tag']} {rd['signer']} "
                f"{base64.b64encode(rd['signature']).decode()}")
    if rtype == TYPES["NSEC"]:
        return rd["next"] + " " + " ".join(TYPE_NAMES[t] for t in rd["types"])
    if rtype == TYPES["NSEC3"]:
        salt = rd["salt"].hex() if rd["salt"] else "-"
        return (f"{rd['hash_alg']} {rd['flags']} {rd['iterations']} {salt} "
                f"{rd['next_hash'].hex()} "
                f"{' '.join(TYPE_NAMES[t] for t in rd['types'])}")
    if rtype == TYPES["NSEC3PARAM"]:
        salt = rd["salt"].hex() if rd["salt"] else "-"
        return f"{rd['hash_alg']} {rd['flags']} {rd['iterations']} {salt}"
    raise WireError(f"cannot render type {TYPE_NAMES.get(rtype, rtype)}")


# --------------------------------------------------------------------------
# DNSKEY tag, DS digest, NSEC3 hash (RFC 4034 / RFC 5155)
# --------------------------------------------------------------------------
def dnskey_rdata_wire(flags: int, protocol: int, algorithm: int,
                      pubkey: bytes) -> bytes:
    return encode_u16(flags) + encode_u8(protocol) + encode_u8(algorithm) + pubkey


def key_tag(flags: int, protocol: int, algorithm: int, pubkey: bytes) -> int:
    """RFC 4034 Appendix B key tag.

    Octets at even (0-based) positions are treated as the high byte of a
    16-bit word; odd positions are the low byte.
    """
    data = dnskey_rdata_wire(flags, protocol, algorithm, pubkey)
    acc = 0
    for i, byte in enumerate(data):
        acc += (byte << 8) if i % 2 == 0 else byte
    acc += (acc >> 16) & 0xFFFF
    return acc & 0xFFFF


def ds_digest(owner_name: str, flags: int, protocol: int, algorithm: int,
              pubkey: bytes, digest_type: int) -> bytes:
    """RFC 4034 section 5.1.4 DS digest = H(owner | DNSKEY RDATA)."""
    import hashlib
    name = digest_type
    if name not in DIGEST_ALGS:
        raise WireError(f"unsupported DS digest type {digest_type}")
    h = hashlib.new(DIGEST_ALGS[name][1])
    h.update(encode_name(owner_name))
    h.update(dnskey_rdata_wire(flags, protocol, algorithm, pubkey))
    return h.digest()


def nsec3_hash(owner_name: str, hash_alg: int, iterations: int,
               salt: bytes) -> bytes:
    """RFC 5155 section 5 NSEC3 next-owner hash.

    The initial SHA-1 is over ``canonical owner name || salt``; each of the
    ``iterations`` additional rounds hashes ``previous || salt``.
    """
    import hashlib
    if hash_alg != 1:
        raise WireError(f"unsupported NSEC3 hash algorithm {hash_alg}")
    h = hashlib.sha1(encode_name(owner_name) + salt).digest()
    for _ in range(iterations):
        h = hashlib.sha1(h + salt).digest()
    return h
