"""DNSSEC cryptographic verification over canonical wire data.

Supports the algorithms declared in :data:`wire.SIG_ALGS`.  Unsupported
algorithms raise :class:`UnsupportedAlgorithm` so callers can distinguish
"cannot decide" from "cryptographically invalid".
"""
from __future__ import annotations

import sys

sys.path.insert(0, "/workspace/pylibs")

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa

from . import wire


class UnsupportedAlgorithm(Exception):
    """Algorithm number is not implemented by this verifier."""


class KeyParseError(Exception):
    """A DNSKEY public key blob cannot be parsed."""


_HASHES = {
    "sha1": hashes.SHA1,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}


def algorithm_supported(algorithm: int) -> bool:
    return algorithm in wire.SIG_ALGS


def _hash(name: str):
    return _HASHES[name]()


# --------------------------------------------------------------------------
# RFC 3110 RSA public keys
# --------------------------------------------------------------------------
def _parse_rsa_pubkey(blob: bytes) -> rsa.RSAPublicKey:
    if len(blob) < 2:
        raise KeyParseError("RSA key blob too short")
    first = blob[0]
    if first & 0x80:
        # Leading length field is 3 octets (RFC 3110 section 2).
        if len(blob) < 3:
            raise KeyParseError("truncated RSA exponent length")
        e_len = ((first & 0x7F) << 16) | (blob[1] << 8) | blob[2]
        pos = 3
    else:
        if first == 0:
            raise KeyParseError("reserved zero exponent length")
        e_len = first
        pos = 1
    if e_len == 0 or pos + e_len >= len(blob):
        raise KeyParseError("bad RSA exponent length")
    exponent = int.from_bytes(blob[pos:pos + e_len], "big")
    modulus_bytes = blob[pos + e_len:]
    if len(modulus_bytes) < 64:
        raise KeyParseError("RSA modulus suspiciously short")
    modulus = int.from_bytes(modulus_bytes, "big")
    if exponent <= 0 or modulus <= 0:
        raise KeyParseError("non-positive RSA parameter")
    numbers = rsa.RSAPublicNumbers(exponent, modulus)
    try:
        return numbers.public_key()
    except ValueError as exc:
        raise KeyParseError(str(exc)) from exc


# --------------------------------------------------------------------------
# EC / Ed public keys (RFC 6605, RFC 8080)
# --------------------------------------------------------------------------
def _parse_ec_pubkey(algorithm: int, blob: bytes):
    if algorithm == 13:
        curve, size = ec.SECP256R1(), 64
    elif algorithm == 14:
        curve, size = ec.SECP384R1(), 96
    else:  # pragma: no cover
        raise UnsupportedAlgorithm(algorithm)
    if len(blob) != size:
        raise KeyParseError(
            f"ECDSA key for alg {algorithm} must be {size} bytes, "
            f"got {len(blob)}")
    x = int.from_bytes(blob[:size // 2], "big")
    y = int.from_bytes(blob[size // 2:], "big")
    try:
        return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
    except ValueError as exc:
        raise KeyParseError(str(exc)) from exc


def load_public_key(algorithm: int, pubkey: bytes):
    """Build a cryptography public-key object from DNSKEY RDATA bytes."""
    if not algorithm_supported(algorithm):
        raise UnsupportedAlgorithm(algorithm)
    family = wire.SIG_ALGS[algorithm][1]
    if family == "rsa":
        return _parse_rsa_pubkey(pubkey)
    if family == "ec":
        return _parse_ec_pubkey(algorithm, pubkey)
    if family == "ed25519":
        if len(pubkey) != 32:
            raise KeyParseError("Ed25519 key must be 32 bytes")
        return ed25519.Ed25519PublicKey.from_public_bytes(pubkey)
    if family == "ed448":
        if len(pubkey) != 57:
            raise KeyParseError("Ed448 key must be 57 bytes")
        return ed448.Ed448PublicKey.from_public_bytes(pubkey)
    raise UnsupportedAlgorithm(algorithm)  # pragma: no cover


# --------------------------------------------------------------------------
# RFC 6605 ECDSA signature conversion (raw R||S -> DER)
# --------------------------------------------------------------------------
def _ecdsa_der(blob: bytes, coord_len: int) -> bytes:
    if len(blob) != 2 * coord_len:
        raise KeyParseError("bad ECDSA signature length")
    r = int.from_bytes(blob[:coord_len], "big")
    s = int.from_bytes(blob[coord_len:], "big")
    return encode_ec_der(r, s)


def encode_ec_der(r: int, s: int) -> bytes:
    """Wrap two integers in an ASN.1 SEQUENCE { r INTEGER, s INTEGER }."""
    content = _der_integer(r) + _der_integer(s)
    length = len(content)
    if length < 128:
        prefix = bytes([length])
    else:
        size_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
        prefix = bytes([0x80 | len(size_bytes)]) + size_bytes
    return b"\x30" + prefix + content


def _der_integer(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    if body[0] & 0x80:
        body = b"\x00" + body
    return b"\x02" + bytes([len(body)]) + body


# --------------------------------------------------------------------------
# Canonical RR set (RFC 4034 section 6.3)
# --------------------------------------------------------------------------
def canonical_rrset(owner: str, rtype: int, rclass: int, ttl: int,
                    rdata_list: list[dict]) -> bytes:
    """Build the canonical wire-ordered RR set portion of signed data."""
    name_wire = wire.encode_name(wire.canonical_name(owner))
    encoded = sorted(
        (wire.encode_rdata(rtype, rd) for rd in rdata_list),
        key=lambda b: b,
    )
    out = bytearray()
    for rdata_wire in encoded:
        out += name_wire
        out += wire.encode_u16(rtype)
        out += wire.encode_u16(rclass)
        out += wire.encode_u32(ttl)
        out += wire.encode_u16(len(rdata_wire))
        out += rdata_wire
    return bytes(out)


def rrsig_rdata_wire(sig: dict) -> bytes:
    return wire.encode_rdata(wire.TYPES["RRSIG"], sig)


def signature_input(sig: dict, owner: str, rdata_list: list[dict],
                    rclass: int) -> bytes:
    """RFC 4034 section 3.1.8.1 RRSIG signed data blob."""
    rrsig_hdr = rrsig_rdata_wire(sig)
    # RRSIG RDATA wire = everything up to and including the signer name,
    # i.e. exclude the trailing signature field (RFC 4034 3.1.8.1).
    signer_wire = wire.encode_name(sig["signer"])
    head_end = 18 + len(signer_wire)
    head = rrsig_hdr[:head_end]
    body = canonical_rrset(owner, sig["type_covered"], rclass,
                           sig["original_ttl"], rdata_list)
    return head + body


# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------
def verify_rrsig(sig: dict, owner: str, rdata_list: list[dict], rclass: int,
                 pubkey: bytes, at_time: int,
                 zone_apex: str) -> tuple[bool, str]:
    """Validate one RRSIG against one DNSKEY at a UTC epoch second.

    Returns ``(ok, reason)``; ``ok=False`` with a human-readable reason
    covering expiry, label mismatch, signer mismatch and crypto failure.
    """
    algorithm = sig["algorithm"]
    if not algorithm_supported(algorithm):
        raise UnsupportedAlgorithm(algorithm)

    # Validity period (RFC 4034 3.1.5): inclusive endpoints.
    if at_time < sig["inception"]:
        return False, (f"signature not yet valid (inception "
                       f"{sig['inception']} > {at_time})")
    if at_time > sig["expiration"]:
        return False, (f"signature expired (expiration "
                       f"{sig['expiration']} < {at_time})")

    # Labels field check (RFC 4034 3.1.3).  For an explicit owner the labels
    # field equals the owner label count; for a wildcard RRset the labels
    # field is one less (the '*' label is not part of the original name).
    owner_labels = wire.name_labels(owner)
    if sig["labels"] > owner_labels:
        return False, (f"RRSIG labels={sig['labels']} exceeds owner labels "
                       f"{owner_labels} for {owner}")
    if owner.startswith("*."):
        if sig["labels"] != owner_labels - 1:
            return False, (f"wildcard RRSIG labels={sig['labels']} "
                           f"inconsistent with wildcard owner {owner}")
    elif sig["labels"] != owner_labels:
        return False, (f"RRSIG labels={sig['labels']} does not match owner "
                       f"label count {owner_labels} for {owner}")

    if wire.canonical_name(sig["signer"]) != wire.canonical_name(zone_apex):
        return False, (f"RRSIG signer {sig['signer']} is not the zone apex "
                       f"{zone_apex}")

    try:
        key = load_public_key(algorithm, pubkey)
    except UnsupportedAlgorithm:
        raise
    except KeyParseError as exc:
        return False, f"DNSKEY public key unparseable: {exc}"

    data = signature_input(sig, owner, rdata_list, rclass)
    family, hash_name = wire.SIG_ALGS[algorithm][1], wire.SIG_ALGS[algorithm][2]
    try:
        if family == "rsa":
            key.verify(sig["signature"], data, padding.PKCS1v15(),
                       _hash(hash_name))
        elif family == "ec":
            coord = 32 if algorithm == 13 else 48
            der = _ecdsa_der(sig["signature"], coord)
            key.verify(der, data, ec.ECDSA(_hash(hash_name)))
        elif family == "ed25519":
            key.verify(sig["signature"], data)
        elif family == "ed448":
            key.verify(sig["signature"], data)
        else:  # pragma: no cover
            raise UnsupportedAlgorithm(algorithm)
    except InvalidSignature:
        return False, "cryptographic signature verification failed"
    except (ValueError, KeyParseError) as exc:
        return False, f"malformed signature: {exc}"
    return True, "ok"


def verify_ds_match(ds: dict, owner_name: str, key: dict) -> tuple[bool, str]:
    """Check whether a DS record digests the given child DNSKEY."""
    if ds["key_tag"] != wire.key_tag(key["flags"], key["protocol"],
                                    key["algorithm"], key["pubkey"]):
        return False, f"key tag mismatch (DS tag {ds['key_tag']})"
    if ds["algorithm"] != key["algorithm"]:
        return False, (f"algorithm mismatch (DS {ds['algorithm']} vs "
                       f"DNSKEY {key['algorithm']})")
    if ds["digest_type"] not in wire.DIGEST_ALGS:
        raise UnsupportedAlgorithm(
            f"DS digest type {ds['digest_type']}")
    digest = wire.ds_digest(owner_name, key["flags"], key["protocol"],
                            key["algorithm"], key["pubkey"],
                            ds["digest_type"])
    if digest != ds["digest"]:
        return False, "DS digest does not match DNSKEY wire data"
    return True, "ok"
