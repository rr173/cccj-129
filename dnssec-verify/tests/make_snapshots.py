"""Generate cryptographically signed zone snapshots for test fixtures.

The generator signs with the real ``cryptography`` primitives but builds the
RRSIG signed-data blob through the same canonical wire rules that RFC 4034
mandates.  The *verification* expectations are cross-checked independently by
``oracle_check.py`` via dnspython, so the generator is not used as the
oracle for the system under test.
"""
from __future__ import annotations

import base64
import os
import sys

sys.path.insert(0, "/workspace/pylibs")

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dnssecverify import wire  # noqa: E402
from dnssecverify.crypto import encode_ec_der  # noqa: E402

TTL = 3600
SIG_TTL = 3600
DEFAULT_ALG = 13  # ECDSAP256SHA256


# --------------------------------------------------------------------------
# Key generation and DNSKEY material
# --------------------------------------------------------------------------
def generate_key(algorithm: int = DEFAULT_ALG):
    if algorithm in (5, 7, 8, 10):
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif algorithm == 13:
        priv = ec.generate_private_key(ec.SECP256R1())
    elif algorithm == 14:
        priv = ec.generate_private_key(ec.SECP384R1())
    elif algorithm == 15:
        priv = ed25519.Ed25519PrivateKey.generate()
    elif algorithm == 16:
        priv = ed448.Ed448PrivateKey.generate()
    else:
        raise ValueError(f"unsupported algorithm {algorithm}")
    return priv


def _rsa_public_wire(pub: rsa.RSAPublicKey) -> bytes:
    nums = pub.public_numbers()
    e = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
    n = nums.n.to_bytes(pub.key_size // 8, "big")
    # RFC 3110 section 2: 3-octet length when exponent length >= 256.
    if len(e) >= 256:
        prefix = bytes([0x01, (len(e) >> 8) & 0xFF, len(e) & 0xFF])
    else:
        prefix = bytes([len(e)])
    return prefix + e + n


def _ec_public_wire(priv, algorithm: int) -> bytes:
    nums = priv.public_key().public_numbers()
    size = 32 if algorithm == 13 else 48
    return (nums.x.to_bytes(size, "big") + nums.y.to_bytes(size, "big"))


def dnskey_pubkey_wire(priv, algorithm: int) -> bytes:
    family = wire.SIG_ALGS[algorithm][1]
    if family == "rsa":
        return _rsa_public_wire(priv.public_key())
    if family == "ec":
        return _ec_public_wire(priv, algorithm)
    if family == "ed25519":
        return priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
    if family == "ed448":
        return priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
    raise ValueError(algorithm)


def make_dnskey(priv, algorithm: int, flags: int = 257) -> dict:
    pub = dnskey_pubkey_wire(priv, algorithm)
    return {"flags": flags, "protocol": 3, "algorithm": algorithm,
            "pubkey": pub,
            "key_tag": wire.key_tag(flags, 3, algorithm, pub)}


def make_ds(zone: str, dnskey: dict, digest_type: int = 2) -> dict:
    digest = wire.ds_digest(zone, dnskey["flags"], dnskey["protocol"],
                            dnskey["algorithm"], dnskey["pubkey"],
                            digest_type)
    return {"key_tag": dnskey["key_tag"],
            "algorithm": dnskey["algorithm"],
            "digest_type": digest_type, "digest": digest}


def fresh_key(algorithm: int = DEFAULT_ALG, flags: int = 257):
    """Generate a new private key and its DNSKEY publication record."""
    priv = generate_key(algorithm)
    return priv, make_dnskey(priv, algorithm, flags)


# --------------------------------------------------------------------------
# Signing
# --------------------------------------------------------------------------
def _sign_blob(priv, algorithm: int, blob: bytes) -> bytes:
    family, hash_name = wire.SIG_ALGS[algorithm][1], wire.SIG_ALGS[algorithm][2]
    if family == "rsa":
        h = {"sha1": hashes.SHA1, "sha256": hashes.SHA256,
             "sha384": hashes.SHA384, "sha512": hashes.SHA512}[hash_name]()
        sig = priv.sign(blob, __import__(
            "cryptography.hazmat.primitives.asymmetric.padding",
            fromlist=["PKCS1v15"]).PKCS1v15(), h)
        return sig
    if family == "ec":
        h = {"sha256": hashes.SHA256, "sha384": hashes.SHA384}[hash_name]()
        der = priv.sign(blob, ec.ECDSA(h))
        return _ec_der_to_raw(der, 32 if algorithm == 13 else 48)
    if family == "ed25519":
        return priv.sign(blob)
    if family == "ed448":
        return priv.sign(blob)
    raise ValueError(algorithm)


def _ec_der_to_raw(der: bytes, coord_len: int) -> bytes:
    def read_int(data: bytes, pos: int) -> tuple[int, int]:
        assert data[pos] == 0x02
        length = data[pos + 1]
        body = data[pos + 2:pos + 2 + length]
        return int.from_bytes(body, "big"), pos + 2 + length

    assert der[0] == 0x30
    pos = 2
    r, pos = read_int(der, pos)
    s, pos = read_int(der, pos)
    return (r.to_bytes(coord_len, "big") + s.to_bytes(coord_len, "big"))


def sign_rrset(priv, dnskey: dict, zone: str, owner: str, rtype: int,
               rdata_list: list[dict], inception: int, expiration: int,
               original_ttl: int = TTL, signer: str | None = None,
               labels_override: int | None = None) -> dict:
    algorithm = dnskey["algorithm"]
    labels = (wire.name_labels(owner) - 1 if owner.startswith("*.")
              else wire.name_labels(owner))
    if labels_override is not None:
        labels = labels_override
    sig = {
        "type_covered": rtype, "algorithm": algorithm, "labels": labels,
        "original_ttl": original_ttl, "expiration": expiration,
        "inception": inception, "key_tag": dnskey["key_tag"],
        "signer": signer or zone, "signature": b"",
    }
    from dnssecverify.crypto import canonical_rrset
    head = wire.encode_rdata(wire.TYPES["RRSIG"], sig)
    signer_wire = wire.encode_name(sig["signer"])
    blob = head[:18 + len(signer_wire)] + canonical_rrset(
        owner, rtype, wire.CLASS_IN, original_ttl, rdata_list)
    sig["signature"] = _sign_blob(priv, algorithm, blob)
    return sig


# --------------------------------------------------------------------------
# Zone file rendering
# --------------------------------------------------------------------------
def render_record(owner: str, ttl: int, rtype_name: str, rdata: dict,
                  origin: str) -> str:
    rtype = wire.TYPES[rtype_name]
    return f"{owner}\t{ttl}\tIN\t{rtype_name}\t{wire.rdata_presentation(rtype, rdata)}"


def write_zone(path: str, zone: str, serial: int, lines: list[str],
               default_ttl: int = TTL):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(f"; generated signed snapshot\n")
        fh.write(f"$ORIGIN {zone}\n")
        fh.write(f"$TTL {default_ttl}\n")
        for i, line in enumerate(lines):
            fh.write(line + "\n")
    return path


def soa_rdata(zone: str, serial: int) -> dict:
    return {"mname": f"ns1.{zone}", "rname": f"hostmaster.{zone}",
            "serial": serial, "refresh": 7200, "retry": 3600,
            "expire": 1209600, "minimum": 3600}


def write_anchor_json(path: str, zone: str, record: dict,
                      record_type: str, source_note: str = "test anchor"):
    if record_type == "DS":
        rec = {"type": "DS", "key_tag": record["key_tag"],
               "algorithm": record["algorithm"],
               "digest_type": record["digest_type"],
               "digest": record["digest"].hex()}
    else:
        rec = {"type": "DNSKEY", "flags": record["flags"],
               "protocol": record["protocol"],
               "algorithm": record["algorithm"],
               "pubkey": base64.b64encode(record["pubkey"]).decode()}
    import json
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"anchors": [{"zone": zone, "record": rec,
                                "source": source_note}]}, fh, indent=2)
    return path
