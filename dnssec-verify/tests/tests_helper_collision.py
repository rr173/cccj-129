"""Find two distinct ECDSA keys sharing key tag and algorithm number.

Used to prove that tag+algorithm equality cannot establish key identity.
This is test-support code, never imported by the package under test.
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, "/workspace/pylibs")

from dnssecverify import wire  # noqa: E402
from make_snapshots import fresh_key  # noqa: E402


def make_collision_pair(algorithm: int = 13, max_attempts: int = 400000):
    """Return ``(priv_a, dnskey_a, dnskey_b)`` with equal tag, different key.

    ECDSA P-256 key tags span 16 bits, so a collision for any fixed target is
    expected after roughly 2^16 draws; the generous bound plus outer retries
    make the search deterministic enough for the suite.
    """
    for _outer in range(5):
        priv_a, dk_a = fresh_key(algorithm)
        target = dk_a["key_tag"]
        for attempts in range(1, max_attempts + 1):
            priv_b, dk_b = fresh_key(algorithm)
            if (dk_b["key_tag"] == target
                    and dk_b["pubkey"] != dk_a["pubkey"]):
                return priv_a, dk_a, dk_b
    raise RuntimeError("tag collision search exhausted")
