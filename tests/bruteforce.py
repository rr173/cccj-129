"""Independent brute-force reference for traffic attribution.

This deliberately shares no code with ``dnsrepo.traffic``: it enumerates
every integer millisecond of a connection, classifies each instant with a
naive scan over all ownership rows, merges equal neighbours and then does
the byte split with plain divmod arithmetic.  It is only usable for tiny
hand-checkable inputs and exists to cross-check the indexed implementation.
"""

import ipaddress


def _contains(cidr_net, address):
    return cidr_net.version == address.version and address in cidr_net


def classify_instant(address, at, rows):
    """(status, owners) using a linear scan over *rows*."""
    hits = []
    for row in rows:
        network = ipaddress.ip_network(row["cidr"])
        owner, low, high = row["owner"], row["valid_from_ms"], row["valid_to_ms"]
        if _contains(network, address) and low <= at < high:
            hits.append((network.prefixlen, owner))
    if not hits:
        return ("unassigned", ())
    longest = max(prefix for prefix, _ in hits)
    owners = tuple(sorted({owner for prefix, owner in hits
                           if prefix == longest}))
    return ("assigned" if len(owners) == 1 else "ambiguous", owners)


def fragments(flow, rows):
    address = ipaddress.ip_address(flow["dst_ip"])
    start, end = flow["start_ms"], flow["end_ms"]
    pieces = []
    for at in range(start, end):
        state = classify_instant(address, at, rows)
        if pieces and pieces[-1][2] == state[0] and pieces[-1][3] == state[1]:
            pieces[-1][1] = at + 1
        else:
            pieces.append([at, at + 1, state[0], state[1]])
    return [tuple(piece) for piece in pieces]


def split(total, pieces):
    """Largest-remainder byte split, computed with divmod only."""
    span = sum(hi - lo for lo, hi, _, _ in pieces)
    amounts = []
    remainders = []
    for index, (lo, hi, _, _) in enumerate(pieces):
        share, remainder = divmod(total * (hi - lo), span)
        amounts.append(share)
        remainders.append((-remainder, lo, index))
    remaining = total - sum(amounts)
    for _, _, index in sorted(remainders)[:remaining]:
        amounts[index] += 1
    return amounts


def attribute(flow, rows):
    """List of (start, end, status, owners, bytes) for one connection."""
    pieces = fragments(flow, rows)
    return [piece + (amount,) for piece, amount
            in zip(pieces, split(flow["bytes"], pieces))]
