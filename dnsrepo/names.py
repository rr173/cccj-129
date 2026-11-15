"""DNS name handling.

All names handled internally are canonical: lowercase, absolute, with a
single trailing dot (the root itself is ".").  Comparison is always done
on canonical forms; the library lowercases names on parse because DNS is
case-insensitive.
"""

from .errors import ParseError

MAX_NAME_LEN = 253  # wire length without the root label
MAX_LABEL_LEN = 63

_LABEL_OK = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")


def is_absolute(name):
    return name.endswith(".")


def canonical(name):
    """Return the canonical (lowercase) form of an absolute name."""
    return name.lower()


def absolutize(name, origin, line=None):
    """Make *name* absolute against *origin*.

    ``@`` denotes the origin itself.  A name already ending in a dot is
    absolute and returned (canonically).  Anything else has the origin
    appended.  The result is validated and lowercased.
    """
    if name == "@":
        if not origin:
            raise ParseError("'@' used without a current origin", line)
        return origin
    if name.endswith("."):
        result = name
    else:
        if not origin:
            raise ParseError("relative name %r without a current origin" % name, line)
        if origin == ".":
            result = name + "."
        else:
            result = name + "." + origin
    return validate_name(result.lower(), line)


def validate_name(name, line=None):
    """Validate an absolute domain name, returning it unchanged.

    Performs length and character checks.  Wildcard labels (``*``) are
    permitted.  Escapes and binary labels are not supported.
    """
    if name == ".":
        return name
    if not name.endswith("."):
        raise ParseError("internal: name %r is not absolute" % name, line)
    body = name[:-1]
    if len(body) > MAX_NAME_LEN:
        raise ParseError("domain name too long (%d octets): %r" % (len(body), name), line)
    for label in body.split("."):
        if not label:
            raise ParseError("empty label in name %r" % name, line)
        if len(label) > MAX_LABEL_LEN:
            raise ParseError("label too long (%d octets) in %r" % (len(label), name), line)
        if label == "*":
            continue
        for ch in label:
            if ch not in _LABEL_OK:
                raise ParseError("bad character %r in name %r" % (ch, name), line)
    return name


def in_zone(name, origin):
    """True if canonical absolute *name* equals or is below *origin*."""
    if origin == ".":
        return True
    return name == origin or name.endswith("." + origin)


def relative(name, origin):
    """Render canonical absolute *name* relative to *origin* for output."""
    if name == origin:
        return "@"
    suffix = "." + origin
    if origin != "." and name.endswith(suffix):
        return name[: -len(suffix)]
    return name


def canon_zone(zone):
    """Normalize a zone name supplied by a caller to canonical absolute form."""
    zone = zone.strip()
    if not zone:
        raise ParseError("empty zone name")
    if zone == "@":
        raise ParseError("zone name must be explicit, not '@'")
    if not zone.endswith("."):
        zone = zone + "."
    return validate_name(zone.lower())
