"""Exception hierarchy for dnsrepo."""


class ZoneError(Exception):
    """Base class for all dnsrepo errors."""


class ParseError(ZoneError):
    """A zone/increment file could not be parsed."""

    def __init__(self, message, line=None):
        self.line = line
        if line is not None:
            message = "line %d: %s" % (line, message)
        super().__init__(message)


class UnknownTypeError(ParseError):
    """An unknown record type was seen and preserve_unknown is off."""


class ValidationError(ZoneError):
    """A zone failed pre-publish validation."""


class OutOfZoneError(ValidationError):
    """A record owner name lies outside the zone boundary."""


class CNAMEConflictError(ValidationError):
    """A CNAME coexists with other data at the same owner name."""


class CNAMELoopError(ValidationError):
    """Following CNAME targets inside the zone forms a loop."""


class SerialError(ValidationError):
    """A serial number does not increase (RFC 1982) or does not match."""


class PrereqError(ZoneError):
    """An increment's prerequisite serial does not match the baseline."""


class DeltaError(ZoneError):
    """An increment directive does not match the baseline content."""


class BatchError(ZoneError):
    """A traffic attribution batch was rejected as a whole.

    ``source`` names the rejected input file (or is None for output and
    repository problems); ``line`` is the 1-based line number inside it.
    """

    def __init__(self, message, source=None, line=None):
        self.source = source
        self.line = line
        if source is not None:
            location = source
            if line is not None:
                location = "%s:%d" % (source, line)
            message = "%s: %s" % (location, message)
        super().__init__(message)


class HandoffError(ZoneError):
    """A handoff package is unreadable, corrupt or semantically invalid.

    Also raised when a package cannot be produced from the source
    repository (unknown zone, unpublished cutoff serial, ...).
    ``line`` is the 1-based line number inside the package when the
    problem is located in the package file.
    """

    def __init__(self, message, line=None):
        self.line = line
        if line is not None:
            message = "package line %d: %s" % (line, message)
        super().__init__(message)


class HandoffConflict(ZoneError):
    """The receiving repository's history cannot be spliced with the
    package: for some zone the receiver already carries versions that
    do not match the package prefix (or carries more versions than the
    package).  ``conflicts`` is a list of Conflict namedtuples locating
    every divergence found (zone, serial, category, detail)."""

    def __init__(self, conflicts):
        self.conflicts = list(conflicts)
        lines = ["handoff package conflicts with the receiving repository:"]
        for c in self.conflicts:
            lines.append("  zone %s serial %s: %s (%s)"
                         % (c.zone, c.serial, c.category, c.detail))
        super().__init__("\n".join(lines))
