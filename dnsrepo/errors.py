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
