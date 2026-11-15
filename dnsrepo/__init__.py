"""dnsrepo - versioned DNS zone file repository.

Parses master and increment zone files, validates them (zone boundary,
CNAME conflicts/loops, serial arithmetic), and publishes immutable,
queryable versions into SQLite.  Never talks to a live DNS server.
"""

from .errors import (BatchError, CNAMEConflictError, CNAMELoopError,
                     DeltaError, OutOfZoneError, ParseError, PrereqError,
                     SerialError, UnknownTypeError, ValidationError,
                     ZoneError)
from .increment import apply_increment, parse_increment
from .repo import Repository
from .records import Record, serial_gt
from .traffic import attribute_flows
from .validate import validate_zone
from .zonefile import parse_master

__version__ = "0.1.0"

__all__ = [
    "Repository",
    "Record",
    "parse_master",
    "parse_increment",
    "apply_increment",
    "validate_zone",
    "serial_gt",
    "attribute_flows",
    "ZoneError",
    "ParseError",
    "UnknownTypeError",
    "ValidationError",
    "OutOfZoneError",
    "CNAMEConflictError",
    "CNAMELoopError",
    "SerialError",
    "PrereqError",
    "DeltaError",
    "BatchError",
]
