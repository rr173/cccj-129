"""Command line interface for dnsrepo."""

import argparse
import sys

from .ct import import_ct_observations
from .errors import HandoffError, ZoneError
from .handoff import inspect_handoff, pack_handoff
from .repo import Repository
from .traffic import attribute_flows


def _repo(args):
    return Repository(args.db, preserve_unknown=args.preserve_unknown)


def _read(path):
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def cmd_publish_master(args):
    with _repo(args) as repo:
        info = repo.publish_master(args.zone, _read(args.file),
                                   source_file=args.file)
        print("published %s serial %d (%d records)"
              % (info.zone, info.serial, info.record_count))
    return 0


def cmd_publish_increment(args):
    with _repo(args) as repo:
        info = repo.publish_increment(_read(args.file),
                                      source_file=args.file)
        print("published %s serial %d (%d records)"
              % (info.zone, info.serial, info.record_count))
    return 0


def cmd_zones(args):
    with _repo(args) as repo:
        for name, serial in repo.zones():
            print("%s %s" % (name, serial if serial is not None else "-"))
    return 0


def cmd_history(args):
    with _repo(args) as repo:
        for info in repo.versions(args.zone):
            print("serial=%d kind=%s records=%d source=%s at=%s"
                  % (info.serial, info.kind, info.record_count,
                     info.source_file or "-", info.published_at))
    return 0


def cmd_query(args):
    with _repo(args) as repo:
        for rec in repo.lookup(args.zone, args.name, args.rtype):
            print(rec.to_line(args.zone))
    return 0


def cmd_resolve(args):
    with _repo(args) as repo:
        answer = repo.resolve(args.zone, args.name, args.rtype or "A")
        for owner, target in answer.chain:
            print("%s CNAME -> %s" % (owner, target))
        for rec in answer.records:
            print(rec.to_line(args.zone))
        print("; status: %s" % answer.status)
    return 0


def cmd_diff(args):
    with _repo(args) as repo:
        print(repo.diff(args.zone, args.from_serial, args.to_serial).format())
    return 0


def cmd_export(args):
    with _repo(args) as repo:
        if args.output:
            path = repo.export_file(args.zone, path=args.output,
                                    serial=args.serial)
            print("wrote %s" % path)
        else:
            sys.stdout.write(repo.export_text(args.zone, args.serial))
    return 0


def cmd_attribute(args):
    result = attribute_flows(
        args.flows, args.ownership, args.output,
        repo_path=args.repo, zone=args.zone, serial=args.serial)
    print("attributed %d flows into %d fragments, %d bytes -> %s"
          % (result.flows, result.fragments, result.bytes_total,
             result.output))
    for status in ("assigned", "ambiguous", "unassigned"):
        print("%s: %d bytes" % (status, result.statuses.get(status, 0)))
    for owner, count in result.owner_bytes.items():
        print("owner %s: %d bytes" % (owner, count))
    return 0


def cmd_ct_import(args):
    result = import_ct_observations(
        args.observations, args.output, args.repo, args.zone, args.serial)
    print("imported %d observations (%d duplicate lines) for %s serial %d"
          % (result.observations, result.duplicates,
             result.zone, result.serial))
    print("findings: %d names (%d wildcard, %d plain)"
          % (result.findings, result.wildcards,
             result.findings - result.wildcards))
    for reason in ("out_of_zone", "zone_apex", "existing"):
        print("%s: %d name occurrences" % (reason,
                                           result.excluded.get(reason, 0)))
    print("wrote %s" % result.output)
    return 0


def _parse_selections(pairs):
    selections = []
    for pair in pairs:
        if "=" not in pair:
            raise HandoffError("selection %r must look like ZONE=SERIAL"
                               % pair)
        zone, _, serial = pair.rpartition("=")
        if not serial.isdigit():
            raise HandoffError("selection %r has a non-numeric serial"
                               % pair)
        selections.append((zone, int(serial)))
    return selections


def cmd_handoff_pack(args):
    report = pack_handoff(args.db, _parse_selections(args.selections),
                          args.package)
    print("packed %d zone(s), %d snapshot(s), %d record(s) -> %s"
          % (len(report.zones), report.snapshot_count,
             report.record_count, report.path))
    for zone in report.zones:
        print("zone %s: %d snapshot(s), %d record(s)"
              % (zone.name, len(zone.snapshots), zone.record_count))
    print("sha256: %s" % report.sha256)
    return 0


def cmd_handoff_inspect(args):
    report = inspect_handoff(args.package)
    print("package %s: format ok, integrity ok (sha256 %s)"
          % (report.path, report.sha256[:16] + "..."))
    print("%d zone(s), %d snapshot(s), %d record(s)"
          % (len(report.zones), report.snapshot_count,
             report.record_count))
    for zone in report.zones:
        print("zone %s: %d snapshot(s), %d record(s)"
              % (zone.name, len(zone.snapshots), zone.record_count))
        for snap in zone.snapshots:
            print("  #%d serial=%d kind=%s records=%d source=%s at=%s"
                  % (snap.position, snap.serial, snap.kind,
                     snap.record_count, snap.source_file or "-",
                     snap.created_at))
    return 0


def cmd_handoff_receive(args):
    with _repo(args) as repo:
        report = repo.receive_handoff(args.package)
    print("received %s: %d snapshot(s) reused, %d appended"
          % (report.path, report.reused, report.appended))
    for outcome in report.outcomes:
        print("zone %s: reused=%d appended=%d head serial=%s"
              % (outcome.zone, outcome.reused, outcome.appended,
                 outcome.head_serial))
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="dnsrepo",
        description="Versioned DNS zone file repository (no live DNS).")
    parser.add_argument("--db", default="dnsrepo.db",
                        help="SQLite database path (default: dnsrepo.db)")
    parser.add_argument("--preserve-unknown", action="store_true",
                        help="keep unknown record types as raw text")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("publish-master", help="publish a master zone file")
    p.add_argument("zone")
    p.add_argument("file")
    p.set_defaults(func=cmd_publish_master)

    p = sub.add_parser("publish-increment", help="publish an increment file")
    p.add_argument("file")
    p.set_defaults(func=cmd_publish_increment)

    p = sub.add_parser("zones", help="list zones and current serials")
    p.set_defaults(func=cmd_zones)

    p = sub.add_parser("history", help="list published versions of a zone")
    p.add_argument("zone")
    p.set_defaults(func=cmd_history)

    p = sub.add_parser("query", help="records at a name in the current zone")
    p.add_argument("zone")
    p.add_argument("name")
    p.add_argument("rtype", nargs="?")
    p.set_defaults(func=cmd_query)

    p = sub.add_parser("resolve", help="resolve a name inside the zone")
    p.add_argument("zone")
    p.add_argument("name")
    p.add_argument("rtype", nargs="?")
    p.set_defaults(func=cmd_resolve)

    p = sub.add_parser("diff", help="diff two versions of a zone")
    p.add_argument("zone")
    p.add_argument("from_serial", type=int)
    p.add_argument("to_serial", type=int)
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("export", help="render a version as a zone file")
    p.add_argument("zone")
    p.add_argument("--serial", type=int)
    p.add_argument("-o", "--output")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser(
        "attribute",
        help="attribute connection bytes to network owners (offline batch)")
    p.add_argument("flows", help="connection summaries JSONL")
    p.add_argument("ownership", help="ownership facts JSONL")
    p.add_argument("output", help="output directory (must not exist)")
    p.add_argument("--repo", help="repository to read DNS labels from")
    p.add_argument("--zone", help="zone whose version supplies DNS labels")
    p.add_argument("--serial", type=int,
                   help="published serial whose A/AAAA owners are attached")
    p.set_defaults(func=cmd_attribute)

    p = sub.add_parser(
        "ct-import",
        help="import CT certificate observations as review findings "
             "(offline batch)")
    p.add_argument("observations", nargs="+",
                   help="CT observation JSONL file(s)")
    p.add_argument("output", help="output directory (must not exist)")
    p.add_argument("--repo", required=True,
                   help="repository holding the pinned zone version")
    p.add_argument("--zone", required=True,
                   help="zone whose version defines the scope")
    p.add_argument("--serial", required=True, type=int,
                   help="published serial whose records suppress findings")
    p.set_defaults(func=cmd_ct_import)

    p = sub.add_parser(
        "handoff-pack",
        help="pack selected zone history from --db into a handoff package")
    p.add_argument("package", help="package file to create (must not exist)")
    p.add_argument("selections", nargs="+", metavar="ZONE=SERIAL",
                   help="zone and its cutoff serial (each zone once)")
    p.set_defaults(func=cmd_handoff_pack)

    p = sub.add_parser(
        "handoff-inspect",
        help="verify a handoff package and list its contents")
    p.add_argument("package", help="package file to inspect")
    p.set_defaults(func=cmd_handoff_inspect)

    p = sub.add_parser(
        "handoff-receive",
        help="splice a handoff package into the --db repository")
    p.add_argument("package", help="package file to receive")
    p.set_defaults(func=cmd_handoff_receive)

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ZoneError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
