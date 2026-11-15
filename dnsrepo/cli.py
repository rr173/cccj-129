"""Command line interface for dnsrepo."""

import argparse
import sys

from .errors import ZoneError
from .repo import Repository


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
