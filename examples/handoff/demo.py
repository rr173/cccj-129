#!/usr/bin/env python3
"""可复跑的交接案例：旧库 → 交接包 → 核查 → 接收 → 继续日常发布。

场景（与 tests/test_handoff.py 的 ReceiveHappyPathTest 一致）：

* 旧库 old.db 有三个 zone：
  - alpha.example.  三个版本（serial 100 → 200 → 300），包含未动条目延续、
    删掉后重加、TXT 转义、保留的未知类型（CAA）；
  - beta.example.   两个版本，serial 从 4294967294 回绕到 1；
  - keep.example.   不交接，留在旧库。
* 接收库 new.db 已在使用：先录入无关的 other.example.（内部 id 与旧库错开），
  再通过一个更早的小包接进 alpha 的第一份快照（真正相同的短前缀）。
* 主交接包把 alpha 到 serial 300、beta 到 serial 1 的历史接进接收库。

运行（在仓库根目录）：

    python3 examples/handoff/demo.py [工作目录]

不给目录时使用临时目录。脚本逐步打印，并在每步校验；任何不符都以
非零状态退出。
"""

import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from dnsrepo import Repository, inspect_handoff, pack_handoff  # noqa: E402

ALPHA_V1 = """\
$ORIGIN alpha.example.
$TTL 3600
@ IN SOA ns1.alpha.example. hostmaster.alpha.example. 100 7200 3600 1209600 300
@ IN NS ns1
ns1 A 192.0.2.1
www 300 IN A 192.0.2.80
_meta TXT "v=spf1 \\"all\\""
www CAA 0 issue "ca.example"
old A 192.0.2.99
"""

ALPHA_V2 = """\
$ZONE alpha.example.
$PREREQ 100
$SERIAL 200
$DELETE
old A
$ADD
api 600 IN A 192.0.2.50
$END
"""

ALPHA_V3 = """\
$ZONE alpha.example.
$PREREQ 200
$SERIAL 300
$ADD
old 300 IN A 192.0.2.99
$END
"""

BETA_V1 = """\
@ 300 IN SOA ns1 h 4294967294 7200 3600 1209600 300
@ IN NS ns1
"""

BETA_V2 = """\
$ZONE beta.example.
$PREREQ 4294967294
$SERIAL 1
$ADD
host 300 IN A 10.0.0.1
$END
"""

KEEP_V1 = "@ 300 IN SOA ns1 h 5 7200 3600 1209600 300\n"
OTHER_V1 = ("@ 300 IN SOA ns1 h 42 7200 3600 1209600 300\n"
            "@ IN NS ns1\n")


def check(label, condition):
    print("  [%-4s] %s" % ("ok" if condition else "FAIL", label))
    if not condition:
        raise SystemExit("check failed: %s" % label)


def main():
    workdir = sys.argv[1] if len(sys.argv) > 1 else None
    if workdir is None:
        workdir = tempfile.mkdtemp(prefix="dnsrepo-handoff-demo-")
    else:
        os.makedirs(workdir, exist_ok=True)
    os.chdir(workdir)
    print("工作目录: %s" % workdir)

    print("\n== 1. 旧库：两个待交 zone + 一个不交的 zone ==")
    old = Repository("old.db", preserve_unknown=True)
    old.publish_master("alpha.example.", ALPHA_V1, source_file="alpha/v1.zone")
    old.publish_increment(ALPHA_V2, source_file="alpha/v2.inc")
    old.publish_increment(ALPHA_V3, source_file="alpha/v3.inc")
    old.publish_master("beta.example.", BETA_V1)          # source_file 为 null
    old.publish_increment(BETA_V2, source_file="beta/v2.inc")
    old.publish_master("keep.example.", KEEP_V1, source_file="keep/v1.zone")
    for name, serial in old.zones():
        print("  old: %-16s head serial=%d" % (name, serial))
    old.close()

    print("\n== 2. 接收库：先录入无关内容（内部 id 错开）==")
    new = Repository("new.db", preserve_unknown=True)
    new.publish_master("other.example.", OTHER_V1, source_file="other/v1.zone")
    print("  new: other.example. head serial=%d" % new.current("other.example.").serial)

    print("\n== 3. 更早的小包：接收库获得 alpha 的相同短前缀 ==")
    pack_handoff("old.db", {"alpha.example.": 100}, "prefix.dhf")
    new.receive_handoff("prefix.dhf")
    print("  new: alpha.example. versions=%s"
          % [v.serial for v in new.versions("alpha.example.")])
    new.close()

    print("\n== 4. 打主交接包（alpha 到 300，beta 到 1）==")
    report = pack_handoff("old.db",
                          {"alpha.example.": 300, "beta.example.": 1},
                          "handoff.dhf")
    print("  packed %d zones, %d snapshots, %d records"
          % (len(report.zones), report.snapshot_count, report.record_count))
    check("keep.example. 不在包中",
          "keep.example." not in open("handoff.dhf", encoding="utf-8").read())

    print("\n== 5. 接收方核查交接包（完整性 + 语义）==")
    insp = inspect_handoff("handoff.dhf")
    for zone in insp.zones:
        for snap in zone.snapshots:
            print("  %s #%d serial=%d kind=%s records=%d source=%s"
                  % (zone.name, snap.position, snap.serial, snap.kind,
                     snap.record_count, snap.source_file or "-"))
    check("beta 的位置按入库先后（serial 回绕不改变位置）",
          [(s.position, s.serial) for s in insp.zones[1].snapshots]
          == [(1, 4294967294), (2, 1)])

    print("\n== 6. 接收：复用前缀，只追加尾段 ==")
    new = Repository("new.db", preserve_unknown=True)
    out = new.receive_handoff("handoff.dhf")
    for o in out.outcomes:
        print("  %s reused=%d appended=%d head=%s"
              % (o.zone, o.reused, o.appended, o.head_serial))
    check("alpha 复用 1 份、追加 2 份",
          out.outcomes[0].reused == 1 and out.outcomes[0].appended == 2)

    print("\n== 7. 交接后照常查询：旧 serial、差异、来源位置 ==")
    check("旧 serial 仍可查",
          [v.serial for v in new.versions("alpha.example.")] == [100, 200, 300])
    recs = new.records("alpha.example.", serial=300)
    www = [r for r in recs if r.owner == "www.alpha.example."
           and r.rtype == "A"][0]
    api = [r for r in recs if r.owner == "api.alpha.example."][0]
    readded = [r for r in recs if r.owner == "old.alpha.example."][0]
    check("未动条目延续 (www 来自 alpha/v1.zone:6)",
          (www.line_no, www.source_file) == (6, "alpha/v1.zone"))
    check("v2 新增条目 (api 来自 alpha/v2.inc:7)",
          (api.line_no, api.source_file) == (7, "alpha/v2.inc"))
    check("删掉后重加 (old 来自 alpha/v3.inc:5)",
          (readded.line_no, readded.source_file) == (5, "alpha/v3.inc"))
    txt = [r for r in recs if r.rtype == "TXT"][0]
    caa = [r for r in recs if r.rtype == "CAA"][0]
    check("TXT 原样搬运", txt.rdata == '"v=spf1 \\"all\\""')
    check("未知类型原样保留", not caa.known
          and caa.rdata == '0 issue "ca.example"')
    diff = new.diff("alpha.example.", 100, 300)
    check("跨交接 diff", any(r.owner == "api.alpha.example."
                             for r in diff.added))
    bdiff = new.diff("beta.example.", 4294967294, 1)
    check("serial 回绕后的 diff", any(r.owner == "host.beta.example."
                                      for r in bdiff.added))

    print("\n== 8. 独立 SQL 核对内容与起源 ==")
    def dump(db):
        conn = sqlite3.connect(db)
        rows = conn.execute(
            "SELECT z.name, v.serial, v.kind, v.source_file, v.created_at,"
            "       r.owner, r.rtype, r.ttl, r.rdata, r.known, r.line_no,"
            "       iv.serial "
            "FROM records r JOIN versions v ON v.id = r.version_id "
            "JOIN zones z ON z.id = v.zone_id "
            "JOIN versions iv ON iv.id = r.introduced_in "
            "WHERE v.status = 'published' "
            "AND z.name IN ('alpha.example.', 'beta.example.') "
            "ORDER BY 1, 2, 6, 7, 9").fetchall()
        conn.close()
        return rows
    check("两库中交接对象的全部历史逐条一致", dump("old.db") == dump("new.db"))
    check("不交的 zone 没有越过", new.current("keep.example.") is None)
    check("无关的 other.example. 未受影响",
          new.current("other.example.").serial == 42)

    print("\n== 9. 原样再接收：无新增、无修改 ==")
    again = new.receive_handoff("handoff.dhf")
    check("第二遍 appended=0", again.appended == 0)

    print("\n== 10. 在交接末端接着用现有增量发布 ==")
    new.publish_increment(
        "$ZONE alpha.example.\n$PREREQ 300\n$SERIAL 400\n"
        "$ADD\nnew 300 IN A 192.0.2.200\n$END", source_file="followup.inc")
    new.publish_increment(
        "$ZONE beta.example.\n$PREREQ 1\n$SERIAL 2\n"
        "$ADD\nsecond 300 IN A 10.0.0.2\n$END")
    check("alpha 头落在 400", new.current("alpha.example.").serial == 400)
    check("beta 头落在 2", new.current("beta.example.").serial == 2)
    new.close()

    print("\n交接演示完成：历史已衔接，日常发布在末端继续。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
