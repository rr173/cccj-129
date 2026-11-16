# 离线 DNSSEC 信任链核验工具

对**已发布的历史签名区快照**做只读、离线的 DNSSEC 信任链核验。工具不查询真实
DNS、不发布或改写任何区域版本，只读取调用者显式列出的精确 `(zone, serial)`
快照，并在给定 UTC 时刻判断能否从指定信任锚验证到目标区域，同时定位验证失败的
具体记录及其仓库来源（文件、行号）。

## 1. 设计原则与安全边界

| 要求 | 实现方式 |
| --- | --- |
| 完全离线 | 无任何网络调用；密钥、签名、摘要全部本地计算 |
| 只读 | 核验使用 `mode=ro` + `PRAGMA query_only=ON` 的 SQLite 连接，写操作被数据库直接拒绝（已测试） |
| 不跟随当前区头 | 只打开清单里列出的精确 `(zone, serial)`，不存在“最新版本”概念 |
| 不可变历史 | 同一 `(zone, serial)` 重复装载会被拒绝；表主键为 `(zone, serial)` |
| 单一读视图 | 一次核验全程复用同一个只读连接；数据库运行在 WAL 模式，读到的是已提交内容 |
| 不触达数据库外状态 | 除报告文件外无其它写操作；报告原子落盘且拒绝覆盖 |
| 流式、低内存 | 逐 RRset 经索引查询取回，单组处理完即释放，不把整区记录/密钥/签名常驻内存 |
| 确定性 | 报告按 `(zone, owner, type)` 稳定排序；相同输入与时刻产生相同结果 |

结论分三级：

- `PASS` —— 信任链建立且所需签名均验证成功；
- `FAIL` —— 材料存在但密码学校验失败，或出现明确的篡改条件；
- `INCONCLUSIVE`（无法判定）—— 缺快照、缺中间祖先、缺验证材料或遇到不支持的算法，
  **绝不**把这种情况报成通过或篡改。
- 另有中性的 `SKIPPED`，仅用于委派切点处父区不权威签名的 glue/NS（RFC 4035），
  切点处的 DS 仍由父区正常验签。

## 2. 支持的算法

签名算法（DNSKEY/RRSIG algorithm）：RSASHA1(5)、RSASHA1-NSEC3-SHA1(7)、
RSASHA256(8)、RSASHA512(10)、ECDSAP256SHA256(13)、ECDSAP384SHA384(14)、
ED25519(15)、ED448(16)。

DS 摘要算法：SHA-1(1)、SHA-256(2)、SHA-384(3)、SHA-512(4)。

任何不在表内的算法号都会产生 `INCONCLUSIVE` 并附 `UNSUPPORTED_*` 发现，而不是
通过或失败。

## 3. 目录结构

```
dnssec-verify/
├── dnssec_verify.py            # -I 隔离模式入口
├── dnssecverify/               # 被测包
│   ├── wire.py                 # 线格式、规范名称、RDATA、key tag、DS/NSEC3 哈希
│   ├── crypto.py               # 密钥加载、RRSIG 签名输入、验签、DS 匹配
│   ├── zonefile.py             # 区快照解析（带来源文件/行号）、信任锚装载
│   ├── store.py                # WAL SQLite 存储与逐 RRset 流式只读 API
│   ├── verifier.py             # 信任链与逐 RRset 核验引擎
│   ├── engine.py               # 清单校验、前置拒绝、编排、确定性报告
│   └── cli.py                  # load / verify / list / checksum 子命令
├── tests/
│   ├── make_snapshots.py       # 真实密钥/签名生成（独立于验签代码）
│   ├── build_fixtures.py       # 9 类签名场景夹具
│   ├── oracle_check.py         # dnspython 第二实现，独立产出预期
│   ├── run_unit_tests.py       # 协议级单元测试（与 dnspython/手工 RFC 向量对照）
│   ├── run_all_tests.py        # 端到端场景 + oracle 交叉核对
│   ├── build_large.py          # 十万级历史库构造
│   ├── run_large_test.py       # 规模、峰值内存、只读校验
│   └── tests_helper_collision.py
├── samples/fixtures/           # 可独立核对的签名样例
├── samples/reports/            # 核验报告输出
├── db/                         # SQLite 数据库（WAL）
└── run_reproducible.sh         # 一键复跑
```

## 4. 输入格式

### 4.1 区快照文件（RFC 1035 master 文本）

支持 `$ORIGIN`、`$TTL`、括号续行、相对名、`@`、TTL 单位（S/M/H/D/W）、注释。
每条记录的来源行号都会入库。示例：

```text
$ORIGIN sub.example.
$TTL 3600
sub.example. 3600 IN SOA ns1.sub.example. hostmaster.sub.example. (
                    2000 7200 3600 1209600 3600 )
sub.example. 3600 IN DNSKEY 257 3 13 <base64 公钥>
www.sub.example. 3600 IN A 198.51.100.7
www.sub.example. 3600 IN RRSIG A 13 3 3600 1700086400 1699913600 13129 sub.example. <base64 签名>
```

### 4.2 信任锚 JSON

```json
{
  "anchors": [
    {
      "zone": "example.",
      "record": {
        "type": "DS",
        "key_tag": 52683,
        "algorithm": 13,
        "digest_type": 2,
        "digest": "16acd7ec...（十六进制）"
      },
      "source": "信任锚来源说明"
    }
  ]
}
```

也支持 `type: "DNSKEY"`（字段 `flags/protocol/algorithm/pubkey`，pubkey 为
base64；或用 `pubkey_hex`）。同一区域同时给 DS 和 DNSKEY 锚、或给出完全重复的锚，
都会在开始核验前被拒绝并标注位置。

### 4.3 核验清单 JSON

```json
{
  "verification_time_utc": "2023-11-14T22:13:20Z",
  "snapshots": [
    {"zone": "example.", "serial": 1000},
    {"zone": "sub.example.", "serial": 2000}
  ]
}
```

- 时间必须带时区（`Z` 或偏移）；RRSIG 有效期按该 UTC 秒判定，端点含边界。
- 清单必须从锚点区**连续覆盖**到每个目标区。
- 缺 serial：开始前整体 `REJECTED`，不产出任何“部分通过”报告。
- 缺中间祖先快照：可达部分照常核验，断裂点及下游为 `INCONCLUSIVE`。

## 5. 命令

```bash
# 装载一个历史快照（重复 (zone,serial) 会被拒绝）
python3 -I dnssec_verify.py load \
  --database db/fixtures.db \
  --snapshot samples/fixtures/rollover/example-1000.zone

# 核验（报告已存在则拒绝覆盖；REJECTED 不写报告）
python3 -I dnssec_verify.py verify \
  --database db/fixtures.db \
  --anchor samples/fixtures/rollover/anchors.json \
  --manifest samples/fixtures/rollover/manifest.json \
  --report samples/reports/rollover.json

python3 -I dnssec_verify.py list     --database db/fixtures.db
python3 -I dnssec_verify.py checksum --database db/fixtures.db
```

退出码：`0` 整体 PASS；`1` 整体 FAIL/INCONCLUSIVE（报告已写）；`2` 用法/覆盖类
错误；`3` 前置拒绝（无报告）。

## 6. 信任建立与验签规则

1. **锚点区**：提交的 DS 必须摘要匹配区里某条 DNSKEY（或直接提交 DNSKEY 锚做
   全量字节相等）。匹配基于完整 DNSKEY RDATA，而非 key tag。
2. **父子链**：父区中针对子区的 DS RRset 先由父区已认证密钥验签；每条 DS 再按
   RFC 4034 5.1.4 对 `owner 名 || DNSKEY RDATA` 做摘要比对。
3. **DNSKEY 自证**：子区 apex DNSKEY RRset 必须存在至少一条由已认证密钥验证成功
   的 RRSIG，之后集合中其它密钥才被信任。
4. **区内权威 RRset**：按 owner/type/class/TTL 与全部成员构造 RFC 4034 6.3
   规范签名输入（RDATA 规范排序、名称小写、原始 TTL、通配符 labels 规则）。
   多份签名中**任一份**由已认证密钥验证成功即通过；过期、类型不符或验签失败的旧
   签名不影响有效签名，但会逐条记录原因与行号。
5. **轮换**：正确处理多条 DS、多个 DNSKEY、多份 RRSIG 的组合。key tag 与算法号
   相同**不足以**认定同一把密钥——必须公钥全量一致；伪造同 tag 同算法、不同公钥
   的密钥无法通过 DS 摘要或 RRSIG 验证。
6. **切点**：父区中切点以下的 NS 与 glue A/AAAA 标记 `SKIPPED`；切点 DS 仍由
   父区验签。

## 7. 可复跑样例与独立预期

`tests/` 下的预期不是由被测代码产生的：

- 签名由独立的 `cryptography` 原语生成；
- `oracle_check.py` 使用**另一个 DNSSEC 实现 dnspython 2.9.2** 重新解析同一快照、
  重建 RRset 并独立验签，逐 RRset 与被测系统比对；
- key tag 与 DS 摘要另外用 RFC 4034 附录 B/5.1.4 的手工算法和 dnspython 双向核对。

场景覆盖（见 `samples/fixtures/`）：

| 目录 | 场景 | 预期整体结论 |
| --- | --- | --- |
| `rollover` | 父/子两区，新旧 DNSKEY、双 DS、多份 RRSIG；选定时刻新链有效、旧签名过期 | PASS |
| `spoof` | 同 key tag+算法、不同公钥的冒充密钥 | FAIL |
| `expired` | 仅过期签名的 RRset，其它记录签名有效 | FAIL |
| `no-ds` | 父区缺少子区 DS | FAIL |
| `coverage` | 签名覆盖集合被增改、RRSIG labels 字段错误 | FAIL |
| `wildcard` | 通配符 owner 与 labels 规则 | PASS |
| `gap` | 三级链中中间祖先快照缺失 | INCONCLUSIVE |
| `unsupported` | 不支持的算法号 99 | INCONCLUSIVE |
| `rsa-ttl` | RSA-SHA256(alg 8) 正常签名；同一 RRset 成员 TTL 不一致 | FAIL |
| `anchor-problems` | 重复/冲突信任锚 | REJECTED |

一键复跑：

```bash
./run_reproducible.sh
```

## 8. 规模与只读实测结果（参考环境）

- 204,960 条历史记录、120 个 serial 版本入库约 9 秒；
- 单版本 854 个 RRset 的完整核验约 0.2 秒；
- 峰值常驻内存约 **29.6 MiB**，与区大小无关（逐 RRset 流式处理）；
- 核验前后逻辑校验和一致，核验后可重新 `list/checksum`，内容未变；
- 只读连接上的 INSERT/DELETE/CREATE/PRAGMA 写操作均被 SQLite 拒绝。

## 9. 依赖

- Python 3.11 标准库（SQLite 3.40）；
- `cryptography`（RSA/ECDSA/Ed25519/Ed448 验签），安装在独立目录并以
  `sys.path` 显式引入，运行全程使用 `python3 -I` 隔离模式，不加载当前目录或
  不可信数据目录中的模块；
- `dnspython` **仅**测试对照使用，被测包不依赖它。
