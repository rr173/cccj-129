# dnsrepo — DNS 区域文件接入器

面向域名资产仓库的区域文件接入器：解析**主区文件**与**增量区文件**，校验后发布为
SQLite 中可查询的不可变版本，支持版本差异、当前区查询与本地区文件生成。纯本地
运行，不查询真实 DNS。

## 功能总览

- 主区文件解析（RFC 1035 子集）：`$ORIGIN` / `$TTL`、相对名称、`@`、括号续行、
  `;` 注释、省略属主（行首空白继承上一条属主）、TTL 与 `IN` 类任意顺序
- 项目限定记录类型：**A、AAAA、CNAME、MX、TXT、NS、SOA**；rdata 中的相对名称
  一律按当前 origin 展开为绝对名
- 增量文件：`$ADD` / `$REPLACE` / `$DELETE` 指令，声明 `$PREREQ` 前置 serial，
  仅当与当前基线一致时才应用
- 发布前校验，失败即拒绝发布：
  - 记录属主越出区域边界（out-of-zone）
  - CNAME 与其他数据（含保留的未知类型）共存于同一属主
  - CNAME 别名环（含自环）
  - serial 不递增（RFC 1982 序列号算术，支持回绕）
  - SOA 必须恰好一条且位于顶点，serial 与版本声明一致
- 版本化存储：每次发布是全量快照的**单事务**写入；发布中断（异常/进程被杀）
  整体回滚，不留半成品；每条记录保留**来源行号**与引入版本（可溯源到源文件）
- 未知记录类型：默认拒绝；配置 `preserve_unknown=True` 后按**原文**保留
  （空白归一化），不参与任何语义解释，可正常导出与 diff
- 查询与导出：按名称/类型查询当前区、区内 CNAME 链解析、任意两版本 diff、
  将任意版本渲染为规范主区文件并**原子写盘**（临时文件 + rename）
- 离线批处理：流量归属（连接 × 网段 → 可分团队核算的字节明细）与证书透明度
  观测导入（CT 观测 × 指定历史版本 → 待核查主机名发现）；两者都只读仓库、
  不查真实 DNS、不发布记录
- 离线历史交接：从旧库选出若干 zone 及各自截止 serial 打出自包含交接包，
  接收库核查后把能衔接的历史接进自己的库（复用相同前缀、只追加尾段），
  交接末端继续日常增量发布

## 文件格式

### 主区文件

```
$ORIGIN example.com.
$TTL 3600
@   IN  SOA ns1 hostmaster ( 2024010100 7200 3600 1209600 300 )
    IN  NS  ns1
www 300 IN  A   192.0.2.80
alias   CNAME   www
_text   TXT     "v=spf1 -all"
```

- 区域名由发布方指定（`publish_master(zone, text)`）；文件内 SOA 必须位于该
  区域顶点，SOA serial 即版本 serial
- TTL 缺省顺序：显式 TTL → 此前的 `$TTL` → SOA minimum（RFC 2308）
- TXT 支持多字符串与转义：`\"`、`\\`、`\DDD`（三位十进制）

### 增量文件

```
$ZONE example.com.
$PREREQ 2024010100      ; 前置 serial：必须等于仓库当前 serial
$SERIAL 2024010101      ; 新版本 serial：必须按 RFC 1982 大于前置

$ADD
api 600 IN A 192.0.2.50           ; 新增（同名同数据已存在则报错）

$REPLACE
www 300 IN A 192.0.2.90           ; 重定义 (owner, type) 整个 RRset

$DELETE
mail A                            ; 删除 mail 的 A RRset
junk                              ; 删除 junk 名下所有记录
gone TXT "obsolete"               ; 删除指定单条记录
$END
```

- `$ZONE` / `$PREREQ` / `$SERIAL` 必须位于任何段之前；段内记录语法与主区文件
  一致（可用 `$TTL`；无 TTL 时回落到基线 SOA minimum）
- 增量未触及 SOA 时，系统自动把顶点 SOA serial 提升为 `$SERIAL`（该行
  `line_no` 为 NULL，表示合成记录）；若增量自行替换 SOA，其 serial 必须等于
  `$SERIAL`
- 冲突指令（同一 RRset 既 `$ADD` 又 `$REPLACE`、既 `$DELETE` 又 `$REPLACE`）
  与删除不存在的记录都会在应用前报错

## 使用

### 库

```python
from dnsrepo import Repository

repo = Repository("assets.db", preserve_unknown=True)
repo.publish_master("example.com.", open("v1.zone").read(),
                    source_file="v1.zone")
repo.publish_increment(open("v2.inc").read(), source_file="v2.inc")

repo.current("example.com.")                 # 当前版本信息
repo.versions("example.com.")                # 全部已发布版本
repo.records("example.com.", serial=2024010100)   # 任意版本快照（含来源行号）
repo.lookup("example.com.", "www", "A")      # 当前区按名查询
repo.resolve("example.com.", "alias", "A")   # 沿区内 CNAME 链解析
print(repo.diff("example.com.", 2024010100, 2024010101).format())
repo.export_file("example.com.", path="out/example.com.zone")  # 原子写盘
```

### 命令行

```
python -m dnsrepo --db assets.db publish-master example.com. v1.zone
python -m dnsrepo --db assets.db publish-increment v2.inc
python -m dnsrepo --db assets.db zones
python -m dnsrepo --db assets.db history example.com.
python -m dnsrepo --db assets.db query example.com. www A
python -m dnsrepo --db assets.db resolve example.com. alias A
python -m dnsrepo --db assets.db diff example.com. 2024010100 2024010101
python -m dnsrepo --db assets.db export example.com. -o example.com.zone
python -m dnsrepo --db assets.db ct-import observations.jsonl out \
    --repo assets.db --zone example.com. --serial 2024010100
python -m dnsrepo --db old.db handoff-pack handoff.dhf example.com.=2024010101
python -m dnsrepo handoff-inspect handoff.dhf
python -m dnsrepo --db new.db handoff-receive handoff.dhf
```

加 `--preserve-unknown` 后未知类型按原文保留。

## 离线流量归属（批处理）

连接汇总（`flow_id`、`dst_ip`、`start_ms`、`end_ms`、`bytes`）与网段归属
（`cidr`、`owner`、`valid_from_ms`、`valid_to_ms`）各是一个 UTF-8 JSONL
文件。批处理把它们拆成**可分团队核算的归属明细**，不改写任何区域版本：

```
python3 -m dnsrepo --db assets.db attribute flows.jsonl ownership.jsonl out \
    [--repo assets.db --zone example.com. --serial 2024010100]
```

### 输入字段

连接行：

| 字段 | 规则 |
| --- | --- |
| `flow_id` | 非空字符串，同文件内不得重复 |
| `dst_ip` | 合法 IPv4 或 IPv6 地址；IPv4-mapped IPv6 仍按 IPv6 处理 |
| `start_ms` / `end_ms` | 64 位有符号整数，`start_ms < end_ms`，区间左闭右开 |
| `bytes` | 64 位有符号整数，`>= 0` |

归属行：

| 字段 | 规则 |
| --- | --- |
| `cidr` | 规范 CIDR（无主机位），IPv4 或 IPv6 |
| `owner` | 非空字符串 |
| `valid_from_ms` / `valid_to_ms` | 64 位有符号整数，`from < to`，左闭右开 |

非法行报 `文件:1起始行号` 并整批拒绝。空连接文件产出空明细。

### 归属规则

对每个目的 IP 的每个时刻，只看**当时有效且包含该 IP** 的归属行，取
**最长前缀**：

- 最长前缀下只有一个不同 `owner` → `assigned`
- 最长前缀下多个不同 `owner` → `ambiguous`，列出排序后的 owner；不挑一个、
  不退回更宽网段、不重复计量
- 没有候选 → `unassigned`
- 同一 owner 的重复行不制造歧义；窄网段失效后可重新落到仍有效的宽网段

连接按状态与 owner 集合切成**最大连续区间**（相同状态与 owner 集合的相邻
片段合并）。被更窄网段遮住的宽网段边界、同归属重复资料的边界，都不会留下
无意义切口。

### 字节分摊（整数、守恒）

每条连接的 `bytes` 在**最终合并后**的片段间分摊：

1. 每段先取 `floor(bytes * 时长 / 总时长)`；
2. 剩余字节按余数从大到小逐一补足，余数相同按片段开始时间较早者优先；
3. `assigned`、`ambiguous`、`unassigned` 全部参与；零字节片段保留。

不使用浮点；每条连接的片段时间无缝覆盖原区间，字节和等于输入。

### 输出

`out/details.jsonl`（按输入行号、片段起点排列）：

| 字段 | 说明 |
| --- | --- |
| `flow_id` / `line_no` | 原连接标识与该输入文件的 1 起始行号 |
| `dst_ip` | 目的地址 |
| `start_ms` / `end_ms` | 片段区间（左闭右开） |
| `status` | `assigned` / `ambiguous` / `unassigned` |
| `owners` | `assigned` 为单元素列表，`ambiguous` 为排序后列表，否则为空 |
| `bytes` | 该片段分摊到的整数字节 |
| `dns_owners` | 指定版本内直接 A/AAAA 指向该 IP 的属主，去重排序；未指定时为空 |

`out/summary.json`：`flows`、`fragments`、`bytes`、`status_bytes`
（各状态总字节）、`owner_bytes`（各 assigned owner 的字节）。歧义字节
只计入 `status_bytes.ambiguous`，不分配给任何候选 owner。附版本标签时另含
`dns_version`。

可选 `--repo/--zone/--serial` 三者必须同时给出：只读打开仓库，取**指定
serial** 的直接 A/AAAA 记录属主作为资产标签，不解析别名、不查真实 DNS、
不随当前区头变化、不写入原仓库；指定版本不存在则整批拒绝。

### 交付与规模

- 目标目录已存在 → 拒绝覆盖；整批校验、归属与核算都成功后才 `rename`
  到位；任何失败都不留可误认成功的正式目录（临时工作目录会清理）。
- 连接与归属行分块写入临时 SQLite 索引；查询走
  `(family, prefix_key, prefix_len)` 索引，每条连接只探测数据中实际出现的
  前缀长度，不逐连接全表扫描。内存上界是单条连接的候选行与合并片段；
  明细流式写入磁盘，DNS 标签与 owner 汇总也在磁盘表里，SQLite 缓存各限
  16 MB。
- 可复现样例见 [`examples/attribute/`](examples/attribute/README.md)。

## 离线证书透明度观测导入（批处理）

安全同事从多个 CT 导出源收到证书观测记录（UTF-8 JSONL），批处理把它们变成
一份**待核查发现清单**：某个已管理区域里曾公开出现、但指定已发布区域版本还
没有收录的主机名，并保留哪些证书与来源支撑了每条线索。它**不发布 DNS 记
录**，也不把证书出现解释为域名所有权证明。

```
python3 -m dnsrepo --db assets.db ct-import observations.jsonl out \
    --repo assets.db --zone example.com. --serial 2024010100
```

可一次给多个观测文件（依次合并）：

```
python3 -m dnsrepo --db assets.db ct-import a.jsonl b.jsonl out \
    --repo assets.db --zone example.com. --serial 2024010100
```

### 输入字段

| 字段 | 规则 |
| --- | --- |
| `source` | 非空字符串，观测来源（导出源） |
| `observed_at_ms` | 有符号 64 位整数 |
| `certificate_sha256` | 64 位十六进制 SHA-256，比较/输出统一小写 |
| `dns_names` | 字符串数组，可含重复与等价写法 |

字段缺失、类型错误、无效摘要或无效主机名一律报 `文件:1起始行号` 并拒绝整批；
失败不留下正式结果目录。空行与首字节 UTF-8 BOM 忽略。

### 名称规范化与区域边界

1. 去末尾根点、统一小写；国际化标签按标准库 IDNA(2003) 编成小写 A-label
   （`bücher` ↔ `xn--bcher-kva`）。
2. 非法标签、空标签、超长标签/名称、非最左侧通配符、多个通配符拒绝该行。
3. 合法的最左侧 `*.` **保留为通配符线索**，绝不扩展成具体主机名。
4. 名称必须落在 zone 标签边界内：`example.net.evil` 不属于 `example.net`。
5. 区域顶点本身、以及**指定版本内已直接存在的属主名**不作为新发现输出。
   区域记录与 CNAME 目标不会混入 CT 证据；CNAME 目标既不会因此变成
   “已存在名称”，也不会被当作观测。

### 合并规则

- 按规范化名称合并；跨来源同一证书只计一张证书，同一证书内重复名称只计一次。
- 完全相同的 `(source, certificate_sha256, observed_at_ms)` 重复行折叠；
  该键对应不同的规范化名称集合时**整批拒绝**并指出首次出现的位置与冲突行。
- 同一规范名同时有普通证书和通配符观测时分别成行，通配符与其覆盖的具体名称
  之间互不推断。
- 明细按规范化名称排序，证书、来源与证据列表稳定排序；输入行重排或重复不改变
  汇总数值与证据集合。

### 输出

`out/findings.jsonl`（按 `name` 排序）：

| 字段 | 说明 |
| --- | --- |
| `name` | 规范化小写 ASCII 绝对名（带末尾根点），通配符保留最左侧 `*.` |
| `wildcard` | 是否为通配符线索 |
| `first_observed_at_ms` / `last_observed_at_ms` | 该名称全部观测的最早/最晚时间 |
| `certificate_count` / `certificates` | 去重证书数 / 排序后的 SHA-256 列表 |
| `sources` | 排序后的来源列表 |
| `evidence` | 按 `(source, certificate_sha256)` 排序：来源、摘要、首末观测时间、观测次数 |

`out/summary.json`：`input`（文件、行数、观测数、名称出现次数、折叠重复数、
名称数）、`certificates`（观测证书数 / 支撑发现的证书数）、`findings`（名称数、
通配符数、普通名称数、证据观测数、证书数）、`excluded`（`out_of_zone`、
`zone_apex`、`existing`）、`observed_at_ms`（全局最早/最晚，空输入为
`null`）、`zone`（固定读取的 zone/serial 与该版本记录数）、`sources`
（按来源的观测/重复/证书/发现数与时间范围）。`out/notes.md` 是处理说明。

### 只读、原子交付与规模

- `--repo` 指向已有仓库，`--zone`/`--serial` 必须指向一个**已发布版本**；
  以 `mode=ro`（无 `-wal` 时再加 `immutable=1`）只读打开，不跟随当前区头、
  不写入仓库，也不留下 `-wal`/`-shm` 旁文件。
- 目标目录已存在 → 拒绝覆盖；整批校验、合并与汇总成功后才 `rename` 到位，
  任何失败都不留可误认成功的目录。
- 观测、名称与证书合并全部落在临时 SQLite 索引（`cache_size` 各限 16 MB），
  明细逐行流式写出，不把观测、证书或名称映射常驻内存。20 万观测、约 2 万个
  发现名称、约 5000 张证书的生成数据（37 MB 输入）峰值 RSS 约 35 MB。
- 可复现样例见 [`examples/ct/`](examples/ct/README.md)。

## 离线历史交接（交接包）

机房撤并时，旧库要把一部分 zone 的历史移交给**已经在使用**的接收库：不能
拿旧库整体覆盖，也不能把历史压扁成一份今天才导入的区文件。交接分三步：
旧库**打包** → 接收方**核查** → 接收库**接入**。可复跑示例见
[`examples/handoff/`](examples/handoff/README.md)。

### 交接单与打包

```
python3 -m dnsrepo --db old.db handoff-pack handoff.dhf \
    alpha.example.=300 beta.example.=1
```

```python
from dnsrepo import pack_handoff
pack_handoff("old.db", {"alpha.example.": 300, "beta.example.": 1},
             "handoff.dhf")
```

- 每个 zone 只可选一次；所选截止 serial 必须已经成功发布。
- 包中包含该 zone **第一次发布至截止点的每一份已发布快照**（位置按入库
  先后编号，serial 回绕不改变位置），排除后续历史与未选对象。
- 打包期间旧库可继续读写：所有选择、版本与条目来自**同一次一致读视图**
  （WAL 下的一条读事务，不停写、不执行 Store 的初始化/恢复更新，也不漏掉
  已提交内容）。另一进程用一个事务同时更新两个 zone 时，包要么看到两个
  新、要么看到两个旧，绝不只带走一半。
- 打包目标路径必须不存在（拒绝覆盖）；包先写临时文件、算完整性摘要后
  原子落位，中途失败的包不会被识别为完成。

### 包格式（自包含、可核查）

UTF-8 JSON Lines，每行一个对象（键排序的规范 JSON）：

```
{"type":"header","format":"dnsrepo-handoff","format_version":1,...}
{"type":"zone","name":"alpha.example.","snapshots":2}
{"type":"snapshot","zone":"alpha.example.","position":1,"serial":100,
 "kind":"master","source_file":"alpha/v1.zone","created_at":"...","records":7}
{"type":"record","owner":"www.alpha.example.","rtype":"A","ttl":300,
 "rdata":"192.0.2.80","known":true,"line_no":6,
 "origin_zone":"alpha.example.","origin_position":1,
 "source_file":"alpha/v1.zone"}
...
{"type":"trailer","zones":2,"snapshots":5,"records":27,"sha256":"..."}
```

- 每份快照记录 `serial`、`kind`、`source_file`、`created_at`；每个条目记录
  `owner`、`rtype`、`ttl`、`rdata`、`known`、`line_no` 与**最初引入它的快照
  位置**（`origin_zone` + `origin_position`）。源库的行 id 没有跨库含义，
  起源一律用包内位置坐标连接。
- `source_file`、`line_no` 可以是 `null`；`null` 与空字符串、其他行号都
  不相等。已存文本（含 TXT 与未知类型）按原值搬运，不绕区文件解析。
- 来源路径只是字符串：接收程序不会据此打开文件或执行命令。
- trailer 的 `sha256` 覆盖此前全部行：截断与篡改在语义检查前就会被发现。

### 核查（独立入口）

```
python3 -m dnsrepo handoff-inspect handoff.dhf
```

```python
from dnsrepo import inspect_handoff
report = inspect_handoff("handoff.dhf")   # zones -> snapshots -> 条目数
```

列出交接对象、每份快照的位置/serial/kind/来源/条目数，并校验完整性与
语义：重复 zone/serial、错误发布次序（RFC 1982 不递增）、坏字段、不符合
现有 zone 语义的快照（越界属主、SOA 不唯一或 serial 不符、CNAME 冲突等）
一律拒绝。起源坐标只能落在本 zone 的当前或更早位置；对应起源快照里必须
存在各字段一致、且自指该起源的条目。指向别区、未来、不存在的版本，或
声称的来源文件与起源元数据不符，均为坏包。核查不猜测原文件内容，也不
恢复当年的操作指令。

### 接入裁定（只有"可衔接"或"冲突"）

设包内某 zone 的历史为 `P1…Pn`，接收库已有 `T1…Tm`（缺少的 zone 按
`m=0` 处理）：

- **可衔接**：`m ≤ n` 且每个 `Ti` 与 `Pi` 相同。"相同"是整份快照的元数据
  （serial、kind、source_file、created_at）、条目（owner/rtype/ttl/rdata/
  known/line_no）与起源坐标全部相同；只忽略条目排列与数据库行 id。即便
  DNS 答案相同，起源、行号或发布时间不同也不能复用。
- **冲突**：`m > n`（接收库历史更长，不退头），或任一位置不相同（不凭
  serial 较新就覆盖另一条历史）。冲突报告定位 zone、serial 与不符类别
  （`target-longer` / `serial` / `metadata` / `records`）。

通过后复用前 `m` 份、只追加尾段，各选中 zone 的头落在 `Pn`；其他对象
不受影响。接收时给每个新版本安排目标 id，所有起源引用（含复用前缀指向
的版本）都映射到目标库的正确版本，不直接拷贝整数外键。原样再接收同一
个包：无新增、无修改。

```
python3 -m dnsrepo --db new.db handoff-receive handoff.dhf
```

```python
repo = Repository("new.db")
report = repo.receive_handoff("handoff.dhf")   # 逐 zone 的 reused/appended/head
```

### 原子性与并发

整张交接单是一个提交边界：后面的 zone 冲突、语义检查不成立、包被截断
或篡改、写入中发生真正的数据库错误，都撤销本次全部改动——不留空 zone、
不留半段历史，重新打开库也一样。核对与写入在同一个写事务内完成
（`BEGIN IMMEDIATE` 之后才开始读目标库状态），正常发布或另一个接收者
竞争同一目标时，等待锁之后不会拿等待前的判断继续落库；现有的
`publish-master` / `publish-increment` 也在同一写事务内复核前置 serial，
提前读取了基线的增量不会在交接完成后带着旧前置条件落库。

### 失败后的重新操作

- 打包失败（未知 zone、未发布的 serial、目标已存在）：修正后重打即可，
  源库不受任何影响。
- 核查失败：包损坏或内容不符，重新从旧库打包；接收库尚未被触碰。
- 接入冲突：先解决分歧（例如用正确的包、或确认接收库该 zone 的历史应当
  以哪条线为准后人工调整），再重新接收同一个包；失败的接收没有留下任何
  改动，可安全重试。
- 接入成功后发现需要再交更多历史：用更大的截止 serial 重新打包，接收时
  已衔接的前缀自动复用，只追加新的尾段。

内存上界是当前一份快照加磁盘上的起源索引（临时 SQLite，缓存限 16 MB）：
打包、检查、历史比较与引用查找都不把全包、全部条目或 id 映射装入内存。
11 万条跨版本条目走 `handoff-pack` / `handoff-inspect` /
`handoff-receive` 三条命令各约 1 秒、峰值 RSS 约 32 MB
（`tests/test_handoff.py` 的 ScaleTest）。

## 设计要点

- **发布原子性**：版本行（`publishing`）+ 全量记录 + 头指针切换在同一个
  SQLite 事务内完成；任何中途失败/进程终止都整体回滚。打开库时会兜底把残留
  的 `publishing` 行标记为 `failed`（正常路径下不存在）。
- **写事务边界**：所有"先核对再落库"的路径（发布、交接接收）都在
  `BEGIN IMMEDIATE` 开启的同一事务内完成核对与写入——写锁之后的读才是
  有效判断，竞争同一 zone 的发布/接收不会拿过期基线落库。
- **记录溯源**：`records.introduced_in` 指向引入该记录的版本，`line_no` 是该
  版本源文件中的起始行号；增量携带的记录在后续版本中保持原始行号不变。
- **serial 算术**：RFC 1982。新 serial 必须在序列号空间上严格大于旧 serial
  （差值 ∈ (0, 2³¹)），等于或落在后半空间一律拒绝。
- **未知类型不猜测语义**：保留的是分词后的原文（注释剥离、空白归一化），
  不解析其中的名称；仅在“CNAME 不得与其他数据共存”这一**名称层面**的结构
  性检查中计为数据。
- **名称规范化**：所有域名在解析期转为小写绝对形式（DNS 大小写不敏感）；
  TXT 字符串内容逐字节保留。
- 不支持：`$INCLUDE`、`$GENERATE`、非 IN 类、TTL 单位后缀（如 `1h`）。

## 测试

```
python3 -m unittest discover -s tests -t .
```

覆盖：相对名称展开、TTL 规则、增量前置 serial 冲突、三种删除形式、CNAME 环
与冲突、TXT 转义、未知类型保留/拒绝、发布中断回滚与导出原子性、serial 回绕、
区域边界、版本 diff、记录行号溯源、导出往返一致性。

流量归属另有：手算的宽/窄网段六段用例、时间端点（左闭右开）、同前缀多归属、
重复资料、中途回退宽网段、无关边界合并、字节守恒与余数规则、IPv6 `/0` 与
IPv4-mapped 区分、历史版本 DNS 标签、坏行与重复 `flow_id` 整批拒绝、
与独立毫秒枚举实现的随机交叉核对，以及 20 万归属行 × 20 万连接的生成数据
运行（`tests/test_traffic.py`、`tests/bruteforce.py`）。

证书透明度导入另有：跨源重复证书、证书内重复名称、国际化等价写法、根点与
大小写归一、zone 标签边界、历史 serial 固定、通配符不扩展、普通名称与通配符
分开成行、冲突重复键整批拒绝、空输入、坏行行号、只读仓库不留旁文件、
行重排与重复不改变输出，以及与独立字典实现的随机交叉核对和 20 万观测的生成
数据运行（`tests/test_ct.py`、`tests/ct_reference.py`）。

历史交接另有：可复跑全链路（两待交 zone + 一不交 zone、未动条目延续、删掉后
重加、TXT、未知类型、serial 回绕、接收库 id 错开与相同短前缀、独立 SQL 核对、
幂等再接收、末端继续增量）；打包侧的一致读视图（进程内与跨进程的两 zone 同事务
提交只可能同新或同旧）、源库不被修改、拒绝覆盖；核查侧的重复 zone/serial、
错误次序、坏字段、zone 语义、跨区/未来/缺失起源、来源文件不符（摘要均重算，
截断另测）；接收侧的同值不同来源各类冲突、目标更长、serial 较新不覆盖、
后续 zone 失败整体回滚、数据库写错误回滚并重开验证、接收与发布/另一接收者
竞争不丢历史，以及 11 万条跨版本条目走三条命令的规模运行
（`tests/test_handoff.py`）。
