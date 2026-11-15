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
```

加 `--preserve-unknown` 后未知类型按原文保留。

## 设计要点

- **发布原子性**：版本行（`publishing`）+ 全量记录 + 头指针切换在同一个
  SQLite 事务内完成；任何中途失败/进程终止都整体回滚。打开库时会兜底把残留
  的 `publishing` 行标记为 `failed`（正常路径下不存在）。
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
