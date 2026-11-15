# 离线证书透明度观测导入示例（可复现）

安全同事从多个 CT 导出源收到 UTF-8 JSONL 证书观测记录。本示例演示如何找出
**某个已管理 DNS 区域**中曾公开出现、但指定已发布区域版本还没有收录的主机名，
并回看哪些证书与来源支撑了每条线索。

本功能只生成**待核查的发现清单**：不发布 DNS 记录，也不把证书出现解释为
域名所有权证明。

## 1. 建一个区域版本

```
mkdir -p /tmp/ct-demo && cd /tmp/ct-demo
cat > v1.zone <<'EOF'
$ORIGIN example.com.
$TTL 3600
@   IN  SOA ns1.example.com. hostmaster.example.com. (
        2024010100 7200 3600 1209600 300 )
@   IN  NS  ns1.example.com.
ns1     A       192.0.2.1
www     A       192.0.2.80
mail    A       192.0.2.25
alias   CNAME   www
EOF
python3 -m dnsrepo --db assets.db publish-master example.com. v1.zone
```

## 2. 准备观测文件

`examples/ct/observations-a.jsonl`：

```json
{"source":"ct-log-a","observed_at_ms":1700000000000,"certificate_sha256":"f45ad729...","dns_names":["New.Example.COM.","bücher.example.com"]}
{"source":"ct-log-a","observed_at_ms":1700000000000,"certificate_sha256":"f45ad729...","dns_names":["NEW.EXAMPLE.COM.","xn--bcher-kva.example.com"]}
{"source":"ct-log-b","observed_at_ms":1700000099000,"certificate_sha256":"f45ad729...","dns_names":["new.example.com"]}
```

`examples/ct/observations-b.jsonl`：

```json
{"source":"ct-log-b","observed_at_ms":1700000200000,"certificate_sha256":"684de513...","dns_names":["*.wild.example.com","example.net.evil"]}
{"source":"ct-log-c","observed_at_ms":1700000300000,"certificate_sha256":"20c84cbf...","dns_names":["www.example.com","example.com.","deep.new.example.com"]}
```

两个文件里的摘要都是完整的 64 位十六进制，上面只为排版缩写，可执行样例以
磁盘上的文件为准。

手算预期：

| 名称 | 为什么 | 结果 |
| --- | --- | --- |
| `new.example.com.` | ct-log-a 第 1/2 行是同一 `(来源, 证书, 时间)` 键 → 第 2 行整行重复被折叠；ct-log-b 用另一行报告同一证书 | 1 条线索，首末 `1700000000000`/`1700000099000`，1 张证书，2 个来源 |
| `xn--bcher-kva.example.com.` | `bücher` 与 `xn--bcher-kva` 归一为同一名称；证书内重复名称只计一次 | 1 条线索，1 张证书 |
| `*.wild.example.com.` | 合法最左侧通配符保留为线索，不扩展出具体主机名 | 1 条通配符线索 |
| `deep.new.example.com.` | 区域内新名称 | 1 条线索 |
| `www.example.com.` | 指定版本已直接存在 | 抑制（`existing`） |
| `example.com.` | 区域顶点本身 | 抑制（`zone_apex`） |
| `example.net.evil` | 不在 `example.com.` 的标签边界内 | 抑制（`out_of_zone`） |

合计：4 条线索（1 通配符 + 3 普通），3 张证书，`summary.json` 中
`input.observations = 4`、`input.duplicate_observations = 1`。

## 3. 运行

```
python3 -m dnsrepo --db assets.db ct-import \
    ../examples/ct/observations-a.jsonl \
    ../examples/ct/observations-b.jsonl \
    out --repo assets.db --zone example.com. --serial 2024010100
cat out/summary.json
head out/findings.jsonl
```

输出目录 `out/` 只在整批校验与汇总全部成功后原子改名到位；目标已存在会被
拒绝，失败不留正式目录。仓库始终以只读方式打开，不跟随当前区头，也不写入。

## 4. 输出字段

`out/findings.jsonl`，一行一个规范化名称，按名称排序：

| 字段 | 说明 |
| --- | --- |
| `name` | 规范化后的小写 ASCII 绝对名（带末尾根点）；通配符保留最左侧 `*.` |
| `wildcard` | 该名称是否以最左侧 `*.` 开头 |
| `first_observed_at_ms` / `last_observed_at_ms` | 该名称全部观测的最早/最晚时间 |
| `certificate_count` | 去重后的证书数（同一证书跨来源只计一次） |
| `certificates` | 排序后的 64 位小写 SHA-256 列表 |
| `sources` | 排序后的来源列表 |
| `evidence` | 按 `(source, certificate_sha256)` 稳定排序的证据行：`source`、`certificate_sha256`、`first_observed_at_ms`、`last_observed_at_ms`、`observations`（该组合的观测次数） |

`out/summary.json`：

| 字段 | 说明 |
| --- | --- |
| `input` | 输入文件列表、非空行数、观测数、名称出现次数、折叠的重复行数、不同规范化名称数 |
| `certificates.observed` / `certificates.in_findings` | 观测中出现的不同证书数 / 支撑发现的证书数 |
| `findings` | 发现名称数、通配符数、普通名称数、证据观测数、证书数 |
| `excluded` | `out_of_zone`、`zone_apex`、`existing` 三类被抑制的名称出现次数 |
| `observed_at_ms` | 全部观测的最早/最晚时间；空输入为 `null` |
| `zone` | 固定读取的区域、serial、该版本记录数与直接属主名数 |
| `sources` | 按来源分组的观测数、重复数、证书数、发现数、时间范围 |

`out/notes.md` 是本次运行的处理说明（规则、边界、抑制、只读约束、输入与版本）。
