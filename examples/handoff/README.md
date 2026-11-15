# 离线历史交接示例（可复跑）

机房撤并，旧库要把一部分 zone 的**历史**交给已在使用的接收库：不能拿旧库
整体覆盖，也不能把历史压扁成一份今天才导入的区文件。本示例演示完整流程：
旧库选 zone 和截止 serial 打出交接包，接收方核查后把能衔接的历史接进自己
的库，然后在交接末端继续日常增量发布。

## 运行

```
python3 examples/handoff/demo.py [工作目录]
```

不给目录时使用临时目录。脚本逐步打印并自检，任何不符以非零状态退出。

## 场景

旧库 `old.db`：

| zone | 版本（serial） | 覆盖点 |
| --- | --- | --- |
| `alpha.example.` | 100 → 200 → 300 | 未动条目延续、删掉后重加、TXT 转义、保留未知类型（CAA） |
| `beta.example.` | 4294967294 → 1 | serial 回绕；位置仍按入库先后 |
| `keep.example.` | 5 | 不交接，留在旧库 |

接收库 `new.db` 已在使用：先录入无关的 `other.example.`（内部 id 与旧库
错开），再通过一个更早的小包接入 `alpha.example.` 的第一份快照——这就是
接收库里**真正相同的短前缀**。

主交接包选中 `alpha.example.=300`、`beta.example.=1`。接收时 alpha 复用
已有的第 1 份、只追加第 2、3 份；beta 整段接入；`other.example.` 与
`keep.example.` 各自不受影响。

## 逐步骤对应命令

```bash
# 旧库操作员：每个 zone 选一次，终点必须是已发布 serial
python3 -m dnsrepo --db old.db handoff-pack handoff.dhf \
    alpha.example.=300 beta.example.=1

# 接收方：先核查（完整性 + 语义，列出对象/位置/条目数）
python3 -m dnsrepo handoff-inspect handoff.dhf

# 核查通过后接入（整张交接单一个提交边界）
python3 -m dnsrepo --db new.db handoff-receive handoff.dhf

# 之后一切照旧
python3 -m dnsrepo --db new.db history alpha.example.
python3 -m dnsrepo --db new.db diff alpha.example. 100 300
python3 -m dnsrepo --db new.db publish-increment followup.inc
```

Python 侧对应 `pack_handoff(old_db, {zone: serial}, path)`、
`inspect_handoff(path)` 与 `Repository(db).receive_handoff(path)`。

## 预期要点

* 接收后旧 serial 仍可查、可 diff，记录仍指向当时的来源文件与行号；
  TXT 与未知类型按原值搬运。
* 原样再接收同一包：无新增、无修改（幂等）。
* 若接收库已有同 zone 历史但**任何**业务字段（含起源、行号、发布时间）
  不一致，或接收库历史比包更长：整体冲突、全部回滚，不会退头也不会覆盖。
* 打包期间旧库可继续读写；包内所有内容属于同一次一致读视图。
