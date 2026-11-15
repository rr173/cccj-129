# 离线流量归属示例（可复现）

数据为两份 UTF-8 JSONL。在仓库根目录执行：

```
rm -rf /tmp/attribution-demo && mkdir -p /tmp/attribution-demo
cp examples/attribute/flows.jsonl examples/attribute/ownership.jsonl \
   /tmp/attribution-demo/
python3 -m dnsrepo --db /tmp/attribution-demo/repo.db \
    attribute /tmp/attribution-demo/flows.jsonl \
               /tmp/attribution-demo/ownership.jsonl \
               /tmp/attribution-demo/out
cat /tmp/attribution-demo/out/summary.json
```

`hand-1` 是需求中的手算用例：连接 `[10,110)` 共 17 字节，宽网段 owner A
在 `[0,100)`，更窄的 B 在 `[20,40)`，最窄的 C 在 `[30,35)`。输出六段，字节
依次为 2、2、1、1、10、1。

如果还要附上某个已发布版本的直接 A/AAAA 属主标签（只读打开仓库，不改变
区头，也不写入仓库）：

```
python3 -m dnsrepo --db assets.db attribute flows.jsonl ownership.jsonl out \
    --repo assets.db --zone example.com. --serial 2024010100
```

`out/details.jsonl` 每行是一段归属明细，`out/summary.json` 是核算汇总。
目录只在全部校验与核算成功后才出现；目标已存在会被拒绝，失败不留目录。
