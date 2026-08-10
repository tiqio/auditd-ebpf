# Contract: 单行审计事件格式

## Transport

- 审计事件和审计缺口写 stdout；诊断与周期状态写 stderr。
- 每条记录恰好一行，以单个 LF 结束；记录内容内部禁止原始 CR/LF/NUL。
- 最大输出行 16 KiB。超过时按字段优先级截断，并设置 `truncated=yes` 与字段级原因。
- stdout 成功写入只表示交付到服务日志管道，不表示 rsyslog 远端已持久化。

## Lexical Form

```text
record = field *(SP field) LF
field  = name "=" (token / quoted)
token  = 1*(ALPHA / DIGIT / "_" / "-" / "." / ":" / "/" / "+")
quoted = DQUOTE *(safe-byte / escape) DQUOTE
escape = "\\" ("\\" / DQUOTE / "n" / "r" / "t" / "x" HEXDIG HEXDIG)
```

- 字段名称使用小写 ASCII `snake_case`，版本内不得改变语义。
- 字符串字段统一使用 quoted 形式；展示非 UTF-8 字节时使用 `\xHH`。
- 数值使用十进制，`arch` 保留 Linux audit 十六进制惯例且无 `0x` 前缀。
- 可选字段缺失时不输出；无法可靠获取但字段位置重要时输出 `field=?`。
- 字段顺序固定，消费者不得依赖未声明字段。

## Audit Event

`type=AUDITD_EBPF` 字段顺序：

1. `type`
2. `msg=audit(<unix-seconds>.<millis>:<sequence>)`
3. `schema`
4. `event_id`
5. `rule_version`
6. `rule_id`
7. `key`
8. `arch`
9. `syscall`
10. `operation`
11. `success`
12. `exit`
13. `pid`
14. `ppid`
15. `uid`
16. `gid`
17. `euid`
18. `egid`
19. `comm`
20. `exe`
21. `path`
22. `perm`
23. `argc`
24. `a0` … `a31`
25. `argv_truncated`
26. `path_confidence`
27. `truncated`

示例：

```text
type=AUDITD_EBPF msg=audit(1786352400.123:42) schema=1 event_id="550e8400-e29b-41d4-a716-446655440000:42" rule_version=184467 rule_id=7 key="exec" arch=c000003e syscall=execve operation=exec success=yes exit=0 pid=1200 ppid=1180 uid=1000 gid=1000 euid=1000 egid=1000 comm="bash" exe="/usr/bin/id" path="/usr/bin/id" argc=2 a0="id" a1="-u" argv_truncated=no path_confidence=exact truncated=no
```

## Gap Event

`type=AUDITD_EBPF_GAP` 表示已知审计缺口，写 stdout。

固定字段：`type msg schema event_id reason count first_seen last_seen`。

可选字段：`cpu pid syscall raw_path candidate_rules ring_lost queue_lost path_lost`。

```text
type=AUDITD_EBPF_GAP msg=audit(1786352401.000:43) schema=1 event_id="...:43" reason=path_resolution_failed count=1 pid=1220 syscall=openat raw_path="../secret" candidate_rules="12,15" first_seen=1786352401000 last_seen=1786352401000
```

## Diagnostic Event

诊断写 stderr，使用 `type=AUDITD_EBPF_DIAG`，包含：

`level code component message rule_file rule_line errno` 中适用字段。

诊断不得使用 `type=AUDITD_EBPF`，以免被审计事件过滤器误收集。

## Compatibility

- schema v1 允许在末尾新增可选字段。
- 删除字段、重命名字段、改变转义或字段语义必须提升 schema 主版本。
- 消费者必须忽略未知字段，但必须拒绝未知 schema 主版本或将其路由到隔离目的地。
- 本格式只借用 audit 风格，不承诺被 `ausearch`/`aureport` 当作原生内核 audit 记录解析。
