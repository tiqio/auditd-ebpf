# Contract: 单行审计事件格式

## Transport

- 审计事件和审计缺口写 stdout；诊断与周期状态写 stderr。
- 每条记录恰好一行，以单个 LF 结束；记录内容内部禁止原始 CR/LF/NUL。
- 最大输出行 16 KiB。超过时按字段优先级截断，并设置 `truncated=yes` 与字段级原因。
- stdout 成功写入只表示交付到服务日志管道，不表示 rsyslog 远端已持久化。
- rsyslog 必须保存服务完成输出策略后实际写出的整行记录；完整性比较以该行逐字节内容为准。
  `argv_output=suppressed` 时缺少 `aN` 是有意的策略结果，不得由下游补写、推断或判定为损坏。
- 命中 exec 规则时，`a0`–`a31` 在事件上限内默认原样输出，不进行脱敏、猜测或删除；
  全局或规则级 argv 关闭控制启用时不得输出这些字段，但内核仍采集参数并提交 RingBuf。
- exec 事件必须输出 `argv_output=emitted|suppressed`。`suppressed` 时仍输出 `argc`、
  `argv_truncated` 和其他 exec 元数据，但禁止输出任意 `aN` 参数字段。
- stdout、journal、rsyslog、本地文件和远端消费者必须把记录视为可能包含凭据、令牌、
  密钥与个人数据的敏感审计数据，并执行生产访问控制和保留策略。

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
4. `host`
5. `machine_id`
6. `event_id`
7. `rule_version`
8. `rule_id`
9. `key`
10. `arch`
11. `syscall`
12. `operation`
13. `success`
14. `exit`
15. `pid`
16. `ppid`
17. `uid`
18. `gid`
19. `euid`
20. `egid`
21. `comm`
22. `exe`
23. `path`
24. `perm`
25. `argv_output`
26. `argc`
27. `a0` … `a31`
28. `argv_truncated`
29. `path_confidence`
30. `truncated`

- `host` 为配置的 node name；未配置时为服务启动时 hostname 快照。同一进程所有记录必须一致。
- `machine_id` 为应用专用 `/etc/machine-id` 派生摘要，使用 32 个小写十六进制字符表示 128 bits；
  不得输出原始 machine-id；来源缺失或无效时使用 `machine_id=?` 并输出可操作诊断。

示例：

```text
type=AUDITD_EBPF msg=audit(1786352400.123:42) schema=1 host="node-a" machine_id=7f6a9c1b3e4d508192a3b4c5d6e7f801 event_id="550e8400-e29b-41d4-a716-446655440000:42" rule_version=184467 rule_id=7 key="exec" arch=c000003e syscall=execve operation=exec success=yes exit=0 pid=1200 ppid=1180 uid=1000 gid=1000 euid=1000 egid=1000 comm="bash" exe="/usr/bin/id" path="/usr/bin/id" argv_output=emitted argc=2 a0="id" a1="-u" argv_truncated=no path_confidence=proc-snapshot truncated=no
```

抑制示例：

```text
type=AUDITD_EBPF msg=audit(1786352400.124:43) schema=1 host="node-a" machine_id=7f6a9c1b3e4d508192a3b4c5d6e7f801 event_id="550e8400-e29b-41d4-a716-446655440000:43" rule_version=184467 rule_id=7 key="exec" arch=c000003e syscall=execve operation=exec success=yes exit=0 pid=1201 ppid=1180 uid=1000 gid=1000 euid=1000 egid=1000 comm="bash" exe="/usr/bin/id" path="/usr/bin/id" argv_output=suppressed argc=2 argv_truncated=no path_confidence=proc-snapshot truncated=no
```

## Gap Event

`type=AUDITD_EBPF_GAP` 表示已知审计缺口，写 stdout。

固定字段：`type msg schema host machine_id event_id reason count first_seen last_seen`。

可选字段：`cpu pid syscall raw_path candidate_rules ring_lost queue_lost path_lost`。

```text
type=AUDITD_EBPF_GAP msg=audit(1786352401.000:43) schema=1 host="node-a" machine_id=7f6a9c1b3e4d508192a3b4c5d6e7f801 event_id="...:43" reason=path_resolution_failed count=1 pid=1220 syscall=openat raw_path="../secret" candidate_rules="12,15" first_seen=1786352401000 last_seen=1786352401000
```

`count` 通常为十进制非零整数。仅 `reason=unclean_shutdown` 可使用 `count=?`，表示异常终止期间
是否丢失以及丢失多少不可知；禁止把它替换为 0 或推测值。该 gap 必须在发现历史 dirty 标记后
10 秒内输出，并使健康状态进入 degraded。

## Diagnostic Event

诊断写 stderr，使用 `type=AUDITD_EBPF_DIAG`，包含：

`level code component message rule_file rule_line errno` 中适用字段。

诊断不得使用 `type=AUDITD_EBPF`，以免被审计事件过滤器误收集。
诊断、状态和 gap 记录不得包含被采集的 argv 内容。

## Compatibility

- schema v1 允许在末尾新增可选字段。
- 删除字段、重命名字段、改变转义或字段语义必须提升 schema 主版本。
- 消费者必须忽略未知字段，但必须拒绝未知 schema 主版本或将其路由到隔离目的地。
- 本格式只借用 audit 风格，不承诺被 `ausearch`/`aureport` 当作原生内核 audit 记录解析。
