# Data Model: auditd-ebpf 替代与性能验证

**Date**: 2026-08-10

## Design Rules

- 内核/用户态共享类型必须 `#[repr(C)]`、固定宽度、无指针、无动态容器，并包含 schema 与长度。
- 用户态持久对象使用稳定 ID；PID 必须与进程启动时间组合，避免 PID 复用。
- 所有容量按字节或条目显式计量；达到上限必须产生计数和状态转换。
- 字符串在内核事件中是有界字节序列，只有格式化阶段才执行 UTF-8 展示或十六进制转义。

## RuleSource

表示参与一次规则加载的文件。

| Field | Type | Required | Validation |
|---|---|---:|---|
| `path` | absolute path | yes | 位于允许目录或显式指定文件 |
| `order` | u32 | yes | 文件名排序后的连续序号 |
| `owner_uid` | u32 | yes | 必须为 0 |
| `mode` | u32 | yes | group/other 不得可写 |
| `sha256` | 32 bytes | yes | 原始文件内容摘要 |
| `loaded_at` | timestamp | yes | UTC |
| `diagnostics` | list | no | 文件、行、列、代码、消息 |

## AuditRule

规范化后的首版规则。原始语法可以来自 syscall form 或 legacy watch form。

| Field | Type | Required | Validation |
|---|---|---:|---|
| `rule_id` | u32 | yes | 在 RuleSet 内唯一，按原始顺序递增 |
| `source_order` | tuple | yes | `(file_order, line_number)` |
| `action` | enum | yes | 首版只能为 `AlwaysExit` |
| `arches` | set | yes | `B64` 或 `B32`；x86_64 首版至少包含 B64 |
| `syscalls` | ordered set | conditional | syscall 规则至少一个；watch 规则由 perm 展开 |
| `uid_filter` | comparison | no | `= != < <= > >=` 与 u32 |
| `gid_filter` | comparison | no | `= != < <= > >=` 与 u32 |
| `success_filter` | bool | no | yes/no |
| `path_filter` | absolute path | no | 与 `dir_filter` 互斥 |
| `dir_filter` | absolute path | no | 与 `path_filter` 互斥 |
| `permissions` | bit flags | no | `r/w/x/a`，不得为空 |
| `key` | bytes | yes | 1–31 bytes，不含控制字符 |
| `argv_output` | enum | yes | `Inherit/Enabled/Disabled`；仅 exec 规则有效，默认 `Inherit` |

### Validation

- 所有 syscall 必须能在所选 arch 的 syscall table 中解析。
- `path`/`dir` 必须绝对、词法规范化，禁止 `..`、NUL 和换行。
- `perm` 必须与 path/dir 或 legacy watch 同时出现。
- 不支持字段或操作符使整个候选 RuleSet 验证失败。
- 同一事件按 `rule_id` 升序 first-match，不合并多个 key。
- exec 规则的 `argv_output` 先应用规则级配置，再回退全局 `exec_argv_enabled=true`；关闭时仍输出
  exec 元数据，但不读取或输出 `a0`–`a31`。

## RuleSet

一次完整、可原子生效的规则集合。

| Field | Type | Required | Validation |
|---|---|---:|---|
| `version_hash` | 32 bytes | yes | 所有规范化规则的 SHA-256 |
| `version_id` | u64 | yes | hash 前 64 位，碰撞时拒绝加载 |
| `generation` | u8 | yes | 0 或 1，表示双缓冲槽 |
| `rules` | ordered list | yes | 0–4,096 条 |
| `source_hashes` | list | yes | 与 RuleSource 顺序一致 |
| `compiled_at` | timestamp | yes | UTC |
| `state` | enum | yes | `Candidate/Validating/Staged/Active/Rejected/Retired` |

### State Transitions

```text
Candidate → Validating → Staged → Active → Retired
                    └──→ Rejected
Active + reload failure → Active（旧版本不变）
```

## KernelFilterPlan

从 RuleSet 派生的内核粗筛选配置，不承担 first-match 精确求值。

| Field | Type | Description |
|---|---|---|
| `generation` | u8 | 与 RuleSet generation 一致 |
| `rule_version` | u64 | 写入每个 KernelEvent |
| `b64_syscall_bitmap` | bitset | 所有 B64 syscall 并集 |
| `b32_syscall_bitmap` | bitset | 所有 B32 syscall 并集 |
| `identity_prefilters` | bounded list | 可安全下推的 uid/gid 粗过滤 |
| `path_syscall_bitmap` | bitset | 需要捕获路径参数的 syscall |
| `exec_capture_enabled` | bool | 是否需要 argv |
| `process_arch_map` | map<tgid, arch> | 用户态维护的 B64/B32 提示；未知时不过滤 |

## KernelEventHeader

所有 RingBuf 记录的公共头。

| Field | Type | Description |
|---|---|---|
| `schema_version` | u16 | 首版为 1 |
| `record_type` | u16 enum | syscall/exec-attempt/exec-result/fork/exit/gap-internal |
| `record_len` | u32 | 完整记录字节数 |
| `cpu` | u32 | 产生事件的 CPU |
| `flags` | u32 bit flags | truncated/compat32/path-bearing 等 |
| `ktime_ns` | u64 | 内核单调时间 |
| `sequence` | u64 | 全局事件序号 |
| `rule_version` | u64 | 采集时活动规则版本 |
| `pid_tgid` | u64 | 高 32 位 TGID，低 32 位 PID |
| `process_start_ns` | u64 | 可用时的进程启动标识 |

## SyscallEvent

| Field | Type | Description |
|---|---|---|
| `header` | KernelEventHeader | 公共头 |
| `arch` | u32 | audit arch 常量 |
| `syscall_nr` | u32 | syscall number |
| `args` | `[u64; 6]` | 原始参数 |
| `return_value` | i64 | syscall 返回值 |
| `uid/gid/euid/egid` | u32 | 采集时身份 |
| `ppid` | u32 | 可用时父进程 |
| `comm` | `[u8; 16]` | 内核 comm |
| `path_arg` | bounded bytes | 路径型 syscall 的原始用户路径 |
| `dirfd` | i32 | AT_FDCWD 或 fd |
| `path_flags` | bit flags | missing/truncated/read-failed |

## ExecAttempt and ExecResult

完整 argv 不在 eBPF inflight map 中长期保存。sys_enter 立即发送 `ExecAttempt`，用户态建立
有界 pending exec；成功的 `sched_process_exec` 或失败的 sys_exit 发送 `ExecResult` 完成关联。

### ExecAttempt

| Field | Type | Description |
|---|---|---|
| `header` | KernelEventHeader | 公共头 |
| `attempt_id` | u64 | 每进程单调关联 ID |
| `filename` | bounded bytes | execve/execveat filename |
| `argc_observed` | u32 | 已发现参数数量 |
| `argc_captured` | u16 | 实际捕获数量，最大 32 |
| `argv_bytes` | bounded bytes | 最大 6,144 bytes |
| `argv_offsets` | `[u16; 33]` | 参数边界 |
| `argv_flags` | bit flags | count/value/total truncated、read-failed |

### ExecResult

| Field | Type | Description |
|---|---|---|
| `header` | KernelEventHeader | 公共头 |
| `attempt_id` | u64 | 对应 ExecAttempt |
| `result` | i64 | 成功为 0，失败为负 errno |
| `new_comm` | `[u8; 16]` | 成功后 comm |

pending exec 默认最多 65,536 项，超时 30 秒；缺少 attempt/result 必须产生 gap 和计数。

## ProcessIdentity and ProcessState

`ProcessIdentity` 是 `(tgid, start_time)`，全局唯一到一次启动周期。`ProcessState` 用于路径解析。

| Field | Type | Description |
|---|---|---|
| `identity` | ProcessIdentity | 主键 |
| `parent` | ProcessIdentity? | fork 关系 |
| `cwd` | absolute path? | chdir/fchdir 后更新 |
| `exe` | absolute path? | exec 成功后更新 |
| `uid/gid/euid/egid` | u32 | 最新身份快照 |
| `abi_arch` | enum | B64/B32/Unknown，从 ELF class 与继承关系确定 |
| `fd_table` | map<i32, FdEntry> | 有界、LRU，跟踪路径型 fd |
| `last_seen` | monotonic time | 淘汰依据 |
| `confidence` | enum | exact/proc-snapshot/derived/unknown |

### Process State Transitions

```text
/proc bootstrap → Running
fork(parent) → Running(child inherits cwd/fd references)
exec success → Running(exe/argv 更新)
chdir/fchdir success → Running(cwd 更新)
open/dup/close success → Running(fd_table 更新)
exit → Exited → 缓冲期后淘汰
```

## ResolvedAuditEvent

用户态精确匹配后的输出对象。

| Field | Type | Description |
|---|---|---|
| `event_id` | boot UUID + u64 | stdout 去重主键 |
| `schema` | u16 | 输出契约版本 |
| `event_time` | timestamp | ktime 与启动时钟换算 |
| `rule_version` | u64 | 采集时版本 |
| `rule_id/key` | u32/bytes | first-match 结果 |
| `arch/syscall/operation` | values | 规范化操作 |
| `success/exit` | bool/i64 | 调用结果 |
| `process` | ProcessIdentity fields | pid/ppid/uid/gid/comm/exe |
| `path` | absolute path? | 解析成功时提供 |
| `argv` | list<bytes> | exec 事件默认输出 |
| `truncation` | flags | 字段级截断 |
| `integrity` | enum | complete/truncated/uncertain |

## AuditGapEvent

表示系统知道自己无法给出完整审计判断的情况。

| Field | Type | Description |
|---|---|---|
| `event_id` | boot UUID + u64 | 唯一标识 |
| `reason` | enum | ring_full/path_resolution/output_queue_full/parse_failure |
| `count` | u64 | 合并事件数量，单次为 1 |
| `cpu` | u32? | RingBuf 丢失时提供 |
| `pid/syscall/raw_path` | optional | 路径解析失败时提供 |
| `candidate_rule_ids` | bounded list | 最多 16 个 |
| `first_seen/last_seen` | timestamp | 合并窗口 |

## AdaptiveQueue

| Field | Type | Default | Validation |
|---|---|---:|---|
| `current_limit_bytes` | usize | 64 MiB | 2 的幂，≤ max |
| `max_limit_bytes` | usize | 512 MiB | 16 MiB–4 GiB |
| `used_bytes` | usize | 0 | ≤ current limit |
| `high_watermark` | percent | 80% | 连续 3 个窗口触发增长 |
| `low_watermark` | percent | 25% | 10 分钟后允许缩小 |
| `state` | enum | Normal | Normal/Growing/AtMax/Dropping |

## HealthSnapshot

| Field | Type | Description |
|---|---|---|
| `state` | enum | Starting/Healthy/Degraded/Unhealthy/Stopping |
| `rule_version` | u64 | 当前活动版本 |
| `programs_attached` | u32 | 已挂载数量 |
| `events_seen/submitted/output` | u64 | 主流水线计数 |
| `ring_reserve_failed_per_cpu` | list<u64> | 每 CPU 丢失 |
| `queue_dropped` | u64 | 用户队列丢失 |
| `path_resolution_failed` | u64 | 路径缺口 |
| `parse_failed/output_failed` | u64 | 用户态错误 |
| `queue_used/limit/max_bytes` | usize | 背压状态 |
| `last_error` | code + timestamp | 最近错误 |
| `production_policy` | enum | `NotRequested/Passed/Failed` |

## ProductionPolicy

表示启用默认原样 argv 输出时的生产安全门禁。风险接受记录只能确认风险取舍，不能关闭强制
访问控制、保留、加密或事件响应检查。

| Field | Type | Required | Validation |
|---|---|---:|---|
| `deployment_mode` | enum | yes | `NonProduction/Production` |
| `risk_acceptance_path` | absolute path | production | root 所有，group/other 不得可写 |
| `owner` | non-empty string | production | 明确责任人或责任团队 |
| `purpose` | non-empty string | production | 记录采集和使用目的 |
| `approved_readers` | bounded list | production | root 与获准审计管理员组，至少一项 |
| `destinations` | bounded list | production | journal、本地文件、rsyslog 或远端接收端 |
| `transport_protection` | enum | remote | 经认证加密及服务端身份验证方式 |
| `retention_days` | u32 | production | 1–3,650，并与全部目的地一致 |
| `incident_response` | non-empty string | production | 暴露、越权读取和转发失败处置要求 |
| `validated_at` | timestamp | yes | 本次启动或检查时间 |
| `validation_errors` | bounded list | no | 每项包含稳定错误码和可操作消息 |

### Health State Transitions

```text
Starting → Healthy（规则、程序和消费者全部就绪）
Healthy → Degraded（任意事件丢失、路径缺口或可恢复输出错误）
Degraded → Healthy（连续 5 分钟无新增缺口；累计计数不清零）
* → Unhealthy（程序脱离、规则无效、stdout 永久失败、内部不变量破坏）
* → Stopping（收到停止信号）
```

## Benchmark Entities

### BenchmarkEnvironment

包含主机型号、CPU、内存、内核、内核配置摘要、auditd/项目版本、规则 hash、文件系统、
CPU governor、affinity、日志 sink、构建 profile 和 Git commit。

### BenchmarkScenario

| Field | Type | Description |
|---|---|---|
| `name` | enum | syscall/path/mixed |
| `ruleset_hash` | 32 bytes | 等价规则集合 |
| `operations` | ordered list | 确定性负载 |
| `expected_events` | set | 规范化期望结果 |
| `warmup_seconds` | u32 | 默认 30 |
| `measure_seconds` | u32 | 默认 120 |
| `repetitions` | u8 | 最少 5 |

### BenchmarkSample

包含方案、随机执行顺序、吞吐、p50/p95/p99、代理 CPU、系统 CPU、RSS、cycles、instructions、
context switches、事件总数、缺失、重复、误报、ring/queue 丢失和原始文件路径。

### BenchmarkReport

状态为 `Invalid/Failed/Passed`。任何正确性不等价使报告 `Invalid`；正确性通过但性能阈值未达成
为 `Failed`；全部规格阈值通过才为 `Passed` 并允许发布性能提升结论。
