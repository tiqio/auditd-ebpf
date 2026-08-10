# Contract: 持久生命周期状态

## Purpose

生命周期文件只用于区分完整优雅停止与未完成清理的终止。它不保存事件，不提供事件重放，也不能
证明异常终止期间的精确丢失数量。

默认路径：`/var/lib/auditd-ebpf/lifecycle.toml`。

## File Trust

- 文件必须由 root 所有，模式必须为 `0600`，必须是普通文件且不得是符号链接。
- 父目录必须由 root 所有且 group/other 不可写；打开时使用拒绝 symlink 的语义并在写前后复核。
- 未知 schema 主版本、权限不可信、文件过大、解析失败或原子持久化失败均使启动失败。
- 首次安装可由服务在可信父目录创建；不得跟随攻击者预置的链接或覆盖其他文件。

## TOML Schema

```toml
version = 1
state = "dirty" # clean | dirty
boot_id = "550e8400-e29b-41d4-a716-446655440000"
invocation_id = "7d444840-9dc0-11d1-b245-5ffdce74fad2"
pid = 1200
process_start_time = 1786352400123
rule_version = 184467
updated_at = "2026-08-10T08:00:00Z"

[final_counters] # 仅 clean 必须存在；dirty 必须省略
events_seen = 100000
events_submitted = 100000
events_output = 82000
ring_lost = 0
queue_lost = 0
path_lost = 0
```

- `boot_id` 来自 `/proc/sys/kernel/random/boot_id`；`invocation_id` 每次启动重新生成。
- `rule_version` 尚未确定时可省略；已激活后下一次 dirty 刷新可补充，但不得延迟首次 dirty。
- `final_counters` 只保存有界累计摘要，不得包含 event ID、路径、argv 或其他事件内容。

## Durable Write Procedure

每次状态转换必须执行同目录原子替换：

1. 在目标目录创建仅当前进程可访问的临时普通文件。
2. 写入完整 TOML，设置 owner/mode，并 `fdatasync` 或 `fsync` 文件。
3. 使用原子 rename 替换目标文件。
4. `fsync` 父目录，确认目录项持久化。
5. 任何步骤失败都不得继续到依赖该状态的 attach、事件接收或 clean 完成声明。

## State Transitions

```text
missing/clean --durable dirty--> attaching/accepting
previous dirty --durable dirty(new invocation)--> degraded + unclean_shutdown(count=?) gap
runtime dirty --stop accepting/drain/final status/cleanup--> durable clean
runtime dirty --SIGKILL/crash/power loss--> dirty remains
```

- dirty 必须在加载后 attach eBPF、启动 RingBuf 消费或接受事件之前完成。
- clean 只能在停止新事件、排空至成功或超时、输出最终计数、解除所有 link 并清理 map 后写入。
- 排空超时仍可在记录最终未输出计数且 link/map 清理完成后写 clean；退出码按 CLI 契约为 8。
- 启动发现 previous dirty 时，第一个 audit gap 必须在进程启动后 10 秒内写 stdout，使用
  `reason=unclean_shutdown count=?`，并立即记录 `unclean_shutdown_detected_total=1`。
- 成功写入新 dirty 后才能覆盖 previous dirty；若 gap 输出失败，按 stdout 永久失败策略退出，
  新 dirty 保留供下次启动继续暴露异常。
