# Data Model: Watch 规则端到端运行

## Overview

本功能不增加持久化数据库。规则覆盖、进程路径上下文和文件描述符关联均为运行时内存状态；
durable lifecycle 文件继续只记录服务 clean/dirty、规则版本和累计状态摘要。所有跨 eBPF 边界的
值使用固定宽度布局。

## PermissionMask

表示一次文件操作满足的权限集合，底层为 `u8`。

| Bit | Value | Symbol | Meaning |
|-----|-------|--------|---------|
| 0 | 1 | `x` | 执行目标对象 |
| 1 | 2 | `w` | 写入、内容变化或目录内容变化 |
| 2 | 4 | `r` | 读取或读取目标属性 |
| 3 | 8 | `a` | 元数据、所有者、模式或扩展属性变化 |

### Validation

- 只允许低四位；其他位必须拒绝或按未知 flags 处理。
- 空 mask 不能满足带 `perm` 的规则。
- 文本输出固定按 `r`、`w`、`x`、`a` 顺序，避免数值位顺序影响日志稳定性。
- 一个事件允许同时包含多个权限，例如 O_RDWR 对应 `rw`，link/linkat 可对应 `wa`。

## WatchRule

解析后的管理员规则声明。

| Field | Type | Rules |
|-------|------|-------|
| `rule_id` | `u32` | 按规则文件和行顺序分配，候选规则集内唯一 |
| `source` | Rule source location | 文件、行号和原始摘要，用于拒绝诊断 |
| `path` | Absolute lexical path | 非空、绝对、无通配符和父目录跳转 |
| `requested_permissions` | PermissionMask | 至少一位，来自 `-p rwxa` |
| `key` | String | 1–31 字节且规则内唯一声明一次 |
| `order` | `u32` | 保持跨文件的确定顺序 |
| `argv_output` | Existing policy | watch 默认继承；与 exec 重叠时沿用现有策略 |

### Relationship

一个 WatchRule 对应两个 ABI 的零或一个 `RulePermissionCoverage`。任何请求权限在声明支持 ABI
上的覆盖为空时，整个候选 RuleSet 无效。

## RulePermissionCoverage

规则编译后供 staging、检查输出和版本摘要使用的覆盖。

| Field | Type | Description |
|-------|------|-------------|
| `coverage_version` | `u16` | 权限矩阵版本，初始为 1 |
| `arch` | `b64` / `b32` | syscall 编号解释方式 |
| `requested_permissions` | PermissionMask | 规则请求集合 |
| `effective_syscalls` | Ordered set | 至少一个 syscall；按编号排序后稳定输出 |
| `syscall_permission_masks` | Map syscall -> PermissionMask | 该 syscall 可为此规则满足的权限 |
| `dynamic_open_syscalls` | Ordered set | 需要根据 open flags 决定实际 mask 的调用 |
| `fd_path_syscalls` | Ordered set | 需要通过 fd table 得到目标路径的调用 |
| `primary_path_syscalls` | Ordered set | 目标路径来自首个捕获路径参数 |
| `secondary_path_syscalls` | Ordered set | 可能同时影响第二路径的调用 |

### Validation

- `effective_syscalls` 不得为空。
- 每个请求权限至少映射到一个 syscall。
- 每个 syscall 的 mask 必须是请求 mask 的非空子集。
- coverage version、arch、syscall 编号和权限 mask 全部进入规则版本摘要。

## KernelFilterPlan

双 generation staging 的完整候选计划。

| Field | Type | Description |
|-------|------|-------------|
| `generation` | `u8` | 仅允许 0 或 1 |
| `rules` | Ordered rules | syscall 与 watch 规则原顺序 |
| `syscalls_b64/b32` | 512-bit set | 显式 syscall 与权限展开后的并集 |
| `permission_masks_b64/b32` | 512-byte table | 每 syscall 当前全部规则请求权限的并集 |
| `coverage_by_rule` | Rule ID -> coverage | 规则检查与用户态匹配依据 |
| `version_hash` | 32 bytes | 规范化规则和 coverage version 的 SHA-256 |

### Invariants

- `permission_masks[syscall] != 0` 时，对应 syscall 必须也在总 bitmap 中。
- active generation 切换前，总 bitmap、permission table 和 version 必须全部 stage 成功。
- inactive generation 失败不得改变 active generation 或用户态 RuleEngine。

## FileAssociation

文件描述符到命名空间词法路径的关联。

| Field | Type | Description |
|-------|------|-------------|
| `fd` | `i32` | 非负文件描述符 |
| `path` | Absolute lexical path | 进程 root/mount namespace 中的规范化路径 |
| `confidence` | AssociationConfidence | Reliable / Stale / Unknown |
| `source` | AssociationSource | ProcBootstrap / OpenResult / Duplication / Refresh |
| `mount_epoch` | `u64` | 创建关联时的 mount 边界版本 |
| `last_sequence` | `u64` | 最后成功更新的内核事件序列 |

### State Transitions

```text
Unknown
  -> Reliable      /proc bootstrap、成功 open 或可靠 dup

Reliable
  -> Reliable      成功 dup 到新 fd；成功 open 复用 fd 覆盖旧关联
  -> removed       成功 close
  -> Stale         mount boundary 改变、exec refresh 失败、事件序列缺口

Stale
  -> Reliable      /proc refresh 成功
  -> removed       进程退出或确认 fd 不存在
```

Stale/Unknown 不允许产生 watch 成功命中，只能触发 refresh 或 WatchGap。

## ProcessFileTable

一个稳定进程身份共享的 FD 表。

| Field | Type | Description |
|-------|------|-------------|
| `process` | `(tgid,start_time)` | 防止 PID 复用 |
| `fds` | Map fd -> FileAssociation | 同一 tgid 所有线程共享 |
| `state` | Reliable / Stale | 整体可信状态 |
| `last_refresh` | Monotonic timestamp | `/proc` 刷新时间 |

### Relationships

- 多个 ThreadPathContext 引用同一个 ProcessFileTable。
- fork 到新 tgid 时创建独立快照；同 tgid 新线程只增加 ThreadPathContext。
- exec 成功后使用 `/proc/<tgid>/fd` 替换表；失败时保留内容但整体标记 Stale。
- process exit 删除表；单线程 exit 只删除对应 ThreadPathContext。

## ThreadPathContext

线程级路径解析边界。

| Field | Type | Description |
|-------|------|-------------|
| `tid` | `u32` | 线程 ID |
| `process` | ProcessIdentity | 关联 ProcessFileTable |
| `root` | Path or Unknown | 事件进程 root |
| `cwd` | Path or Unknown | 当前工作目录 |
| `mount_namespace` | `(dev,inode)` or Unknown | mount namespace 标识 |
| `mount_epoch` | `u64` | 路径边界版本 |
| `abi` | B64/B32/Unknown | syscall 编号解释方式 |

## FileOperationCandidate

从 SyscallEvent 解码并丰富后的规则候选。

| Field | Type | Description |
|-------|------|-------------|
| `event_id` | Stable identifier | CPU + sequence，沿用现有契约 |
| `rule_version` | `u64` | 选择对应 generation RuleEngine |
| `arch/syscall` | ABI + name/number | 操作身份 |
| `permissions` | PermissionMask or Unknown | 来自有效 header flags |
| `primary_path` | Resolved path or error | 主路径 |
| `secondary_path` | Resolved path or error | 次路径 |
| `fd_path` | Resolved path or error | fd-only 操作路径 |
| `success/exit` | bool + i64 | syscall 结果 |
| `identity` | uid/gid/euid/egid/pid | 规则过滤与输出 |

候选路径按 primary、secondary、fd 的文档化顺序求值。第一个命中规则和路径决定输出 key/path；
未命中的其他路径不产生重复记录。

## WatchAuditEvent

成功规则求值后的 stdout 事件。

新增或明确字段：

| Field | Rule |
|-------|------|
| `operation` | 稳定 syscall 名称 |
| `path` | 实际命中的 namespace lexical path |
| `perm` | 非空、固定顺序 `rwxa` 子集 |
| `path_confidence` | `namespace-lexical` |
| `key/rule_id/rule_version` | 对应首个确定性匹配规则 |

## WatchGap

无法可靠做出 watch 决策时的结构化缺口。

| Reason | Trigger |
|--------|---------|
| `permission_flags_missing` | 旧对象或 flags 未声明有效 |
| `permission_classification_failed` | openat2 flags 读取失败或未知动态模式 |
| `path_argument_missing` | 矩阵要求路径但事件未携带 |
| `path_argument_truncated` | 固定路径缓冲达到上限 |
| `thread_context_missing` | 无 ThreadPathContext 且 refresh 失败 |
| `mount_context_stale` | mount epoch 或 namespace 过期 |
| `fd_association_missing` | fd 不在可靠 ProcessFileTable 中 |
| `fd_association_stale` | fd 表整体或条目过期 |

每个 gap 必须增加对应原因计数和总 gap 计数，并关联 event_id、rule_version、pid/tid、syscall；
诊断不得包含 exec argv。
