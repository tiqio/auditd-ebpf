# Implementation Plan: Watch 规则端到端运行

**Branch**: `[002-watch-rule-runtime]` | **Date**: 2026-08-11 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/002-watch-rule-runtime/spec.md`

## Summary

把 legacy `-w PATH -p rwxa -k KEY` 规范化为与 Linux audit 权限分类一致的、非空且可检查的
syscall 覆盖计划；内核态继续只做 syscall 预选、动态 open 访问模式判定、路径参数有界复制和
RingBuf 投递，用户态完成命名空间词法路径解析、文件描述符关联、规则顺序匹配、gap 生成、健康
计数和日志格式化。首个验收目标是 `-w /tmp/ddtest -p rw -k ddtest` 对确定性读取和写入均产生
正确事件，同时无关路径不误报。

## Technical Context

**Language/Version**: 用户态与共享代码 Rust 1.97.1；eBPF 使用 nightly-2026-08-06、
`bpfel-unknown-none` 与 `rust-src`

**Primary Dependencies**: Aya 0.14.0、aya-ebpf 0.2.1、aya-log 0.3.0、aya-log-ebpf 0.2.0；
沿用现有 `tokio`、`clap`、`serde`、`sha2`，不新增生产依赖

**Storage**: 规则文件与 durable lifecycle 文件；运行时进程/线程/文件描述符关联仅驻留内存，
不持久化路径缓存

**Testing**: `cargo test` 单元/契约/集成测试、共享 ABI 布局测试、规则 corpus、真实 Linux 5.15+
特权内核测试、故障注入、前后性能对照

**Target Platform**: Linux x86_64，最低内核 5.15；支持 b64 与 x86_64 宿主上的 b32 compat ABI；
沿用 CAP_BPF、CAP_PERFMON、初始化期 CAP_SYS_ADMIN 回退和初始化后降权策略

**Project Type**: Cargo workspace 中的特权 Linux CLI/daemon、规则编译库、共享 ABI 与 eBPF 对象

**Performance Goals**: `-w ... -p rw` 正确性负载覆盖率 100%；事件在 10 秒内可检索；相对关闭
watch 的同版本基线，服务 CPU 中位数增幅不超过 10%，业务吞吐下降不超过 2%；RingBuf 和用户
队列均不得静默丢失

**Constraints**: 内核热路径必须有界、无动态分配、无路径规范化、无 inode 等价声明；syscall
编号必须小于 512；共享 ABI 保持固定布局和 `no_std`；路径参数固定上限，截断必须形成 gap；
RingBuf map 加载后不能原地扩容，继续依靠固定容量、per-CPU 计数和自适应用户队列受控降级

**Scale/Scope**: 单宿主最多 65,536 个并发 inflight syscall，双 generation 原子规则切换；首版
只覆盖版本化矩阵中明确列出的 `rwxa` 文件操作，不支持 io_uring 文件操作、inode/hard-link
等价、通配符 watch 或其他 CPU 架构

## Constitution Check

*GATE: Phase 0 前检查通过；Phase 1 设计后再次检查通过。*

- [x] 使用 Rust 与 Aya；不引入 C、libbpf、BCC 或新的生产运行时
- [x] 内核侧仅承担 bitmap 预选、open 权限位判定、有界复制和投递，路径/FD/规则策略位于用户态
- [x] 复用固定布局 ABI，并为保留 flags 定义向后兼容的权限有效位、权限掩码和未知行为
- [x] 本功能不扩大 argv 采集；与 exec 重叠时继续遵守原样 argv、关闭控制、访问权限、加密、保留和风险接受
- [x] 已规划权限纯函数、规则编译、ABI、FD 生命周期、日志 golden、特权内核和 b32/b64 测试
- [x] 已量化正确性、10 秒可见性、CPU、业务吞吐和零静默丢失目标
- [x] 权限矩阵、open flags、openat2 用户指针读取、FD 复用和 namespace gap 必须写中文安全注释
- [x] 已调研 Linux audit、audit-userspace、Aya 与 Falco 官方源码并在 `research.md` 记录许可证和差异
- [x] 每个逻辑里程碑均定义验证命令和独立 Git commit 检查点

## Architecture

### Event Flow

```text
rules.d
  -> parser: WatchRule(path, requested_permissions, key)
  -> permission coverage compiler
       -> overall syscall bitmap b64/b32
       -> per-syscall requested permission mask b64/b32
       -> rule coverage summary + version hash
  -> inactive generation staging
       -> syscall bitmap maps
       -> permission mask maps
       -> rule version
  -> raw sys_enter
       -> overall bitmap prefilter
       -> static mask or bounded open/openat/openat2 access-mode classification
       -> explicit syscall rule OR requested permission intersection
       -> bounded path argument capture + inflight correlation
  -> raw sys_exit
       -> SyscallEvent(header.flags = permission-valid + rwxa mask)
       -> RingBuf + per-CPU counters
  -> collector/runtime
       -> process-scoped FD table and thread path context
       -> primary/secondary/fd path resolution
       -> CandidateEvent(path, permissions, identity, success)
       -> ordered RuleEngine evaluation
       -> WatchAuditEvent or WatchGap
       -> adaptive queue -> stdout -> journal -> rsyslog
```

### Permission Coverage

1. `auditd-ebpf-common` 定义固定宽度 `PermissionMask(u8)`、事件 flag 位和 ABI 无关权限值，供
   eBPF 与用户态共同使用。
2. `auditd-ebpf-rules` 定义版本化 b64/b32 syscall 权限表：
   - `r`：只读/读写 open 类及 Linux audit read class；
   - `w`：只写/读写 open 类、目录内容变化及 Linux audit write class；
   - `x`：execve/execveat；
   - `a`：chmod/chown/xattr/link 等属性变化类。
3. 编译器把 watch 规则与带 `perm=` 的 syscall 规则统一展开为：
   - 总 syscall bitmap：显式 `-S` 与权限覆盖的并集；
   - 每 syscall 请求权限掩码：用于内核快速跳过与当前规则无交集的动态 open；
   - 每规则覆盖摘要：供 `check-rules --print-normalized` 和测试验证。
4. 任一请求权限在目标 ABI 上覆盖为空时，候选规则集整体失败；禁止保留空 `syscalls=` 的成功
   watch 计划。
5. 内核输出的是“当前已加载规则请求且本次操作实际满足的权限集合”；用户态仍按每条规则的
   权限集合求交，不把全局请求集合直接当作规则命中。

### Dynamic Open Classification

- `open`/`openat` 从 syscall 参数中的 `O_ACCMODE` 计算 `r`、`w` 或 `rw`。
- `creat` 固定为 `w`。
- `openat2` 在 sys_enter 使用一次固定 8 字节用户指针读取获取 `open_how.flags`；读取失败时仍可
  为显式 syscall 规则投递，但权限规则必须生成 `permission_classification_failed` gap。
- 动态分类只做整数掩码运算，不在内核解释路径、读取文件对象或遍历规则。

### Path and File Descriptor Association

- 将当前“每线程各自复制 fd_table”重构为：
  - `ThreadPathContext`：tid、process identity、root、cwd、mount namespace、ABI；
  - `ProcessFileTable`：以稳定 `ProcessIdentity(tgid,start_time)` 为键，保存该进程所有线程共享的
    fd -> `FileAssociation`；
  - `FileAssociation`：namespace 词法路径、来源、可信状态和最后更新序列。
- 同 tgid 线程共享一个表；fork 到新 tgid 时复制快照；exec 后优先从 `/proc/<tgid>/fd` 重新
  建立权威快照，失败则把旧表标记 stale 而不是假定为空。
- 成功 open/creat 替换同号 fd；close 仅在成功时删除；dup/dup2/dup3 与受支持 fcntl duplicate
  原子复制关联；fd 复用始终覆盖旧关联。
- 路径操作解析 primary 和 secondary 两个路径；fd-only 操作通过参数指定 fd 查表；截断、缺失
  context、stale fd、mount epoch 过期均返回结构化 gap。
- 首版不追踪 inode 身份；删除后重建同路径继续按词法路径匹配，事件明确保留
  `path_confidence=namespace-lexical`。

### Event and Health Contract

- 保持 `SyscallEvent` 固定布局与 schema 1；使用此前保留为零的 `KernelEventHeader.flags`：
  - bit 0..3：`x/w/r/a`，数值分别为 1/2/4/8，与 Linux audit permission bit 保持一致；
  - bit 8：permission mask 有效；
  - 其他位必须为零并为未来版本保留。
- 旧对象产生 `flags=0` 时，普通无 `perm` syscall 规则仍可处理；任何要求权限的候选规则必须
  生成 gap，防止新用户态与旧 eBPF 对象组合时静默漏报。
- stdout 事件的 `perm` 使用稳定顺序 `rwxa` 输出实际匹配集合；未知时省略并伴随 gap，不输出
  空字符串伪装已分类。
- 新增单调计数：watch candidates、watch matches、read/write/execute/attribute matches、
  permission classification failures、fd association failures；现有 ring/queue/path/output 计数不变。

### Rule Reload

- generation 0/1 同时 stage 总 syscall bitmap、permission mask、rule version 和用户态 RuleEngine。
- 所有 map 写入完成后才切换 `ACTIVE_GENERATION`；失败时清理 inactive generation 并保留旧版。
- 规则版本摘要纳入规范化 watch 权限和覆盖矩阵版本，确保权限表变化会产生新 rule version。

## Project Structure

### Documentation (this feature)

```text
specs/002-watch-rule-runtime/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   ├── check-rules-output.md
│   ├── kernel-event-permission-flags.md
│   ├── watch-event-format.md
│   └── watch-permission-coverage.md
└── tasks.md
```

### Source Code (repository root)

```text
crates/auditd-ebpf-common/
├── src/event.rs                 # permission flags 与固定 ABI
├── src/permission.rs            # no_std PermissionMask
└── tests/abi_layout.rs

crates/auditd-ebpf-rules/
├── src/permissions.rs           # b64/b32 权限覆盖矩阵与展开
├── src/compiler.rs              # bitmap、permission map、coverage summary
├── src/model.rs                 # KernelFilterPlan 扩展
├── src/normalize.rs             # 稳定规范化与 coverage 输出
└── tests/                       # parser/compiler/syscall matrix

crates/auditd-ebpf-ebpf/
├── src/maps.rs                  # 双 generation permission mask maps
└── src/programs/syscall.rs      # 有界权限分类与路径参数捕获

crates/auditd-ebpf/
├── src/loader.rs                # permission maps 原子 staging
├── src/process_cache/           # process-scoped FD table 与 stale/gap
├── src/rules/engine.rs          # PermissionMask 求交
├── src/runtime.rs               # 双路径/fd 解析、事件与计数
├── src/output/event_formatter.rs
├── src/health/counters.rs
├── src/commands/check_rules.rs
└── tests/                       # rule engine、FD、golden、reload

tests/
├── fixtures/rules/              # watch coverage corpus
├── integration/                 # CLI 与日志契约
└── privileged/watch_rules.sh    # 真内核 rwxa、失败、fd、reload
```

**Structure Decision**: 沿用现有六 crate workspace；权限位放共享 `no_std` crate，权限覆盖表和规则
展开留在规则 crate，内核只消费编译结果，进程/FD/路径与策略全部留在用户态。无需新增 crate 或
生产依赖。

## Implementation Phases and Milestones

### Milestone 1 - Permission Contract and Compiler

- 先添加失败测试：watch 编译结果不得为空、`rwxa` 与 b64/b32 覆盖稳定、版本摘要随覆盖版本变化。
- 实现共享 `PermissionMask`、权限矩阵、`KernelFilterPlan` permission maps 和 coverage summary。
- 更新 `check-rules` 输出契约与兼容 corpus。
- 验证：`cargo test -p auditd-ebpf-common -p auditd-ebpf-rules`、fmt、Clippy。
- Commit：`feat: compile watch permissions into syscall coverage`

### Milestone 2 - Kernel Permission Delivery

- 先添加 ABI flags、open flags 和 map staging 测试。
- 增加双 generation permission maps；在 sys_enter 完成静态/动态权限交集与 openat2 有界读取。
- 扩展需要 primary/secondary 路径的 syscall 表；保持 verifier 有界并记录 reserve/read failure。
- 验证：共享 ABI 测试、eBPF 构建、`cargo xtask test-kernel --kernel host`。
- Commit：`feat: deliver watch permission candidates from ebpf`

### Milestone 3 - Process FD and Path Semantics

- 先添加同进程多线程共享、fork 快照、exec refresh、dup/close/fd reuse、stale gap 测试。
- 重构 ProcessCache 为线程路径上下文 + process-scoped FD table；解析 primary/secondary/fd path。
- 为 namespace 变化和 `/proc` refresh 失败定义中文原因码。
- 验证：`cargo test -p auditd-ebpf --test process_cache --test path_resolution`、Clippy。
- Commit：`feat: correlate watch events with process file tables`

### Milestone 4 - Rule Match, Output, Health and Reload

- 将 permission flags 转为 CandidateEvent，修复 watch 与 syscall `perm=` 求交。
- 输出稳定 `perm=rwxa`、watch/gap 原因与新增计数；完整 staging permission maps 并原子 reload。
- 添加 golden、无旧对象权限静默兼容、队列丢失和 reload 回归。
- 验证：`cargo test -p auditd-ebpf -p auditd-ebpf-rules`、fmt、Clippy。
- Commit：`feat: evaluate and report watch rule matches`

### Milestone 5 - End-to-End and Performance Evidence

- 添加 `tests/privileged/watch_rules.sh`，覆盖 cat、tee、O_RDWR、chmod、exec、失败、无关路径、
  secondary path、fd 复制/复用、b32（环境可用时）和 SIGHUP。
- 更新 quickstart、内核套件和 watch 开关前后性能负载；保留至少 5 个有效样本。
- 验证：workspace fmt/Clippy/test、eBPF build、host kernel suite、quickstart。
- Commit：`test: validate watch rules end to end`

## Post-Design Constitution Check

- [x] 未新增依赖、crate 或高权限 hook；所有内核循环、读取和 map 索引均有固定上限
- [x] 权限表来源、差异和许可证已记录；未复制 GPL/Apache 项目代码
- [x] ABI 扩展使用保留 flags 且定义旧对象未知行为，避免布局漂移
- [x] RingBuf 固定容量和自适应用户队列边界明确，所有丢失与分类失败均有计数
- [x] 生产 argv、日志访问控制、rsyslog 和风险接受契约不被改变
- [x] 真实内核、b64/b32、reload、namespace、FD 生命周期和性能证据均有门禁

## Complexity Tracking

无宪章违规。新增 process-scoped FD table 是满足跨线程 fd 正确性的必要状态，不引入新服务、
持久化层或第三方依赖；若无法可靠维护，设计要求输出 gap 而不是继续增加推测性缓存。
