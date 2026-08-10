# Implementation Plan: auditd-ebpf 替代与性能验证

**Branch**: `001-auditd-ebpf-replacement` | **Date**: 2026-08-10 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/001-auditd-ebpf-replacement/spec.md`

## Summary

实现一个以 Rust 和 Aya 构建的 Linux 审计代理。用户态读取并验证常用 audit 规则子集，
将规则编译为内核粗筛选表；Aya eBPF 程序通过稳定 raw tracepoint/tracepoint 捕获系统调用、
进程执行和路径参数，使用版本化共享 ABI 写入 RingBuf。用户态完成路径规范化、精确规则匹配、
`key=value` 单行格式化、stdout 输出、健康状态和动态有界队列管理。项目同时提供与传统
auditd 的正确性优先、同机重复对照基准，只有满足规格阈值时才发布性能提升结论。

## Technical Context

**Language/Version**: 用户态 Rust 1.97.1 stable；eBPF crate 使用固定的
`nightly-2026-08-06`、`rust-src` 和 `bpfel-unknown-none`

**Primary Dependencies**: Aya 0.14、aya-ebpf 0.2.1、aya-log 0.3.0、aya-log-ebpf 0.2.0、
bpf-linker 0.10.4、clap 4、tracing 0.1、tracing-subscriber 0.3、signal-hook 0.3、sha2 0.10、
libc 0.2；测试使用 proptest 1，基准使用自研 Rust workload 驱动与 Linux perf

**Storage**: 不使用数据库；读取 `/etc/audit/rules.d/*.rules` 或
`/etc/audit/audit.rules`，运行状态位于有界内存映射和队列，基准原始结果写入版本化 JSON/Markdown

**Testing**: `cargo test`、规则解析属性测试、共享 ABI 布局测试、格式契约 golden test、
特权 QEMU/真实内核加载测试、systemd/journald/rsyslog 集成测试、24 小时稳定性和同机对照基准

**Target Platform**: x86_64 Linux 5.15+；要求 BTF、BPF syscall、raw tracepoint、
tracepoint 和 RingBuf。首版不要求 BPF LSM；服务加载时探测能力并对不满足要求的主机失败关闭

**Project Type**: Cargo workspace，包含用户态服务、共享 ABI、eBPF 程序、规则库、
构建工具和基准驱动

**Performance Goals**: 三类等价负载下审计组件 CPU 中位数均比 auditd 低至少 20%；
任一负载吞吐回退不超过 2%；至少两类负载吞吐提升或 p95 延迟改善达到 10%；确定性负载
事件覆盖 100%、误报和未解释重复为 0；所有丢失与计数器一致

**Constraints**: eBPF 热路径有界、不得 panic；内核 ABI 固定宽度且显式版本化；
内核只做粗筛选和采集，用户态做精确规则解释；RingBuf 和队列均有硬上限；默认输出完整
命令行参数但必须转义和标记截断；禁止依赖 C/libbpf/BCC 或未合并的 Rust CO-RE 方案

**Scale/Scope**: 默认最多 4,096 条规范化规则、65,536 个并发 syscall 上下文、
16 MiB RingBuf、64 MiB 初始用户队列和 512 MiB 队列硬上限；默认单事件最大 8 KiB，
最多 32 个命令行参数且每项最多 192 字节，任何超限均显式计数或标记

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- [x] 使用 Rust 与 Aya；未引入替代 eBPF 框架
- [x] 内核侧只执行有界粗筛选、字段采集和 RingBuf 投递，精确规则解释位于用户态
- [x] 共享 ABI 包含 schema 版本、记录长度、固定宽度字段、规则版本和丢失计数
- [x] 计划定义能力探测、规则文件权限、参数敏感性、脱敏、截断和内存硬上限
- [x] 规划单元、属性、ABI、格式、特权内核、日志链路、稳定性和兼容矩阵测试
- [x] 规格和基准协议已量化 CPU、吞吐、延迟、内存、正确性和事件丢失目标
- [x] 公共 API、unsafe、ABI、验证器约束和内核兼容路径必须包含中文文档或安全注释
- [x] `research.md` 记录 Aya、Linux Audit、Falco、Tracee、systemd、rsyslog 与 perf 调研及许可证
- [x] Setup、基础采集、规则兼容、日志集成、基准和发布均设置独立验证与 Git commit 里程碑

**Pre-Research Gate**: PASS。无宪章例外。

## Architecture

### Event Flow

1. 用户态按文件名排序读取规则文件，完成词法、语法、字段和可信权限验证。
2. 规则库将 `-a always,exit`、`-S`、`-F arch/uid/gid/success/path/dir/perm`
   与 `-k`，以及 legacy `-w/-p/-k` 形式规范化为有序 `RuleSet`。
3. 编译器将全部规则需要的 syscall 数字并集和粗粒度身份条件写入双缓冲 BPF maps，
   再原子切换活动 generation；进程 ABI 架构和精确 first-match 语义保留在用户态。
4. `raw_syscalls:sys_enter/sys_exit` 采集 syscall 参数与结果；`sched_process_exec/fork/exit`
   维护执行事件和进程缓存。exec argv 在 sys_enter 立即发送 `ExecAttempt`，成功由
   `sched_process_exec`、失败由 sys_exit 发送 `ExecResult`，用户态按 PID 和 attempt ID 关联。
   只读取稳定 tracepoint 上下文和用户指针，不直接解引用不稳定内核结构。
5. eBPF 通过 RingBuf 发送版本化 `KernelEvent`；预留失败时增加每 CPU 丢失计数。
6. 收集线程立即复制记录到按字节计量的用户态自适应队列，写线程格式化为单行
   audit 风格 `key=value` 并写入 stdout。
7. 用户队列从 64 MiB 按高水位倍增到 512 MiB；达到硬上限后丢弃新事件、计数并进入 degraded。
8. 诊断和周期健康记录写入 stderr；systemd/journald 负责采集，rsyslog 负责持久化和转发。

### Rule and Path Semantics

- 规则文件使用 C locale 的字节顺序排序；文件内保持原始顺序。首版仅支持 `always,exit`，
  同一事件命中多条规则时采用 first-match，并输出该规则 key。
- `path=` 和 `dir=` 仅接受绝对、规范化的规则路径。内核捕获路径型 syscall 的原始路径、
  `dirfd` 和调用参数，用户态结合进程 cwd/fd 缓存生成规范化绝对路径。
- 进程缓存通过服务启动时扫描 `/proc` 初始化，并通过 fork、exec、chdir、fchdir、open、dup、
  close 和 exit 事件维护。缓存键包含 PID 与启动时间，防止 PID 复用；同时从 ELF class 和
  fork/exec 关系维护 B64/B32 ABI。未知 ABI 的 syscall 作为候选上送，用户态无法确认时输出 gap。
- 路径因进程退出、fd 竞争或缓存缺口无法可靠解析时，不得猜测。系统输出
  `type=AUDITD_EBPF_GAP reason=path_resolution_failed`，附候选规则、原始路径和丢失计数，
  并将健康状态标为 degraded。
- `perm=r/w/x/a` 编译为版本化 syscall 操作分类表；兼容矩阵明确每个 syscall 的操作类别。

## Requirement Traceability

| Requirements | Design/Contract |
|---|---|
| FR-001–FR-005 | RuleSource/RuleSet、规则 EBNF、双 generation 重载与 CLI |
| FR-006–FR-010a | KernelEvent/ResolvedAuditEvent、event-format stdout 契约 |
| FR-011–FR-013 | AdaptiveQueue、HealthSnapshot、health-and-logging、check-rules |
| FR-014–FR-016 | Benchmark entities、benchmark-protocol、quickstart comparison |
| SR-001–SR-002 | Lifecycle/capabilities、可信规则文件校验、systemd sandbox |
| SR-003–SR-005 | argv 截断/脱敏、转义、规则和内存容量硬上限 |
| SR-006–SR-007 | 健康状态机、gap 事件、基准隔离与清理 |
| SC-001–SC-004 | parser/golden/privileged/logging 端到端测试 |
| SC-005–SC-008 | benchmark protocol、内核矩阵和 24 小时稳定性测试 |

### Lifecycle and Privileges

- 启动顺序为：验证配置和文件权限 → 探测内核能力 → 加载 maps/programs → 原子安装规则 →
  挂载 hooks → 启动消费者 → 输出 ready 状态。
- 服务使用受限 root/capability 边界。运行与规则重载保留 `CAP_BPF`、`CAP_PERFMON`；
  仅兼容探测需要时允许 `CAP_SYS_ADMIN`，启动后立即删除；不长期保留 `CAP_SYS_RESOURCE`。
- `SIGHUP` 触发规则重载。新规则全部验证和填充完成后才切换 generation；失败保留旧版本。
- `SIGTERM/SIGINT` 停止新事件、排空用户队列至超时、输出最终计数、分离 links 并退出。
- 不提供网络监听端口或常驻控制 socket；`--check-rules`、`--print-capabilities` 和
  `--benchmark-info` 为只读 CLI 操作。

## Project Structure

### Documentation (this feature)

```text
specs/001-auditd-ebpf-replacement/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   ├── audit-rule-subset.ebnf
│   ├── benchmark-protocol.md
│   ├── cli.md
│   ├── event-format.md
│   └── health-and-logging.md
└── tasks.md
```

### Source Code (repository root)

```text
Cargo.toml
rust-toolchain.toml
rust-toolchain-ebpf.toml
crates/
├── auditd-ebpf/                 # 用户态服务与 CLI
│   └── src/
│       ├── collector/
│       ├── config/
│       ├── health/
│       ├── output/
│       ├── process_cache/
│       ├── reload/
│       └── main.rs
├── auditd-ebpf-common/          # no_std 内核/用户共享 ABI
│   └── src/
├── auditd-ebpf-ebpf/            # Aya eBPF 程序
│   └── src/
├── auditd-ebpf-rules/           # 规则词法、解析、规范化和精确匹配
│   └── src/
├── auditd-ebpf-bench/           # 正确性工作负载、基准运行和报告
│   └── src/
└── xtask/                        # eBPF 构建、打包、VM 和测试编排
    └── src/
packaging/
├── systemd/auditd-ebpf.service
└── rsyslog/60-auditd-ebpf.conf
tests/
├── fixtures/rules/
├── golden/events/
├── integration/
├── privileged/
└── vm/
benchmarks/
├── workloads/
├── environments/
└── reports/
```

**Structure Decision**: 六个职责单一的 workspace crate 隔离共享 ABI、内核程序、规则语义、
服务运行时、基准和构建编排。该拆分允许无特权规则测试和 ABI 测试独立运行，同时避免把
内核 `no_std` 约束泄漏到用户态。

## Phase 0: Research Deliverables

- [x] 选择 Rust/Aya 版本和可重复 eBPF 工具链
- [x] 确定 Linux 5.15+、BTF、RingBuf 和 tracepoint 能力基线
- [x] 决定首版不依赖 Rust CO-RE 或 BPF LSM，采用稳定 tracepoint 上下文
- [x] 定义规则子集、路径解析边界、first-match 与失败关闭语义
- [x] 定义 RingBuf、每 CPU 计数、自适应用户队列和健康状态策略
- [x] 定义 stdout/journald/rsyslog 日志契约
- [x] 定义 auditd 公平基准、正确性前置门禁和结果发布规则

详细结论见 [research.md](research.md)。

## Phase 1: Design Deliverables

- [x] [data-model.md](data-model.md) 定义规则、事件、进程缓存、队列、健康和基准实体
- [x] [contracts/audit-rule-subset.ebnf](contracts/audit-rule-subset.ebnf) 固定首版语法
- [x] [contracts/event-format.md](contracts/event-format.md) 固定单行输出和转义
- [x] [contracts/cli.md](contracts/cli.md) 固定服务 CLI、退出码和信号行为
- [x] [contracts/health-and-logging.md](contracts/health-and-logging.md) 固定健康状态和计数器
- [x] [contracts/benchmark-protocol.md](contracts/benchmark-protocol.md) 固定公平对照方法
- [x] [quickstart.md](quickstart.md) 定义端到端验收步骤

## Post-Design Constitution Check

- [x] 设计仅使用 Rust/Aya，并明确拒绝未合并 CO-RE 依赖
- [x] 内核程序保持最小；路径规范化、规则顺序、输出和基准均在用户态
- [x] ABI、事件格式、健康计数、规则版本和截断均有独立契约
- [x] 权限、敏感 argv、资源硬上限、失效状态和失败关闭均可测试
- [x] 设计工件覆盖所有宪章测试层级及内核兼容矩阵
- [x] 性能结论受正确性门禁、重复次数和完整报告约束
- [x] 中文注释与安全文档要求已进入代码边界和评审门禁
- [x] 开源参考只用于设计，许可证已记录，不复制第三方实现
- [x] 后续 tasks 必须按阶段设置验证和 Git commit 检查点

**Post-Design Gate**: PASS。无宪章例外，无待澄清技术项。

## Agent Context Update

当前 Spec Kit 安装中不存在 `update-agent-context` 或等价脚本，无法执行自动上下文更新。
实现阶段必须以本 `plan.md`、`research.md` 和 `contracts/` 为权威上下文；未创建或修改
`AGENTS.md`，避免伪造不存在的集成行为。

## Complexity Tracking

无宪章违规需要豁免。多 crate、进程缓存和自适应队列均直接对应 `no_std` ABI 隔离、
路径规则兼容和有界背压要求，不属于可删除的组织层。
