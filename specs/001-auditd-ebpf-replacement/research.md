# Phase 0 Research: auditd-ebpf 替代与性能验证

**Date**: 2026-08-10

## 1. Rust 与 Aya 工具链

**Decision**: 用户态固定 Rust 1.97.1 stable；eBPF crate 固定
`nightly-2026-08-06`、`rust-src`、`bpfel-unknown-none`。依赖基线为 Aya 0.14、
aya-ebpf 0.2.1、aya-log 0.3.0、aya-log-ebpf 0.2.0 和 bpf-linker 0.10.4，
所有精确版本进入 `Cargo.lock`。

**Rationale**: Aya 0.14 是当前稳定用户态 API，aya-ebpf 0.2.1 提供 Rust eBPF API；固定 stable
与 nightly 可以复现构建，并避免 nightly 编译行为漂移。x86_64 Linux 使用小端 BPF 目标。

**Alternatives considered**:

- 跟随未固定的 stable/nightly：拒绝，无法复现验证器和代码生成结果。
- C/libbpf/BCC：拒绝，违反项目宪章和统一 Rust 工具链要求。
- RedBPF：拒绝，项目维护状态和 Aya 生态目标不匹配。

**Sources**:

- Rust stable channel manifest: https://static.rust-lang.org/dist/channel-rust-stable.toml
- Aya 0.14 documentation: https://docs.rs/aya/0.14.0/aya/
- aya-ebpf 0.2 documentation: https://docs.rs/aya-ebpf/0.2.1/aya_ebpf/
- aya-log 0.3 documentation: https://docs.rs/aya-log/0.3.0/aya_log/
- aya-log-ebpf 0.2 documentation: https://docs.rs/aya-log-ebpf/0.2.0/aya_log_ebpf/
- bpf-linker 0.10.4: https://docs.rs/bpf-linker/0.10.4/bpf_linker/
- Aya Book: https://aya-rs.dev/book/

## 2. 最低内核与可移植性边界

**Decision**: 首版最低 Linux 5.15、x86_64，要求 BTF、raw tracepoint、tracepoint、
BPF syscall 和 `BPF_MAP_TYPE_RINGBUF`。加载器在运行前执行实际能力探测，不能只依赖版本号。

**Rationale**: RingBuf 自 Linux 5.8 提供；5.15 是广泛部署的 LTS 基线，并包含所需的有界循环、
BTF 和 RingBuf 能力。内核发行版可能关闭配置，因此必须加载探针程序并检查 `/sys/kernel/btf/vmlinux`。

**Alternatives considered**:

- Linux 5.8：拒绝，虽有 RingBuf，但发行版支持和后续 tracing 能力基线过窄。
- Linux 6.1+：暂不采用，会不必要地排除大量 5.15 LTS 主机。
- 仅检查 `uname`：拒绝，发行版配置和 backport 会使版本号不足以证明能力。

**Sources**:

- Linux BPF Ring Buffer: https://docs.kernel.org/bpf/ringbuf.html
- Linux BPF LSM: https://docs.kernel.org/bpf/prog_lsm.html
- Linux tracepoints: https://docs.kernel.org/trace/tracepoints.html

## 3. 采集点与 Rust CO-RE 取舍

**Decision**: 首版使用 `raw_syscalls:sys_enter/sys_exit` 与
`sched_process_exec/fork/exit`。不使用需要读取不稳定内核结构字段的 kprobe/LSM 实现，也不把
未合并的 Rust CO-RE 工作作为生产依赖。

**Rationale**: Aya 的 Rust eBPF 工作流当前不提供与 libbpf C 相同的完整 CO-RE 体验。
稳定 tracepoint 上下文避免 `task_struct`、`file`、`dentry` 等字段偏移随内核变化。该方案以
更多用户态规范化换取可测试的 5.15+ 兼容性和更低验证器风险。

**Alternatives considered**:

- BPF LSM + `bpf_d_path`：路径语义更接近内核对象，但读取 `struct file/path` 会引入
  内核布局兼容风险；延后到 Aya Rust CO-RE 成熟后的版本。
- kprobe 内核函数：函数签名和符号稳定性低于 tracepoint，拒绝作为首版默认。
- 为每个内核构建单独 eBPF 对象：运维和发布矩阵成本过高，首版拒绝。

**Sources**:

- Aya Rust CO-RE tracking: https://github.com/aya-rs/aya/issues/1041
- Aya LSM program API: https://docs.rs/aya/0.14.0/aya/programs/lsm/index.html
- Linux raw syscall tracepoints: https://www.kernel.org/doc/html/latest/trace/events.html

## 4. 规则子集与求值位置

**Decision**: 支持注释、空行、`-a always,exit`、`-S`、
`-F arch/uid/gid/success/path/dir/perm`、`-k` 和 legacy `-w/-p/-k`。规则按文件名、
文件内顺序组成单一列表，采用 first-match。内核只按 syscall 数字、可用进程 ABI 提示和
粗身份并集筛选，用户态执行精确 arch、字段、路径、perm 和顺序匹配。

**Rationale**: Linux Audit 的规则顺序会影响结果，提前在内核中展开完整规则会增加 map、分支和
验证器复杂度。粗筛选可减少事件量，用户态精确匹配可保留清晰错误和可测试语义。

**Alternatives considered**:

- 在 eBPF 中执行完整规则 VM：拒绝，违反内核最小化原则且难以热更新。
- 接受全部 auditctl 语法后忽略不支持部分：拒绝，违反失败关闭和禁止静默降级。
- 所有 syscall 全量上送：拒绝，规则稀疏时产生不必要开销。

**Sources**:

- auditctl manual: https://man7.org/linux/man-pages/man8/auditctl.8.html
- audit.rules manual: https://man7.org/linux/man-pages/man7/audit.rules.7.html
- audit-userspace source: https://github.com/linux-audit/audit-userspace

## 5. 路径规则

**Decision**: path/dir 规则路径必须是绝对路径。eBPF 捕获路径型 syscall 的用户路径、dirfd、
PID/TGID 和结果；用户态以 PID+启动时间进程缓存解析 cwd 和 fd，执行词法规范化和目录前缀匹配。
解析失败输出 `AUDITD_EBPF_GAP`，列出候选规则并进入 degraded，不猜测或静默丢失。

**Rationale**: 在不读取不稳定内核结构的前提下，这是 Aya-only 首版可复现的路径方案。
显式 gap 记录使路径竞态成为可量化限制，而不是虚假的成功审计。

**Alternatives considered**:

- 只匹配原始字符串：拒绝，无法正确处理相对路径和 `openat` dirfd。
- 从 `/proc` 临时读取但失败时忽略：拒绝，产生不可见审计缺口。
- 强制只允许业务使用绝对路径：不可由审计代理控制，拒绝。

## 6. 事件 ABI、RingBuf 与背压

**Decision**: `auditd-ebpf-common` 定义 `#[repr(C)]`、固定宽度、schema v1 的 `KernelEvent`。
默认 RingBuf 16 MiB；每 CPU Array 记录 seen/submitted/reserve_failed。用户态按字节计量的
`AdaptiveQueue` 从 64 MiB 扩到 512 MiB，达到上限后丢弃新事件并进入 degraded。

**Rationale**: RingBuf 保留跨 CPU 的全局事件顺序并支持可变记录；每 CPU 计数避免热点原子竞争。
用户态队列吸收 journald/rsyslog 短时抖动，但硬上限保护主机内存。

**Alternatives considered**:

- PerfEventArray：每 CPU 缓冲和顺序重组更复杂，首版选择 RingBuf。
- 阻塞业务 syscall：拒绝，审计代理不能造成主机级拒绝服务。
- 无限队列：拒绝，可能耗尽内存。
- 自动采样：拒绝，安全事件采样会改变规则语义。

**Sources**:

- Linux BPF Ring Buffer: https://docs.kernel.org/bpf/ringbuf.html
- Aya RingBuf API: https://docs.rs/aya/0.14.0/aya/maps/ring_buf/struct.RingBuf.html
- BPF per-CPU array maps: https://docs.kernel.org/bpf/map_array.html

## 7. 输出、systemd 与 rsyslog

**Decision**: 审计事件只写 stdout，格式为单行 audit 风格 `key=value`；诊断和状态写 stderr，
同样保持单行。systemd unit 使用 `StandardOutput=journal`、`StandardError=journal` 和稳定
`SyslogIdentifier=auditd-ebpf`。rsyslog 从 journal 读取并按 identifier/type 分流。

**Rationale**: journald 会把换行划分为独立记录，因此单行契约可避免事件被拆分。rsyslog
`imjournal` 具有状态文件和限速行为，必须配置持久游标、显式 rate limit 和磁盘队列；本服务
只能证明 stdout 写入，不能声称远端最终持久化成功。

**Alternatives considered**:

- 服务自行写 `/var/log/audit`：拒绝，会重复实现轮转和转发。
- JSON Lines：用户已明确选择传统 audit 风格。
- syslog socket 直写：拒绝，stdout 是明确产品接口，且 journald 已管理服务上下文。

**Sources**:

- systemd standard output: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html
- rsyslog imjournal: https://www.rsyslog.com/doc/configuration/modules/imjournal.html
- rsyslog imuxsock: https://www.rsyslog.com/doc/configuration/modules/imuxsock.html

## 8. 权限与重载

**Decision**: 启动和 SIGHUP 重载保留 `CAP_BPF`、`CAP_PERFMON`；仅内核兼容探测回退允许
`CAP_SYS_ADMIN`，完成后删除。规则文件必须 root 所有且 group/other 不可写。规则更新采用
inactive generation 填充后原子切换，失败保留旧 generation。

**Rationale**: 运行时重载需要更新 maps，不能在启动后删除所有 BPF 权限。generation 切换可保证
不会让半套规则生效。文件权限检查防止低权限用户改变高权限审计策略。

**Alternatives considered**:

- 始终使用完整 root/CAP_SYS_ADMIN：拒绝，不符合最小权限。
- 每次重载重启服务：可作为运维回退，但不是默认体验。
- 原地逐条更新活动 maps：拒绝，会暴露部分规则窗口。

**Sources**:

- Linux capabilities: https://man7.org/linux/man-pages/man7/capabilities.7.html

## 9. 开源架构参考与许可证

**Decision**: 参考 Falco modern eBPF 的 syscall 事件流水线和 Tracee 的事件处理分层，但仅采用
架构思想，不复制代码。Aya 使用 Apache-2.0/MIT；Falco、Tracee 和 Linux audit-userspace
均按其上游许可证记录来源。

**Rationale**: Falco 与 Tracee 已验证 eBPF 安全事件采集的队列、事件 schema 和用户态处理模式，
但本项目的 audit 规则兼容、单行输出与 Aya-only 约束不同，直接复制会引入不必要依赖和许可风险。

**Alternatives considered**:

- 直接移植 Falco probe：拒绝，主要为 C/C++/libbpf，并违反 Aya-only 原则。
- 直接嵌入 Tracee：拒绝，产品语义、语言和输出契约不同。

**Sources**:

- Falco modern eBPF: https://falco.org/docs/concepts/event-sources/kernel/#modern-ebpf-probe
- Falco libs: https://github.com/falcosecurity/libs
- Tracee architecture: https://aquasecurity.github.io/tracee/v0.12/contributing/architecture/
- Aya license: https://github.com/aya-rs/aya

## 10. 正确性与性能基准

**Decision**: 自研 `auditd-ebpf-bench` 生成 syscall、path 和 mixed 三类确定性负载。每个场景先
校验规范化事件覆盖，再在同机、同内核、固定 CPU governor/affinity 下随机化 auditd 与本系统
顺序，预热后各执行至少 5 次。记录 workload 吞吐/p95、代理 CPU/RSS、perf counters、事件数、
重复、误报和丢失，输出原始 JSON 和不可选择删减的 Markdown 报告。

**Rationale**: 只有规则和正确性等价时才可比较性能。自研负载能给出精确预期事件集合；perf
提供可重复的 CPU 硬件/软件计数。分别报告 capture-only 等价 sink 和 operational logging 两种模式，
避免把不同持久化策略误算为 eBPF 收益。

**Alternatives considered**:

- 只使用通用压力工具：拒绝，无法给出精确预期审计事件。
- 只比较代理进程 CPU：拒绝，可能把开销转移到业务进程或日志系统。
- 跨主机比较：拒绝，硬件、内核和存储差异不可控。
- 只发布最好一次结果：拒绝，违反完整报告和重复测量要求。

**Sources**:

- Linux perf-stat manual: https://man7.org/linux/man-pages/man1/perf-stat.1.html
- auditd configuration source/manuals: https://github.com/linux-audit/audit-userspace
