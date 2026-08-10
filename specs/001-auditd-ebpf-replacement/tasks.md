# Tasks: auditd-ebpf 替代与性能验证

**Input**: `specs/001-auditd-ebpf-replacement/` 下的 `spec.md`、`plan.md`、`research.md`、
`data-model.md`、`contracts/` 和 `quickstart.md`

**Tests**: 测试是宪章强制门禁。每个故事必须先添加失败测试，再实现最小代码，并在真实或
等价 Linux 内核环境验证加载、挂载、事件、丢失和清理。

**Organization**: 任务按用户故事组织。Setup 和 Foundational 完成后，US1 形成可独立验证的
采集 MVP；US2 增加生产日志链路；US3 建立性能证明。每个里程碑通过质量门禁后创建独立 commit。

## Format: `[ID] [P?] [Story] Description`

- **[P]**: 依赖满足后可与同阶段其他 `[P]` 任务并行，且写入文件不重叠。
- **[Story]**: `[US1]`、`[US2]`、`[US3]` 对应 `spec.md` 中的用户故事。
- 每项任务均给出准确文件路径；实现任务必须遵守中文文档和安全注释要求。

## Phase 1: Setup（项目与工具链）

**Purpose**: 建立可复现的 Rust/Aya workspace、构建命令和基础 CI。

- [ ] T001 创建 workspace、release profile、Rust 1.97.1 与 eBPF nightly 固定配置于 `Cargo.toml`、`rust-toolchain.toml`、`rust-toolchain-ebpf.toml`
- [ ] T002 [P] 创建六个 crate 清单并锁定 Aya 0.14、aya-ebpf 0.2.1、aya-log 0.3.0、aya-log-ebpf 0.2.0 与 bpf-linker 0.10.4 于 `crates/auditd-ebpf/Cargo.toml`、`crates/auditd-ebpf-common/Cargo.toml`、`crates/auditd-ebpf-ebpf/Cargo.toml`、`crates/auditd-ebpf-rules/Cargo.toml`、`crates/auditd-ebpf-bench/Cargo.toml`、`crates/xtask/Cargo.toml`
- [ ] T003 [P] 配置 workspace rustfmt、严格 Clippy、cargo-deny 和依赖许可证策略于 `rustfmt.toml`、`clippy.toml`、`deny.toml`
- [ ] T004 实现 `build-ebpf`、`build`、`test-kernel` 命令骨架和中文帮助于 `crates/xtask/src/main.rs`、`crates/xtask/src/commands/mod.rs`
- [ ] T005 [P] 创建用户态、共享 ABI、eBPF、规则和基准模块骨架于 `crates/auditd-ebpf/src/main.rs`、`crates/auditd-ebpf-common/src/lib.rs`、`crates/auditd-ebpf-ebpf/src/main.rs`、`crates/auditd-ebpf-rules/src/lib.rs`、`crates/auditd-ebpf-bench/src/main.rs`
- [ ] T006 [P] 创建测试、fixture、benchmark、packaging 目录说明和占位清单于 `tests/README.md`、`tests/fixtures/rules/README.md`、`benchmarks/README.md`、`packaging/README.md`
- [ ] T007 配置无特权格式、Clippy、单元测试和 eBPF 构建 CI 于 `.github/workflows/ci.yml`
- [ ] T008 编写中文项目入口、构建前提、特权测试说明和安全警告于 `README.md`
- [ ] T009 运行 `cargo fmt --check`、严格 Clippy、workspace 测试和 eBPF 构建，并创建 Setup 里程碑 commit，涉及 `Cargo.toml`、`crates/`、`.github/workflows/ci.yml`

---

## Phase 2: Foundational（阻塞性共享基础）

**Purpose**: 完成所有故事共享的 ABI、加载器、配置、能力探测、队列、健康模型和特权测试框架。

**⚠️ CRITICAL**: 本阶段未完成前不得开始用户故事实现。

### Tests First

- [ ] T010 [P] 为 `KernelEventHeader`、syscall/exec 记录的大小、对齐、版本和越界添加失败布局测试于 `crates/auditd-ebpf-common/tests/abi_layout.rs`
- [ ] T011 [P] 为未知 schema、非法长度、截断记录和非对齐字节添加失败解码测试于 `crates/auditd-ebpf/tests/event_decode.rs`
- [ ] T012 [P] 为 CLI 优先级、容量范围、argv 全局/规则级控制、生产风险接受、未知键和非法单位添加失败配置测试于 `crates/auditd-ebpf/tests/config_contract.rs`
- [ ] T013 [P] 为 BTF、RingBuf、raw tracepoint、tracepoint 和 capability 探测结果添加 mock 测试于 `crates/auditd-ebpf/tests/capability_probe.rs`
- [ ] T014 [P] 为自适应队列容量不变量和健康状态转换添加失败测试于 `crates/auditd-ebpf/tests/foundation_state.rs`

### Shared Implementation

- [ ] T015 实现 `#[repr(C)]` 固定宽度 ABI、schema 常量、记录类型和中文安全文档于 `crates/auditd-ebpf-common/src/event.rs`、`crates/auditd-ebpf-common/src/lib.rs`
- [ ] T016 实现用户态记录长度校验、无未对齐引用的安全解码和错误类型于 `crates/auditd-ebpf/src/collector/decode.rs`、`crates/auditd-ebpf/src/collector/mod.rs`
- [ ] T017 实现 TOML/环境变量/CLI 配置结构、默认容量、argv 全局/规则级控制、生产风险接受模型和严格校验于 `crates/auditd-ebpf/src/config/model.rs`、`crates/auditd-ebpf/src/config/load.rs`、`crates/auditd-ebpf/src/config/mod.rs`
- [ ] T018 实现 `run`、`check-rules`、`check-production`、`print-capabilities`、`benchmark-info` 命令与退出码骨架于 `crates/auditd-ebpf/src/cli.rs`、`crates/auditd-ebpf/src/main.rs`
- [ ] T019 实现内核版本、x86_64、BTF、BPF syscall、RingBuf、raw tracepoint、tracepoint 和 capabilities 探测于 `crates/auditd-ebpf/src/capabilities.rs`
- [ ] T020 实现 eBPF map、每 CPU 基础计数器、活动 generation 和空程序骨架于 `crates/auditd-ebpf-ebpf/src/maps.rs`、`crates/auditd-ebpf-ebpf/src/programs/mod.rs`、`crates/auditd-ebpf-ebpf/src/main.rs`
- [ ] T021 实现 Aya 对象加载、map 获取、程序 attach/link 生命周期和失败清理于 `crates/auditd-ebpf/src/loader.rs`
- [ ] T022 实现按字节计量、硬上限和无界增长保护的 `AdaptiveQueue` 基础类型于 `crates/auditd-ebpf/src/output/adaptive_queue.rs`、`crates/auditd-ebpf/src/output/mod.rs`
- [ ] T023 实现 `Starting/Healthy/Degraded/Unhealthy/Stopping` 状态机和单调计数模型于 `crates/auditd-ebpf/src/health/state.rs`、`crates/auditd-ebpf/src/health/counters.rs`、`crates/auditd-ebpf/src/health/mod.rs`
- [ ] T024 实现 PID+启动时间身份、ABI 架构和有界进程缓存基础类型于 `crates/auditd-ebpf/src/process_cache/model.rs`、`crates/auditd-ebpf/src/process_cache/mod.rs`
- [ ] T025 创建 QEMU/真实内核特权测试驱动、镜像配置和清理检查于 `crates/xtask/src/commands/test_kernel.rs`、`tests/vm/kernels.toml`、`tests/privileged/smoke.sh`
- [ ] T026 配置 5.15/6.1/6.6/6.12 特权自托管 CI job 和缺少 runner 时的明确跳过报告于 `.github/workflows/privileged.yml`
- [ ] T027 运行共享 ABI、配置、能力、加载/卸载 smoke test 和全部 Foundational 门禁，并创建基础里程碑 commit，涉及 `crates/auditd-ebpf-common/`、`crates/auditd-ebpf/`、`crates/auditd-ebpf-ebpf/`、`tests/`

**Checkpoint**: workspace 可构建；空 eBPF 程序可在受支持内核加载、挂载和清理；共享基础测试通过。

---

## Phase 3: User Story 1 - 使用现有审计规则采集事件（Priority: P1）🎯 MVP

**Goal**: 读取受支持 audit 规则子集，可靠采集 syscall、exec 和路径事件，执行 first-match 并暴露所有审计缺口。

**Independent Test**: 使用兼容规则 corpus 启动内存事件 sink，在 5.15+ 特权环境执行确定性
syscall、exec、绝对/相对/dirfd 路径操作；预期事件覆盖 100%、误报和未解释重复为 0，
不支持规则逐行报错且重载失败保留旧版本。

### Tests First

- [ ] T028 [P] [US1] 为注释、空行、syscall form、legacy watch、CRLF 和多 `-S` 添加失败词法/语法测试于 `crates/auditd-ebpf-rules/tests/parser_supported.rs`
- [ ] T029 [P] [US1] 为不支持选项、字段、action、list、路径、key 和冲突条件添加失败诊断 golden test 于 `crates/auditd-ebpf-rules/tests/parser_rejected.rs`、`tests/golden/rule-errors/`
- [ ] T030 [P] [US1] 为文件排序、root 所有权、group/other 可写和 fallback 文件添加失败 RuleSource 测试于 `crates/auditd-ebpf-rules/tests/rule_sources.rs`
- [ ] T031 [P] [US1] 为规范化、first-match、perm 展开、规则 hash 和双 generation 编译添加失败测试于 `crates/auditd-ebpf-rules/tests/compile_rules.rs`
- [ ] T032 [P] [US1] 为 B64/B32 syscall 名称、数字和未知进程 ABI 候选行为添加失败测试于 `crates/auditd-ebpf-rules/tests/syscall_tables.rs`
- [ ] T033 [P] [US1] 为 syscall、ExecAttempt、ExecResult、fork/exit 和每 CPU 丢失记录添加 ABI 契约测试于 `crates/auditd-ebpf-common/tests/kernel_records.rs`
- [ ] T034 [P] [US1] 为 raw sys_enter/sys_exit 加载、粗筛选、返回值和 rule_version 添加特权失败测试于 `tests/privileged/syscall_capture.sh`
- [ ] T035 [P] [US1] 为 exec 成功/失败、32 参数、参数截断和 attempt/result 缺失添加特权失败测试于 `tests/privileged/exec_capture.sh`
- [ ] T036 [P] [US1] 为 fork、exec、exit、PID 复用和 B64/B32 继承添加特权失败测试于 `tests/privileged/process_lifecycle.sh`
- [ ] T037 [P] [US1] 为 `/proc` bootstrap、cwd、dirfd、open/dup/close 和路径置信度添加失败单元测试于 `crates/auditd-ebpf/tests/process_cache.rs`、`crates/auditd-ebpf/tests/path_resolution.rs`
- [ ] T038 [P] [US1] 为绝对、cwd 相对、dirfd 相对、rename/unlink 和无法解析 gap 添加特权失败测试于 `tests/privileged/path_rules.sh`
- [ ] T039 [P] [US1] 为 SIGHUP 原子切换、并发事件版本和无效候选保留旧规则添加特权失败测试于 `tests/privileged/rule_reload.sh`
- [ ] T040 [P] [US1] 为完整兼容 corpus、逐行拒绝和 `check-rules --print-normalized` 添加端到端失败测试于 `tests/integration/rule_compatibility.rs`、`tests/fixtures/rules/`

### Implementation

- [ ] T041 [P] [US1] 实现带文件/行/列 span 的规则 lexer 和控制字符拒绝于 `crates/auditd-ebpf-rules/src/lexer.rs`
- [ ] T042 [US1] 按 EBNF 实现 syscall/watch parser、字段操作符和重复项处理于 `crates/auditd-ebpf-rules/src/parser.rs`
- [ ] T043 [P] [US1] 实现稳定错误码、中文诊断和原始规则安全摘要于 `crates/auditd-ebpf-rules/src/diagnostic.rs`
- [ ] T044 [US1] 实现 `RuleSource`、`AuditRule`、`RuleSet`、验证状态与 SHA-256 版本于 `crates/auditd-ebpf-rules/src/model.rs`、`crates/auditd-ebpf-rules/src/normalize.rs`
- [ ] T045 [P] [US1] 实现 x86_64 B64/B32 syscall 表、perm 操作分类和版本化兼容矩阵于 `crates/auditd-ebpf-rules/src/syscalls/x86_64.rs`、`crates/auditd-ebpf-rules/src/permissions.rs`、`docs/rule-compatibility.md`
- [ ] T046 [US1] 实现 `.rules` C-locale 字节排序、root/模式校验和单文件 fallback 于 `crates/auditd-ebpf-rules/src/source.rs`
- [ ] T047 [US1] 实现粗 syscall/ABI/身份并集、双 generation map 数据和 first-match 用户态计划于 `crates/auditd-ebpf-rules/src/compiler.rs`
- [ ] T048 [US1] 实现 generation maps、syscall bitmap、进程 ABI 提示、inflight 上限和每 CPU 计数器于 `crates/auditd-ebpf-ebpf/src/maps.rs`
- [ ] T049 [US1] 实现 raw sys_enter/sys_exit 粗筛选、参数/返回值采集和 RingBuf 提交于 `crates/auditd-ebpf-ebpf/src/programs/syscall.rs`
- [ ] T050 [US1] 实现最多 32×192 字节 argv 的 ExecAttempt、成功/失败 ExecResult 和中文 verifier 安全注释于 `crates/auditd-ebpf-ebpf/src/programs/exec.rs`
- [ ] T051 [P] [US1] 实现 sched fork/exec/exit 事件和进程 ABI 继承提示于 `crates/auditd-ebpf-ebpf/src/programs/process.rs`
- [ ] T052 [US1] 实现 RingBuf drain、记录解码、attempt/result 关联、超时 gap 和内存 sink 于 `crates/auditd-ebpf/src/collector/runtime.rs`、`crates/auditd-ebpf/src/collector/exec_pending.rs`
- [ ] T053 [US1] 实现 `/proc` bootstrap、PID 启动时间、ELF class、fork/exec/exit 状态更新于 `crates/auditd-ebpf/src/process_cache/bootstrap.rs`、`crates/auditd-ebpf/src/process_cache/lifecycle.rs`
- [ ] T054 [US1] 实现 cwd/fd 缓存、open/dup/close/chdir/fchdir 更新、路径规范化和 gap 生成于 `crates/auditd-ebpf/src/process_cache/fd_table.rs`、`crates/auditd-ebpf/src/process_cache/path.rs`
- [ ] T055 [US1] 实现 arch/uid/gid/success/path/dir/perm 精确求值、first-match 和 `ResolvedAuditEvent` 于 `crates/auditd-ebpf/src/rules/engine.rs`、`crates/auditd-ebpf/src/rules/mod.rs`
- [ ] T056 [US1] 实现 inactive generation staging、原子切换、失败回滚和 SIGHUP reload service 于 `crates/auditd-ebpf/src/reload.rs`
- [ ] T057 [US1] 完成 `check-rules`、规范化输出、rule_version 状态和兼容矩阵生成于 `crates/auditd-ebpf/src/commands/check_rules.rs`、`crates/auditd-ebpf/src/commands/mod.rs`、`docs/rule-compatibility.md`
- [ ] T058 [US1] 运行 parser/ABI/5.15+ 特权采集/路径/reload 及 US1 quickstart 验证，并创建采集 MVP 里程碑 commit，涉及 `crates/auditd-ebpf-rules/`、`crates/auditd-ebpf-ebpf/`、`crates/auditd-ebpf/src/collector/`、`crates/auditd-ebpf/src/process_cache/`

**Checkpoint**: US1 可通过内存 sink 独立证明规则兼容、采集正确性、路径缺口可见和原子重载。

---

## Phase 4: User Story 2 - 通过系统日志链路管理审计记录（Priority: P2）

**Goal**: 将匹配事件以稳定单行 audit 风格写 stdout，通过 journald 查询和 rsyslog 分流，同时有界吸收背压并公开健康状态。

**Independent Test**: 触发唯一 key 事件后 10 秒内从 `journalctl -u auditd-ebpf` 和 rsyslog
目标文件检索同一 `event_id`；暂停下游时队列增长到硬上限，业务不阻塞，丢失产生 gap、计数和 degraded。

### Tests First

- [ ] T059 [P] [US2] 为固定字段顺序、`AUDITD_EBPF`、gap、diag 和 status 添加 golden contract test 于 `crates/auditd-ebpf/tests/event_format_golden.rs`、`tests/golden/events/`
- [ ] T060 [P] [US2] 为引号、反斜杠、CR/LF/NUL、非 UTF-8 和 16 KiB 上限添加属性测试于 `crates/auditd-ebpf/tests/event_escape.rs`
- [ ] T061 [P] [US2] 为审计 stdout、诊断/status stderr 和永久 EPIPE 退出码添加进程集成测试于 `tests/integration/output_streams.rs`
- [ ] T062 [P] [US2] 为 64 MiB 起始、80% 高水位、512 MiB 硬上限、缩容和 drop-new 添加失败测试于 `crates/auditd-ebpf/tests/adaptive_queue.rs`
- [ ] T063 [P] [US2] 为计数不变量、degraded 恢复窗口、unhealthy 和 final 状态添加失败测试于 `crates/auditd-ebpf/tests/health_contract.rs`
- [ ] T064 [P] [US2] 为 SIGUSR1、SIGTERM 排空、超时退出码 8 和信号重入添加集成测试于 `tests/integration/signals.rs`
- [ ] T065 [P] [US2] 为 systemd unit 启动、reload、journal 单行查询和 capability 边界添加特权测试于 `tests/privileged/systemd_journal.sh`
- [ ] T066 [P] [US2] 为 rsyslog imjournal 状态文件、事件/状态分流、断网队列和恢复添加特权测试于 `tests/privileged/rsyslog_pipeline.sh`

### Implementation

- [ ] T067 [US2] 实现固定字段顺序、audit msg、可逆字节转义、argv 截断和 16 KiB 上限于 `crates/auditd-ebpf/src/output/event_formatter.rs`
- [ ] T068 [P] [US2] 实现 `AUDITD_EBPF_GAP`、`AUDITD_EBPF_DIAG`、`AUDITD_EBPF_STATUS` 格式器于 `crates/auditd-ebpf/src/output/status_formatter.rs`
- [ ] T069 [US2] 实现 collector→AdaptiveQueue→stdout writer、按字节动态增长、硬上限 drop-new 和 flush 错误处理于 `crates/auditd-ebpf/src/output/writer.rs`、`crates/auditd-ebpf/src/output/adaptive_queue.rs`
- [ ] T070 [US2] 实现 eBPF 每 CPU 计数聚合、状态变化即时记录、10 秒周期记录和 5 分钟恢复窗口于 `crates/auditd-ebpf/src/health/reporter.rs`、`crates/auditd-ebpf/src/health/counters.rs`
- [ ] T071 [US2] 实现启动顺序、ready、信号优先级、停止排空、link 清理和最终状态于 `crates/auditd-ebpf/src/runtime.rs`
- [ ] T072 [US2] 将配置、生产风险接受与日志策略门禁、capability、loader、rules、collector、writer 和 health 组装进 `run`/`check-production` 命令于 `crates/auditd-ebpf/src/commands/run.rs`、`crates/auditd-ebpf/src/commands/check_production.rs`、`crates/auditd-ebpf/src/main.rs`
- [ ] T073 [P] [US2] 编写最小 capability、只读文件系统、journal 输出和 reload 的 hardened unit 于 `packaging/systemd/auditd-ebpf.service`
- [ ] T074 [P] [US2] 编写 imjournal 持久游标、事件/运维分流、磁盘辅助队列和限速配置于 `packaging/rsyslog/60-auditd-ebpf.conf`
- [ ] T075 [P] [US2] 编写中文配置参考、argv 默认原样输出与关闭控制、systemd/journal 访问权限、rsyslog 加密转发、保留期和生产风险接受于 `docs/configuration.md`、`docs/operations.md`
- [ ] T076 [US2] 按 quickstart 执行 journalctl、rsyslog、backpressure、reload 和 shutdown 端到端测试并保存脚本于 `tests/integration/logging_end_to_end.sh`
- [ ] T077 [US2] 运行格式/属性/信号/systemd/rsyslog/背压和 US2 quickstart 门禁，并创建日志集成里程碑 commit，涉及 `crates/auditd-ebpf/src/output/`、`crates/auditd-ebpf/src/health/`、`packaging/`

**Checkpoint**: US2 可独立证明完整单行日志进入 journal 和 rsyslog，且下游变慢不会阻塞业务并能暴露缺口。

---

## Phase 5: User Story 3 - 获得可复现的性能提升证据（Priority: P3）

**Goal**: 在正确性等价前提下执行 capture-only 与 operational 两类 auditd 对照，生成不可选择删减、可复现的原始数据和结论。

**Independent Test**: 在隔离主机对 syscall/path/mixed 每场景每方案至少取得 5 个有效样本，
所有样本通过正确性门禁，报告包含全部原始数据、环境、规则、随机顺序和统计，并由第二名维护者复现方向。

### Tests First

- [ ] T078 [P] [US3] 为 syscall workload 的操作序号、期望事件和固定 seed 可重复性添加失败测试于 `crates/auditd-ebpf-bench/tests/syscall_workload.rs`
- [ ] T079 [P] [US3] 为 path/mixed workload 的绝对、cwd、dirfd、rename/unlink 和 exec 期望集合添加失败测试于 `crates/auditd-ebpf-bench/tests/path_mixed_workload.rs`
- [ ] T080 [P] [US3] 为 auditd 与 auditd-ebpf 记录规范化、字段缺失和 event_id 去重添加失败测试于 `crates/auditd-ebpf-bench/tests/normalization.rs`
- [ ] T081 [P] [US3] 为覆盖率、误报、重复、丢失计数和 invalid 判定添加失败 correctness gate 测试于 `crates/auditd-ebpf-bench/tests/correctness_gate.rs`
- [ ] T082 [P] [US3] 为中位数、MAD、bootstrap CI、CPU/吞吐/延迟改善公式和阈值边界添加失败测试于 `crates/auditd-ebpf-bench/tests/statistics.rs`
- [ ] T083 [P] [US3] 为随机运行顺序、污染样本、完整报告和禁止隐藏失败样本添加失败测试于 `crates/auditd-ebpf-bench/tests/report_contract.rs`

### Implementation

- [ ] T084 [US3] 实现 benchmark CLI、环境/场景/样本/报告模型和 protocol 版本于 `crates/auditd-ebpf-bench/src/cli.rs`、`crates/auditd-ebpf-bench/src/model.rs`、`crates/auditd-ebpf-bench/src/main.rs`
- [ ] T085 [P] [US3] 实现固定 seed 的 syscall workload、operation-id 和期望事件生成于 `crates/auditd-ebpf-bench/src/workloads/syscall.rs`
- [ ] T086 [P] [US3] 实现专用临时目录、绝对/cwd/dirfd 和文件操作 path workload 于 `crates/auditd-ebpf-bench/src/workloads/path.rs`
- [ ] T087 [P] [US3] 实现进程 exec、syscall 和 path 固定比例 mixed workload 于 `crates/auditd-ebpf-bench/src/workloads/mixed.rs`
- [ ] T088 [P] [US3] 实现硬件、内核/BTF hash、governor、affinity、日志配置、版本和 Git commit 采集于 `crates/auditd-ebpf-bench/src/environment.rs`
- [ ] T089 [US3] 实现传统 auditd 启停、规则安装、RAW 事件收集、配置备份和恢复于 `crates/auditd-ebpf-bench/src/runners/auditd.rs`
- [ ] T090 [P] [US3] 实现 auditd-ebpf 启停、规则安装、capture-only/operational sink 和最终计数收集于 `crates/auditd-ebpf-bench/src/runners/auditd_ebpf.rs`
- [ ] T091 [P] [US3] 实现 perf stat、CPU/RSS、system 指标和 journal/rsyslog queue 采集于 `crates/auditd-ebpf-bench/src/metrics.rs`
- [ ] T092 [US3] 实现 auditd 多记录与单行 eBPF 事件规范化、正确性集合比较和 invalid 原因于 `crates/auditd-ebpf-bench/src/correctness.rs`
- [ ] T093 [US3] 实现中位数/MAD/bootstrap CI、规格阈值判定、完整 JSON 和 Markdown 报告于 `crates/auditd-ebpf-bench/src/statistics.rs`、`crates/auditd-ebpf-bench/src/report.rs`
- [ ] T094 [US3] 实现等价非持久 sink、基线、预热、120 秒测量和冷却的 capture-only runner 于 `crates/auditd-ebpf-bench/src/modes/capture_only.rs`
- [ ] T095 [US3] 实现 auditd 文件日志与 journald/rsyslog 差异记录的 operational runner 于 `crates/auditd-ebpf-bench/src/modes/operational.rs`
- [ ] T096 [US3] 实现固定 seed 随机顺序、每场景至少 5 个有效样本、污染检测和恢复编排于 `crates/auditd-ebpf-bench/src/runner.rs`
- [ ] T097 [US3] 执行预备基准并根据 perf 热点优化内核粗筛选、collector 和 formatter 于 `crates/auditd-ebpf-ebpf/src/programs/syscall.rs`、`crates/auditd-ebpf/src/collector/runtime.rs`、`crates/auditd-ebpf/src/output/event_formatter.rs`
- [ ] T098 [US3] 在隔离主机执行完整 syscall/path/mixed × capture-only/operational × 5+ 样本，并将动态报告目录及全部数据索引写入 `benchmarks/reports/final/manifest.json`
- [ ] T099 [US3] 由第二名维护者复现方向并记录复现环境、差异、动态报告路径和签字结论于 `benchmarks/reports/final/reproduction.md`
- [ ] T100 [US3] 运行 workload/correctness/statistics/report 测试，核对 SC-005–SC-007，并创建性能证明里程碑 commit，涉及 `crates/auditd-ebpf-bench/`、`benchmarks/reports/`

**Checkpoint**: 只有报告状态 `passed` 才允许宣称性能提升；`failed` 或 `invalid` 报告必须完整保留。

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: 完成跨故事安全、兼容、稳定性、文档、打包和发布质量门禁。

- [ ] T101 [P] 审核公共 API、ABI 字段、复杂算法、兼容处理和错误路径的中文文档与注释于 `crates/auditd-ebpf-common/src/`、`crates/auditd-ebpf/src/`、`crates/auditd-ebpf-ebpf/src/`、`crates/auditd-ebpf-rules/src/`
- [ ] T102 [P] 审核所有 unsafe、用户/内核指针读取、循环上界、栈/map 容量和 verifier 日志并记录结论于 `docs/security-review.md`
- [ ] T103 [P] 运行 cargo-deny、依赖许可证、安全公告和上游来源审计并固定结果于 `deny.toml`、`docs/dependency-audit.md`
- [ ] T104 [P] 验证并收紧 systemd capabilities、NoNewPrivileges、ProtectSystem、可写路径、规则文件权限、journal 获准组、本地日志 `0640`、导出 `0600`、rsyslog 目的地、经认证加密转发和风险接受门禁于 `packaging/systemd/auditd-ebpf.service`、`tests/privileged/systemd_sandbox.sh`
- [ ] T105 在 5.15/6.1/6.6/6.12 x86_64 执行加载、规则、事件、丢失、reload 和清理矩阵并保存结果于 `tests/vm/results/kernel-matrix.md`
- [ ] T106 [P] 添加规则 lexer/parser fuzz target、恶意路径/argv corpus 和资源上限回归于 `fuzz/Cargo.toml`、`fuzz/fuzz_targets/rule_parser.rs`、`fuzz/corpus/rule_parser/`
- [ ] T107 执行 24 小时稳定性、内存增长、计数不变量和无遗留 link/map 测试并保存结果于 `tests/stability/run-24h.sh`、`tests/stability/report.md`
- [ ] T108 [P] 注入 RingBuf 满、用户队列满、stdout 关闭、journald 限速、rsyslog 断网和磁盘满故障于 `tests/failure-injection/run.sh`、`tests/failure-injection/report.md`
- [ ] T109 完整执行 `specs/001-auditd-ebpf-replacement/quickstart.md` 并记录每步命令、结果和偏差于 `docs/quickstart-validation.md`
- [ ] T110 [P] 实现安装、升级、卸载、auditd 冲突保护和配置保留脚本于 `packaging/install.sh`、`packaging/uninstall.sh`、`packaging/upgrade.sh`
- [ ] T111 核对 FR-001–FR-016、SR-001–SR-003a、SR-004–SR-007、SC-001–SC-009 与测试证据的最终追踪矩阵于 `docs/requirements-traceability.md`
- [ ] T112 [P] 编写版本、迁移限制、已知路径语义差异、回滚和性能报告链接于 `CHANGELOG.md`、`docs/release-notes.md`
- [ ] T113 运行 workspace 全量格式/Clippy/test、eBPF 构建、内核矩阵、安全、稳定性、quickstart 和报告门禁，并创建发布里程碑 commit，涉及 `Cargo.toml`、`crates/`、`tests/`、`docs/`、`packaging/`、`benchmarks/reports/`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: 无依赖，T001 → T002–T008 → T009。
- **Foundational (Phase 2)**: 依赖 T009；T010–T014 必须先失败，再完成 T015–T026，最后 T027。
- **US1 (Phase 3)**: 依赖 T027；是可交付 MVP，并阻塞生产日志和性能对照。
- **US2 (Phase 4)**: 依赖 T058 提供 `ResolvedAuditEvent`、collector 和规则生命周期。
- **US3 (Phase 5)**: capture-only 依赖 T058；operational 与最终报告依赖 T077，因此按整体阶段在 US2 后执行。
- **Polish (Phase 6)**: 依赖 T100；T101–T112 可按标记并行，T113 最后执行。

### User Story Dependency Graph

```text
Setup → Foundational → US1 (MVP) → US2 → US3 → Polish/Release
                         └────────→ US3 capture-only 基础可提前并行开发
```

### Within Each User Story

- 所有 `Tests First` 任务必须先提交失败证据，再执行实现任务。
- 模型/解析器/ABI 在服务编排之前；内核采集在精确规则与输出之前。
- 契约测试必须在端到端测试之前通过。
- 每个 checkpoint 的全部门禁通过后才允许创建对应 Git commit。

## Parallel Opportunities

### Setup / Foundational

- T002、T003、T005、T006 可在 T001 后并行。
- T010–T014 写入不同测试文件，可并行建立失败基线。
- T017、T019、T022、T023、T024 可在 T015/T016 接口稳定后按文件并行。

### User Story 1

```text
并行测试：T028 T029 T030 T031 T032 T033 T034 T035 T036 T037 T038 T039 T040
并行实现：T041 与 T043；T045 与 T046；T050 与 T051
集成关键路径：T042 → T044 → T047 → T048/T049 → T052 → T053/T054 → T055 → T056/T057 → T058
```

### User Story 2

```text
并行测试：T059 T060 T061 T062 T063 T064 T065 T066
并行实现：T068、T073、T074、T075
集成关键路径：T067 → T069 → T070 → T071 → T072 → T076 → T077
```

### User Story 3

```text
并行测试：T078 T079 T080 T081 T082 T083
并行实现：T085 T086 T087 T088；T090 与 T091
集成关键路径：T084 → T089/T090/T091 → T092/T093 → T094/T095 → T096 → T097 → T098 → T099 → T100
```

## Implementation Strategy

### MVP First

1. 完成 Setup 和 Foundational。
2. 完成 US1 到 T058，使用内存 sink 验证规则兼容、事件正确性和重载。
3. **STOP AND VALIDATE**：在 5.15+ 内核独立演示规则加载、exec/path 事件和 gap 可见性。

### Incremental Delivery

1. **MVP**: US1 提供可信采集和规则兼容。
2. **Operational**: US2 提供 stdout、journal、rsyslog、背压和健康状态。
3. **Evidence**: US3 提供 auditd 公平对照和可复现性能报告。
4. **Release**: Polish 完成内核矩阵、安全、24 小时稳定性和打包。

## Notes

- `[P]` 只表示文件写入和直接依赖允许并行，不允许跳过所属阶段门禁。
- 特权测试缺少环境时可以报告跳过，但不得删除测试或把跳过当作通过。
- `benchmarks/reports/` 中 invalid/failed 样本必须提交或归档，不得只保留通过样本。
- 所有里程碑 commit 必须在对应任务列出的质量门禁通过后创建。
