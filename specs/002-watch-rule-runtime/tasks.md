# Tasks: Watch 规则端到端运行

**Input**: Design documents from `/specs/002-watch-rule-runtime/`

**Prerequisites**: `plan.md`、`spec.md`、`research.md`、`data-model.md`、`contracts/`、`quickstart.md`

**Tests**: 测试是宪章强制门禁。每个故事均先编写失败测试，再完成实现、真实内核验证和独立 Git commit。

**Organization**: 任务按用户故事组织，使 `-w /tmp/ddtest -p rw -k ddtest` 的 MVP、规则可执行性检查和缺口可观测性能够分阶段交付。

## Format: `[ID] [P?] [Story] Description`

- **[P]**: 可在不同文件中并行执行，且不依赖尚未完成的同阶段任务
- **[Story]**: `[US1]`、`[US2]`、`[US3]` 对应规格中的用户故事
- 每项任务均包含明确文件路径
- 每个逻辑里程碑结束时运行适用门禁并创建独立 Git commit
- eBPF、ABI、unsafe、syscall 兼容和 FD 生命周期代码必须提供解释安全边界的中文注释

## Phase 1: Setup（基线与测试语料）

**Purpose**: 固定当前 watch 规则“可解析但运行覆盖为空”的基线，并准备后续 TDD 语料。

- [X] T001 记录当前 `-w /tmp/ddtest -p rw -k ddtest` 的规范化空覆盖、运行时不命中根因、当前测试命令和预期修复边界于 `docs/watch-baseline.md`
- [X] T002 [P] 创建覆盖 `r`、`w`、`rw`、`x`、`a`、失败操作、双路径和 b32/b64 的受支持规则语料于 `tests/fixtures/rules/watch-supported.rules`
- [X] T003 [P] 创建缺少 `-p`、空权限、重复权限、非法字符、相对路径、通配符和缺失 key 的拒绝语料于 `tests/fixtures/rules/watch-rejected.rules`
- [X] T004 [P] 说明 watch fixture 的预期覆盖、错误码和不得包含敏感采集数据的约束于 `tests/fixtures/rules/README.md`
- [X] T005 运行现有 `check-rules`、规则测试、用户态测试和 `git diff --check`，将基线命令与结果更新到 `docs/watch-baseline.md`
- [X] T006 在 T001–T005 门禁通过后创建 `docs: record watch runtime baseline` 里程碑提交，提交范围为 `docs/watch-baseline.md` 和 `tests/fixtures/rules/`

---

## Phase 2: Foundational（权限契约与规则编译）

**Purpose**: 建立所有用户故事共用的 `PermissionMask`、版本化权限矩阵、maintenance syscall 和非空 KernelFilterPlan。

**⚠️ CRITICAL**: 本阶段完成前不得开始用户故事实现。

### Tests First

- [X] T007 [P] 为 `x=1/w=2/r=4/a=8`、集合求交、未知位拒绝和固定 `rwxa` 文本顺序添加失败测试于 `crates/auditd-ebpf-common/tests/permission_mask.rs`
- [X] T008 [P] 为 b64/b32 的 dynamic open、固定 `r/w/x/a` 覆盖、双权限 link 和 coverage version 添加失败测试于 `crates/auditd-ebpf-rules/tests/permission_coverage.rs`
- [X] T009 [P] 为 watch 与 syscall `perm=` 展开、空覆盖拒绝、permission table/总 bitmap 不变量和 rule version 变化添加失败测试于 `crates/auditd-ebpf-rules/tests/compile_rules.rs`
- [X] T010 [P] 为 path/dir/watch 规则自动加入 close/dup/chdir/mount 边界维护调用且维护调用不属于规则覆盖添加失败测试于 `crates/auditd-ebpf-rules/tests/maintenance_coverage.rs`

### Shared Implementation

- [X] T011 实现 `no_std` 兼容的 `PermissionMask`、有效位检查、求交和稳定格式化接口于 `crates/auditd-ebpf-common/src/permission.rs`、`crates/auditd-ebpf-common/src/lib.rs`
- [X] T012 实现 coverage version 1 的 b64/b32 `rwxa` 操作分类、dynamic open 标记和路径来源元数据于 `crates/auditd-ebpf-rules/src/permissions.rs`
- [X] T013 扩展并导出 `RulePermissionCoverage`、每 syscall permission table、maintenance bitmap 和 KernelFilterPlan 不变量于 `crates/auditd-ebpf-rules/src/model.rs`、`crates/auditd-ebpf-rules/src/lib.rs`
- [X] T014 将 watch 和带 `perm=` syscall 规则编译为非空覆盖、总 bitmap、permission table、maintenance 集合及版本摘要于 `crates/auditd-ebpf-rules/src/compiler.rs`
- [X] T015 补齐 coverage version 1 所需 syscall 名称/编号、b64/b32 双向解析和 `<512` 范围验证于 `crates/auditd-ebpf-rules/src/syscalls/x86_64.rs`
- [X] T016 运行 `cargo fmt --check`、`cargo clippy -p auditd-ebpf-common -p auditd-ebpf-rules --all-targets -- -D warnings` 和两 crate 全量测试，并记录通过结果于 `docs/watch-foundation-validation.md`
- [X] T017 在 T007–T016 全部通过后创建 `feat: compile watch permissions into syscall coverage` 里程碑提交，提交范围为 `crates/auditd-ebpf-common/`、`crates/auditd-ebpf-rules/`、`docs/watch-foundation-validation.md`

**Checkpoint**: 规则库能生成非空、版本化、双 ABI 的 watch 运行计划；用户故事实现可以开始。

---

## Phase 3: User Story 1 - 使用 legacy watch 规则审计文件读写 (Priority: P1) 🎯 MVP

**Goal**: 让 `-w /tmp/ddtest -p rw -k ddtest` 在真实内核中对读取、写入和 O_RDWR 分别输出 `r`、`w`、`rw`，并对无关路径零误报。

**Independent Test**: 加载示例规则，执行 cat、tee、O_RDWR 和无关路径操作；目标操作在 10 秒内产生正确 key/path/perm，无关路径不产生 `ddtest`。

### Tests First

- [X] T018 [P] [US1] 为 schema 1 保持布局、permission bits、bit 8 valid、未知 flags 和旧对象 flags=0 行为添加失败 ABI 测试于 `crates/auditd-ebpf-common/tests/abi_layout.rs`、`crates/auditd-ebpf-common/tests/kernel_records.rs`
- [ ] T019 [P] [US1] 为 `CandidateEvent` permission 求交、O_RDWR 多权限、watch/syscall perm 一致性和首条规则顺序添加失败测试于 `crates/auditd-ebpf/tests/rule_engine.rs`
- [ ] T020 [P] [US1] 将现有“FD 更新线程本地”断言改为同 tgid 共享，并添加 fork 快照、exec refresh、dup/close/fd reuse/stale 测试于 `crates/auditd-ebpf/tests/process_cache.rs`
- [ ] T021 [P] [US1] 为 primary/secondary 独立 dirfd、fd-only 路径、截断、mount epoch 和 namespace lexical 边界添加失败测试于 `crates/auditd-ebpf/tests/path_resolution.rs`
- [ ] T022 [P] [US1] 为 `perm="r"`、`perm="w"`、`perm="rw"`、失败操作和 operation syscall 名添加失败 golden 于 `crates/auditd-ebpf/tests/event_format_golden.rs`、`tests/golden/events/`
- [X] T023 [P] [US1] 创建真实内核 watch 测试骨架，先断言当前实现无法得到 r/w/rw 事件于 `tests/privileged/watch_rules.sh`

### Kernel Permission Delivery

- [X] T024 [US1] 定义 `PERMISSION_VALID`、低四位 permission mask、保留位验证和中文 ABI 文档于 `crates/auditd-ebpf-common/src/event.rs`
- [X] T025 [US1] 增加双 generation b64/b32 permission table maps、固定容量和中文 verifier 边界说明于 `crates/auditd-ebpf-ebpf/src/maps.rs`
- [X] T026 [US1] 在 inactive generation 原子 stage permission tables 和 maintenance bitmap，并把 map 缺失视为包含 permission 规则时的加载错误于 `crates/auditd-ebpf/src/loader.rs`
- [X] T027 [US1] 实现静态权限分类、open/openat O_ACCMODE、creat、openat2 入口 8 字节有界读取、flags 投递和扩展路径参数索引于 `crates/auditd-ebpf-ebpf/src/programs/syscall.rs`
- [X] T028 [US1] 扩展内核 smoke 规则与断言，验证 b64 权限 flags、openat2 读取失败、maintenance 不输出和双 generation 无中间态于 `crates/xtask/src/commands/mod.rs`
- [X] T029 [US1] 增加 permission classification failure 的 per-CPU 槽位、求和和内核丢失不变量于 `crates/auditd-ebpf-common/src/counters.rs`、`crates/auditd-ebpf/src/health/counters.rs`
- [X] T030 [US1] 运行共享 ABI 测试、`cargo xtask build-ebpf --release` 和 `cargo xtask test-kernel --kernel host`，记录 verifier、flags 和 generation 结果于 `docs/watch-kernel-validation.md`
- [X] T031 [US1] 在 T018、T023–T030 通过后创建 `feat: deliver watch permission candidates from ebpf` 里程碑提交，提交范围为共享 ABI、eBPF、loader、xtask 和 `docs/watch-kernel-validation.md`

### Process FD and Path Semantics

- [ ] T032 [US1] 将 `ThreadPathContext.fd_table` 重构为 `ProcessFileTable`、`FileAssociation`、Reliable/Stale/Unknown 状态和 stable ProcessIdentity 引用于 `crates/auditd-ebpf/src/process_cache/model.rs`、`crates/auditd-ebpf/src/process_cache/fd_table.rs`
- [ ] T033 [US1] 让 `/proc` bootstrap 按 tgid 合并线程上下文和共享 FD 表，并保留 fd 来源、mount epoch 与刷新失败原因于 `crates/auditd-ebpf/src/process_cache/bootstrap.rs`
- [ ] T034 [US1] 实现同 tgid 线程共享、fork 新进程快照、exec `/proc` 权威刷新、线程/进程退出清理和 PID reuse 防护于 `crates/auditd-ebpf/src/process_cache/lifecycle.rs`、`crates/auditd-ebpf/src/process_cache/mod.rs`
- [ ] T035 [US1] 按成功结果实现 open/creat 覆盖、close 删除、dup/dup2/dup3/fcntl duplication 复制、fd reuse 覆盖和 maintenance-only 更新于 `crates/auditd-ebpf/src/process_cache/fd_table.rs`、`crates/auditd-ebpf/src/runtime.rs`
- [ ] T036 [US1] 解析 primary/secondary 各自 dirfd、fd-only 目标和文档化路径求值顺序，并把缺失、截断、stale、mount 变化返回结构化原因于 `crates/auditd-ebpf/src/process_cache/path.rs`、`crates/auditd-ebpf/src/runtime.rs`
- [ ] T037 [US1] 运行 process_cache/path_resolution 测试和 mount namespace 特权测试，将共享 FD、fork/exec 和 fd reuse 结果记录于 `docs/watch-path-validation.md`
- [ ] T038 [US1] 在 T020–T021、T032–T037 通过后创建 `feat: correlate watch events with process file tables` 里程碑提交，提交范围为 `crates/auditd-ebpf/src/process_cache/`、`crates/auditd-ebpf/src/runtime.rs`、相关测试和 `docs/watch-path-validation.md`

### Rule Match and Audit Output

- [ ] T039 [US1] 将 RuleEngine 的字符集合替换为 `PermissionMask`，统一 watch 与 syscall `perm=` 的求交、路径顺序和首条规则决定逻辑于 `crates/auditd-ebpf/src/rules/engine.rs`
- [ ] T040 [US1] 从 header flags 构造权限候选，区分 maintenance-only、普通 syscall、watch match 和权限未知，不为无规则命中事件输出日志于 `crates/auditd-ebpf/src/runtime.rs`
- [ ] T041 [US1] 按固定 `rwxa` 顺序输出非空 `perm`、实际 syscall operation 和命中路径，保持 stdout/stderr 与转义契约于 `crates/auditd-ebpf/src/output/event_formatter.rs`
- [ ] T042 [US1] 完成 cat、tee、O_RDWR、失败访问、无关路径、属性、exec、dual path、dup/fd reuse 和 b32 可选场景于 `tests/privileged/watch_rules.sh`
- [ ] T043 [US1] 更新 watch 事件 golden、stdout/stderr 流和 journald 单行集成断言于 `tests/golden/events/`、`tests/integration/output_streams.rs`、`tests/integration/logging_end_to_end.sh`
- [ ] T044 [US1] 执行 `quickstart.md` 第 1–9 节、规则/ABI/用户态测试、eBPF build 和 host kernel suite，将逐步结果记录于 `docs/watch-us1-validation.md`
- [ ] T045 [US1] 在 T019、T022、T039–T044 全部通过后创建 `feat: evaluate and report watch rule matches` MVP 里程碑提交，提交范围为规则引擎、runtime、formatter、特权/集成测试和 `docs/watch-us1-validation.md`

**Checkpoint**: US1 独立可运行，示例 `-w /tmp/ddtest -p rw -k ddtest` 已在真实内核通过。

---

## Phase 4: User Story 2 - 在启动前确认 watch 规则确实可执行 (Priority: P2)

**Goal**: `check-rules` 显示非空双 ABI 覆盖；无效/不可执行 watch 整套拒绝；SIGHUP 同时原子切换 bitmap、permission table 和 RuleEngine。

**Independent Test**: 有效规则输出稳定 coverage；非法权限返回 3；无效重载保留旧 key/version，有效重载后只使用新完整版本。

### Tests First

- [ ] T046 [P] [US2] 为 watch 缺失 `-p`、空/重复/非法权限、空覆盖和错误码添加失败 parser/compiler 测试于 `crates/auditd-ebpf-rules/tests/parser_rejected.rs`、`crates/auditd-ebpf-rules/tests/permission_coverage.rs`
- [ ] T047 [P] [US2] 为 `syscalls` 非空、coverage_version、coverage_b64/b32、稳定字段顺序和摘要变化添加失败 CLI 契约测试于 `tests/integration/rule_compatibility.rs`
- [ ] T048 [P] [US2] 为 permission maps 与 syscall bitmap 同 generation 切换、无效候选保留旧版本和并发事件无非法组合添加失败重载测试于 `crates/auditd-ebpf/tests/reload.rs`、`tests/privileged/rule_reload.sh`

### Implementation

- [ ] T049 [US2] 强制 watch 恰好一个非空 `-p`、拒绝重复字符和非法路径，并保留文件/行号诊断于 `crates/auditd-ebpf-rules/src/parser.rs`、`crates/auditd-ebpf-rules/src/diagnostic.rs`
- [ ] T050 [US2] 按契约输出非空 symbolic syscalls、coverage_version 和 b64/b32 权限列表，并使输出参与稳定版本摘要于 `crates/auditd-ebpf-rules/src/normalize.rs`
- [ ] T051 [US2] 在 `check-rules --print-normalized` 输出 coverage，统一 E_PERMISSION/E_PERMISSION_COVERAGE/E_SYSCALL_RANGE/E_WATCH_PATH 退出码 3 诊断于 `crates/auditd-ebpf/src/commands/check_rules.rs`
- [ ] T052 [US2] 扩展 SIGHUP staging，使 syscall bitmap、permission tables、maintenance set、rule version 和 RuleEngine 全部成功后才切换 active generation于 `crates/auditd-ebpf/src/runtime.rs`、`crates/auditd-ebpf/src/reload.rs`
- [ ] T053 [US2] 在 eBPF 对象缺少 permission maps 或包含未知 ABI flags 时拒绝 permission 规则启动并输出可操作中文诊断于 `crates/auditd-ebpf/src/loader.rs`、`crates/auditd-ebpf/src/collector/decode.rs`
- [ ] T054 [US2] 更新规则兼容矩阵、运行命令、coverage 示例、SIGHUP 行为和旧对象限制于 `docs/configuration.md`、`docs/operations.md`、`README.md`
- [ ] T055 [US2] 执行 `quickstart.md` 第 3、4、10 节和 parser/compiler/CLI/reload 全量测试，将有效/无效重载结果记录于 `docs/watch-us2-validation.md`
- [ ] T056 [US2] 在 T046–T055 全部通过后创建 `feat: validate and reload executable watch coverage` 里程碑提交，提交范围为 parser、normalize、CLI、reload、loader、文档和 `docs/watch-us2-validation.md`

**Checkpoint**: 管理员能够在启动前证明 watch 可执行，且重载不会产生空覆盖或非法中间态。

---

## Phase 5: User Story 3 - 识别无法可靠归类的文件操作 (Priority: P3)

**Goal**: permission/path/FD/ring/queue/output 的所有缺口均有单调计数、结构化 gap 和健康状态，并提供正确性前置的性能证据。

**Independent Test**: 分别注入 flags 缺失、openat2 读取失败、FD stale、路径截断、RingBuf 满和 stdout 失败；每类在 10 秒内产生对应计数和 degraded，且没有伪造 watch 事件。

### Tests First

- [ ] T057 [P] [US3] 为 watch candidates/matches、四类权限命中、permission/FD failure 单调性和总流水线不变量添加失败测试于 `crates/auditd-ebpf/tests/health_contract.rs`
- [ ] T058 [P] [US3] 为 permission_flags_missing、classification_failed、fd_missing/stale、path truncated 和 mount stale 的 gap 决策添加失败测试于 `crates/auditd-ebpf/tests/watch_gaps.rs`
- [ ] T059 [P] [US3] 为新增 status/diag 字段、固定顺序、未知值和绝不包含 argv 添加失败 golden 于 `crates/auditd-ebpf/tests/event_format_golden.rs`、`tests/golden/events/status.log`、`tests/golden/events/diag.log`
- [ ] T060 [P] [US3] 创建 permission、FD、path、RingBuf、queue 和 stdout 故障注入脚本骨架于 `tests/failure-injection/watch_rules.sh`
- [ ] T061 [P] [US3] 为 path workload ledger、至少 5 个样本、正确性失败 invalid 和 watch 开关前后指标字段添加失败测试于 `crates/auditd-ebpf-bench/tests/watch_report.rs`

### Observability and Degradation

- [ ] T062 [US3] 增加 watch candidate/match、r/w/x/a match、permission failure 和 FD failure 计数模型及序列化字段于 `crates/auditd-ebpf/src/health/counters.rs`、`crates/auditd-ebpf-common/src/counters.rs`
- [ ] T063 [US3] 将所有 WatchGap 原因接入 OutputPipeline、累计计数和 10 秒内 degraded/unhealthy 状态转换，禁止输出空 perm/path 假事件于 `crates/auditd-ebpf/src/runtime.rs`、`crates/auditd-ebpf/src/health/state.rs`
- [ ] T064 [US3] 输出新增计数、gap reason、rule_version 和故障阶段，保持状态/诊断单行且不含 argv 于 `crates/auditd-ebpf/src/output/status_formatter.rs`、`crates/auditd-ebpf/src/health/reporter.rs`
- [ ] T065 [US3] 完成旧对象 flags=0、openat2 读取失败、FD stale、路径截断、RingBuf 满、queue 满和 EPIPE 的可重复注入于 `tests/failure-injection/watch_rules.sh`

### Performance Evidence

- [ ] T066 [US3] 为确定性 path workload 记录目标路径、操作 ID、预期权限和完成结果 ledger 于 `crates/auditd-ebpf-bench/src/workloads/path.rs`、`crates/auditd-ebpf-bench/src/executor.rs`
- [ ] T067 [US3] 编排同版本关闭 watch 与启用 `-w /tmp/ddtest -p rw -k ddtest` 的 capture-only/operational 预热、测量、冷却和恢复于 `crates/auditd-ebpf-bench/src/runner.rs`、`crates/auditd-ebpf-bench/src/runners/auditd_ebpf.rs`
- [ ] T068 [US3] 强制至少 5 个有效样本、CPU/RSS/吞吐/p95/丢失字段和正确性失败即 invalid 的 watch 报告于 `crates/auditd-ebpf-bench/src/report.rs`、`crates/auditd-ebpf-bench/src/statistics.rs`、`crates/auditd-ebpf-bench/src/metrics.rs`
- [ ] T069 [US3] 执行 `quickstart.md` 第 11–13 节、故障注入和隔离主机 watch 基准，将脱敏结论与原始结果位置记录于 `docs/watch-us3-validation.md`、`docs/watch-performance-validation.md`
- [ ] T070 [US3] 运行 fmt、严格 Clippy、用户态/bench 测试、eBPF build、host kernel 和 failure injection 门禁，并更新结果于 `docs/watch-us3-validation.md`
- [ ] T071 [US3] 在 T057–T070 全部通过后创建 `feat: expose watch gaps and performance evidence` 里程碑提交，提交范围为 `crates/auditd-ebpf/src/health/`、`crates/auditd-ebpf/src/output/`、`crates/auditd-ebpf/src/runtime.rs`、`crates/auditd-ebpf-bench/`、`tests/failure-injection/`、`docs/watch-us3-validation.md`、`docs/watch-performance-validation.md`

**Checkpoint**: 没有静默权限或路径缺口，性能声明具备正确性前置和可复现证据。

---

## Phase 6: Polish & Cross-Cutting Concerns（发布门禁）

**Purpose**: 完成跨故事文档、安全审查、内核矩阵和最终可追溯性。

- [ ] T072 完整执行 `specs/002-watch-rule-runtime/quickstart.md` 并记录每步命令、结果、耗时、SKIP 理由和偏差于 `docs/watch-quickstart-validation.md`
- [ ] T073 [P] 审核 openat2 用户指针读取、map/栈容量、syscall `<512`、unchecked 索引、FD 缓存和 flags 兼容边界于 `docs/watch-security-review.md`
- [ ] T074 [P] 建立 FR-001–FR-016、SR-001–SR-005、SC-001–SC-008 到任务、测试和证据的最终追踪矩阵于 `docs/watch-requirements-traceability.md`
- [ ] T075 [P] 审核新增公共 API、复杂算法、eBPF/unsafe、b32/b64 和 namespace 处理的中文注释与契约同步于 `crates/`、`specs/002-watch-rule-runtime/contracts/`
- [ ] T076 [P] 在可用的 5.15/6.1/6.6/6.12 x86_64 环境验证 b64/b32 watch、reload、gap、计数和清理，并记录于 `tests/vm/results/watch-kernel-matrix.md`
- [ ] T077 运行 workspace fmt、严格 Clippy、全量测试、eBPF release build、host 特权套件、watch quickstart、安全审查和矩阵门禁，将发布判定记录于 `docs/watch-release-validation.md`
- [ ] T078 在 T072–T077 全部通过后创建 `feat: complete end-to-end watch rule support` 发布里程碑提交并推送 `origin/main`，提交范围为 `crates/`、`tests/`、`docs/watch-*.md`、`specs/002-watch-rule-runtime/`、`benchmarks/reports/watch/`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: 无依赖；固定基线和 fixture。
- **Foundational (Phase 2)**: 依赖 T006；T007–T010 先失败，T011–T015 实现后由 T016/T017 封板。
- **US1 (Phase 3)**: 依赖 T017；内核权限投递 T018/T023–T031 → FD/路径 T020/T021/T032–T038 → 规则输出 T019/T022/T039–T045。
- **US2 (Phase 4)**: 规则检查测试可在 T017 后开始；完整原子重载验收依赖 US1 的 permission maps 和 loader，即 T031。
- **US3 (Phase 5)**: 计数测试可在 T017 后开始；运行时 gap、故障注入和性能证据依赖 US1 完成，即 T045；重载相关故障证据建议在 T056 后执行。
- **Polish (Phase 6)**: 依赖 T045、T056、T071，T077/T078 最后执行。

### User Story Dependency Graph

```text
Setup -> Foundation -> US1 (MVP)
                    ├-> US2 executable validation + atomic reload
                    └-> US3 gaps + metrics + performance
US1 + US2 + US3 -> Polish / Release
```

### Within Each User Story

- 所有 Tests First 任务必须先运行并确认因目标缺失而失败，禁止以测试拼写或环境错误代替失败基线。
- 内核 ABI/map/classifier 必须先于用户态 permission 消费。
- ProcessFileTable 必须先于 fd-only 路径和 watch match。
- 规则检查 coverage 必须使用 Foundation 生成的同一矩阵，禁止维护第二套表。
- 性能报告必须在正确性、gap 和丢失门禁通过后才允许标记 valid。
- 每个 commit 任务只能在其列出的测试与验证报告完成后执行。

## Parallel Opportunities

### Foundation

```text
T007 PermissionMask tests
T008 permission matrix tests
T009 compiler expansion tests
T010 maintenance coverage tests
```

### User Story 1

```text
T018 ABI flags tests
T019 RuleEngine permission tests
T020 ProcessFileTable lifecycle tests
T021 path resolution tests
T022 event golden tests
T023 privileged watch script skeleton
```

完成 T031 后，T032/T033 的数据模型与 bootstrap 可以分文件并行；T039/T041 可在 runtime 集成 T040 前分别准备规则引擎和 formatter。

### User Story 2

```text
T046 parser/compiler rejection tests
T047 check-rules output contract tests
T048 reload atomicity tests
```

### User Story 3

```text
T057 health counter tests
T058 watch gap tests
T059 status/diag golden tests
T060 failure injection skeleton
T061 benchmark report tests
```

T066 workload ledger 与 T062–T064 可在不同 crate 并行；T073–T076 的发布审查可在全部故事完成后并行。

## Implementation Strategy

### MVP First

1. 完成 Setup T001–T006。
2. 完成 Foundation T007–T017，确保 watch 编译覆盖非空。
3. 完成 US1 T018–T045，在真实内核证明示例规则正确输出 r/w/rw。
4. 暂停并评审 MVP；此时不得宣称规则预检、全部故障可见或性能证据已经完成。

### Incremental Delivery

1. **MVP**: US1 解决“规则接受但永远无事件”。
2. **Operational Safety**: US2 让管理员在启动前发现空覆盖并保证原子重载。
3. **Observability & Evidence**: US3 使分类/路径/缓冲缺口可见并完成正确性前置性能报告。
4. **Release**: Phase 6 完成安全、矩阵、quickstart 和需求追踪门禁。

### Suggested Review Boundaries

- Commit 1: baseline/fixtures。
- Commit 2: shared permission contract/compiler。
- Commit 3: eBPF permission delivery。
- Commit 4: process-scoped FD/path correlation。
- Commit 5: MVP rule match/output。
- Commit 6: check-rules/reload safety。
- Commit 7: gaps/health/performance。
- Commit 8: final release evidence。
