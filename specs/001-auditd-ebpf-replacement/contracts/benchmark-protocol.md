# Contract: auditd 对照基准协议

## Goal

在事件正确性等价的前提下，量化传统 auditd 与 auditd-ebpf 对业务吞吐、延迟、CPU、内存和
事件丢失的影响。任何未通过正确性门禁的数据不得用于性能提升声明。

## Test Modes

### Capture-Only

隔离采集本身的成本。两种方案使用同一规则、同一 workload 和等价的非持久本地 sink；
sink 必须完整消费记录但不执行磁盘同步或远端传输。

### Operational Logging

- auditd 使用记录在报告中的标准本地日志配置。
- auditd-ebpf 使用 systemd journal 与 rsyslog 本地 action queue。
- 两者的 flush、同步、文件系统和日志目的地差异必须单独列出，不得将该模式结果解释为纯采集差异。

## Environment Controls

每份报告必须记录：

- 主机厂商/型号、CPU 型号/微码、核数、内存、NUMA。
- Linux 版本、内核配置 hash、启动参数、BTF hash。
- auditd/audit-userspace 版本和完整 `auditd.conf`。
- auditd-ebpf Git commit、构建 profile、Rust/Aya 版本和所有容量。
- 规则文件内容与 SHA-256、workload 版本与参数。
- CPU governor、turbo、IRQ affinity、workload/代理 affinity。
- 文件系统、挂载参数、可用空间、journal/rsyslog 配置。

基准期间禁止自动更新、定时备份和其他已知高负载服务。无法隔离时报告必须标记受污染样本。

## Scenarios

### `syscall`

固定线程执行 getpid、openat/close、read、write 等 syscall 组合；规则只选择其中声明部分。
驱动保存每个操作序号与预期命中集合。

### `path`

在专用临时目录执行 create、read、write、chmod、rename、unlink 和目录操作，包含绝对路径、
cwd 相对路径和 dirfd 相对路径。测试目录位于固定文件系统，不使用生产数据。

### `mixed`

按固定比例混合进程创建/exec、syscall 和路径操作，模拟构建或服务请求型负载。

## Correctness Gate

每个样本在性能统计前必须：

1. 将两种方案记录规范化为 `(operation-id, rule-key, syscall, success, identity, path)`。
2. 与 workload 的期望集合比较。
3. 要求覆盖率 100%、误报 0、未解释重复 0。
4. 要求所有压力丢失与公开计数一致。
5. 任一项失败则样本为 invalid，不得补测后隐藏原始失败；原因必须保留。

## Run Order

1. 重启或恢复已记录的干净环境。
2. 验证 CPU governor、affinity、内核参数、规则 hash 和日志 sink。
3. 运行 30 秒无审计基线。
4. 对当前方案预热 30 秒。
5. 测量 120 秒并采集事件和 perf 数据。
6. 停止方案，等待温度和系统负载恢复到阈值。
7. 使用固定随机种子打乱 auditd/auditd-ebpf 顺序。
8. 每场景、每模式、每方案至少获得 5 个有效样本。

## Metrics

- workload：operations/s、p50/p95/p99 latency、失败数。
- agent：task-clock、CPU%、user/system time、max/mean RSS。
- system：总 CPU、context switches、cpu migrations、page faults。
- perf：cycles、instructions、branches、branch-misses、cache-misses。
- audit：expected、observed、missing、duplicate、false-positive、ring/queue/path loss。
- logging：journal/rsyslog queue depth、rate-limit drops、sink bytes。

建议命令形态：

```text
perf stat -x, -e task-clock,cycles,instructions,context-switches,cpu-migrations,page-faults \
  -- auditd-ebpf-bench workload --scenario syscall --duration 120s --seed 42
```

## Statistics

- 报告所有有效和无效样本，不允许只选最好值。
- 主要比较使用中位数；同时报告 min/max、MAD 和 bootstrap 95% confidence interval。
- CPU 改善按 `(auditd - auditd-ebpf) / auditd` 计算。
- 吞吐改善按 `(auditd-ebpf - auditd) / auditd` 计算。
- 延迟改善按 `(auditd - auditd-ebpf) / auditd` 计算。

## Pass Criteria

只有同时满足以下条件时报告状态为 `passed`：

1. 所有用于比较的样本通过 Correctness Gate。
2. syscall/path/mixed 三类 agent CPU 中位数均降低至少 20%。
3. 任一类别 workload 吞吐不得下降超过 2%。
4. 至少两类吞吐提升 10%，或 p95 延迟降低 10%。
5. 另一名维护者在同等环境复现方向一致的结果。

否则报告为 `failed`；正确性失败则为 `invalid`。

## Artifacts

```text
benchmarks/reports/<date>-<host>-<commit>/
├── environment.json
├── rules/
├── configs/
├── raw/<scenario>/<mode>/<implementation>/<run>.json
├── normalized-events/
├── summary.json
└── report.md
```

`report.md` 必须链接全部原始文件并列出 invalid 样本，不能仅包含汇总表。
