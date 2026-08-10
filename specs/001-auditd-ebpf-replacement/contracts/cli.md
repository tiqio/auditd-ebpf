# Contract: CLI、配置与信号

## Commands

### `auditd-ebpf run`

启动长期运行服务，也是无子命令时的默认行为。

```text
auditd-ebpf run \
  [--rules-dir /etc/audit/rules.d] \
  [--rules-file /etc/audit/audit.rules] \
  [--ring-buffer-bytes 16777216] \
  [--queue-initial-bytes 67108864] \
  [--queue-max-bytes 536870912] \
  [--status-interval 10s] \
  [--shutdown-timeout 30s] \
  [--log-level info]
```

规则选择：

1. 显式 `--rules-file` 优先。
2. 否则读取 `--rules-dir` 中后缀 `.rules` 的普通文件。
3. 目录不存在或没有可用文件时回退 `/etc/audit/audit.rules`。
4. 两者均不可用时启动失败。

### `auditd-ebpf check-rules`

仅执行文件权限、词法、语法、语义、容量和内核 syscall table 验证，不加载 eBPF。

```text
auditd-ebpf check-rules [--rules-dir PATH | --rules-file PATH] [--print-normalized]
```

- 成功时 stdout 输出摘要或规范化规则。
- 失败时 stderr 每行输出一个带文件、行、列和错误码的诊断。

### `auditd-ebpf print-capabilities`

探测并输出内核版本、架构、BTF、BPF syscall、RingBuf、raw tracepoint、tracepoint、
所需 capabilities 和每项 PASS/FAIL。探测失败返回非零。

### `auditd-ebpf benchmark-info`

输出构建版本、Git commit、Rust/Aya 版本、默认容量、schema 和 benchmark protocol 版本，
供基准报告采集环境信息。

## Configuration Precedence

```text
CLI arguments > environment variables > /etc/auditd-ebpf/config.toml > compiled defaults
```

环境变量使用 `AUDITD_EBPF_` 前缀。未知配置键、非法单位或越界值必须失败，禁止忽略。

## Capacity Validation

- RingBuf 必须为 2 的幂，范围 1 MiB–256 MiB。
- 初始队列范围 16 MiB–1 GiB，且不得大于最大队列。
- 最大队列范围 16 MiB–4 GiB。
- 最大规则数 1–4,096；最大并发 syscall 上下文 1,024–262,144。

## Signals

| Signal | Behavior |
|---|---|
| `SIGHUP` | 验证并 staging 新 RuleSet；成功后原子切换，失败保留旧版本 |
| `SIGTERM` | 进入 Stopping，停止接收、按超时排空、输出最终状态并退出 |
| `SIGINT` | 与 SIGTERM 相同，便于前台运行 |
| `SIGUSR1` | 立即向 stderr 输出一次 HealthSnapshot，不改变状态 |

同类信号重入必须合并：重载进行时的新 SIGHUP 设置一次 pending；停止信号优先于重载。

## Exit Codes

| Code | Meaning |
|---:|---|
| 0 | 正常停止或检查成功 |
| 2 | CLI/配置参数错误 |
| 3 | 规则读取或验证失败 |
| 4 | 文件权限或 capability 不满足 |
| 5 | 内核能力、架构或 BTF 不满足 |
| 6 | eBPF 加载、map 或 attach 失败 |
| 7 | 运行时不可恢复错误，包括 stdout 永久失败 |
| 8 | 停止排空超时；最终状态记录包含未输出数量 |

## Version Output

`auditd-ebpf --version` 必须包含应用版本、Git commit、schema 主版本、Aya 版本和 Rust 版本。
