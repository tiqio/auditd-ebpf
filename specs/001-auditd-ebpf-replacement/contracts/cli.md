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
  [--deployment-mode non-production|production] \
  [--risk-acceptance-file /etc/auditd-ebpf/risk-acceptance.toml] \
  [--emit-argv | --no-emit-argv] \
  [--status-interval 10s] \
  [--shutdown-timeout 30s] \
  [--log-level info]
```

规则选择：

1. 显式 `--rules-file` 优先。
2. 否则读取 `--rules-dir` 中后缀 `.rules` 的普通文件。
3. 目录不存在或没有可用文件时回退 `/etc/audit/audit.rules`。
4. 两者均不可用时启动失败。

argv 与生产策略：

- `--emit-argv` 为默认行为，在事件上限内原样输出匹配 exec 规则的 `a0`–`a31`。
- `--no-emit-argv` 全局抑制 argv 输出，但内核仍按相同上限读取并提交 RingBuf；配置文件允许
  按规则 key 设置 `argv.rules.<key>.enabled=false`，规则级设置优先于全局值。
- 只要某个 key 存在规则级覆盖，候选 RuleSet 中该 key 的 exec 规则必须恰好一条；冲突时
  `run` 和 `check-rules` 均返回规则错误，不得任意选择。
- `--deployment-mode production` 必须提供可信的风险接受文件，并在加载 eBPF 前通过 journal、
  本地文件、导出、rsyslog 目的地、经认证加密转发和保留期验证。
- `non-production` 允许门禁未通过时运行，但状态必须输出 `production_policy=failed`，且不得被
  解释为生产就绪。

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

### `auditd-ebpf check-production`

只验证风险接受记录和日志链路安全策略，不加载 eBPF。检查范围包括 journal 获准组、本地事件
文件不宽于 `0640`、导出不宽于 `0600`、rsyslog 目的地、远端经认证加密、服务端身份验证和
所有目的地保留期。

```text
auditd-ebpf check-production \
  --risk-acceptance-file /etc/auditd-ebpf/risk-acceptance.toml
```

成功时 stdout 输出逐项 PASS 摘要；失败时 stderr 输出稳定错误码和修复建议，并返回退出码 9。

### `auditd-ebpf print-policy-digest`

读取与 `run` 相同的规则和有效配置，输出 `policy_digest_version=1` 及当前日志安全策略的
`sha256:<hex>` 摘要，但不加载 eBPF。摘要覆盖 argv 全局/按 key 输出策略、获准读取主体、
日志目的地、传输认证和逐目的地保留期。

```text
auditd-ebpf print-policy-digest \
  [--rules-dir PATH | --rules-file PATH] \
  [--config /etc/auditd-ebpf/config.toml] \
  [--value-only]
```

`--value-only` 只输出摘要值，供审批文件生成脚本使用。未知摘要版本、规则 key 覆盖冲突或配置
无效时返回相应非零退出码。

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
| 9 | 生产风险接受、策略摘要或日志访问、加密、保留策略门禁失败 |

## Version Output

`auditd-ebpf --version` 必须包含应用版本、Git commit、schema 主版本、Aya 版本和 Rust 版本。
