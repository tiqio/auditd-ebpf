# Quickstart Validation: auditd-ebpf 替代与性能验证

本指南描述实现完成后的端到端验收流程，不替代生产部署手册。

## 1. Prerequisites

- x86_64 Linux 5.15+，root 或等价受控 capabilities。
- `/sys/kernel/btf/vmlinux` 存在。
- systemd、journald、rsyslog、audit-userspace 和 Linux perf 可用。
- Rust 1.97.1 stable、`nightly-2026-08-06`、`rust-src` 和 `bpf-linker`。
- 测试主机不得承载生产审计或敏感业务。

先确认内核与 BTF：

```bash
uname -m
uname -r
test -r /sys/kernel/btf/vmlinux
```

期望：架构为 `x86_64`、内核不低于 5.15、BTF 文件可读。

## 2. Build

```bash
rustup toolchain install 1.97.1
rustup toolchain install nightly-2026-08-06 --component rust-src
cargo install bpf-linker --version 0.10.4 --locked
cargo xtask build-ebpf --release
cargo build --workspace --release
```

最低构建门禁：

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

## 3. Create a Supported Rule Set

```bash
sudo install -d -m 0750 -o root -g root /etc/auditd-ebpf/rules.d
sudo tee /etc/auditd-ebpf/rules.d/10-validation.rules >/dev/null <<'RULES'
# 记录 x86_64 exec
-a always,exit -F arch=b64 -S execve,execveat -k exec-test

# 记录身份文件写入和属性变化
-w /tmp/auditd-ebpf-validation/identity -p wa -k identity-test
RULES
sudo chown root:root /etc/auditd-ebpf/rules.d/10-validation.rules
sudo chmod 0640 /etc/auditd-ebpf/rules.d/10-validation.rules
```

规则子集以 [audit-rule-subset.ebnf](contracts/audit-rule-subset.ebnf) 为准。

## 4. Validate Rules and Kernel Capabilities

```bash
sudo target/release/auditd-ebpf check-rules \
  --rules-dir /etc/auditd-ebpf/rules.d \
  --print-normalized

sudo target/release/auditd-ebpf print-capabilities
```

期望：命令均返回 0；规则摘要包含 2 条规则；BTF、RingBuf、raw tracepoint 和 tracepoint 均 PASS。

负例：加入 `-F auid=1000` 后 `check-rules` 必须返回 3，并准确报告文件与行号；删除负例后继续。

## 5. Run Foreground Validation

传统 auditd 必须在隔离测试机上停止，避免重复事件：

```bash
sudo systemctl stop auditd || sudo service auditd stop
sudo mkdir -p /tmp/auditd-ebpf-validation
sudo touch /tmp/auditd-ebpf-validation/identity

sudo target/release/auditd-ebpf run \
  --rules-dir /etc/auditd-ebpf/rules.d \
  --status-interval 2s
```

在另一终端触发事件：

```bash
/usr/bin/id -u
sudo sh -c 'echo test >> /tmp/auditd-ebpf-validation/identity'
sudo chmod 0600 /tmp/auditd-ebpf-validation/identity
```

期望 stdout 出现 `type=AUDITD_EBPF`，分别包含 `key="exec-test"` 和
`key="identity-test"`。exec 事件必须包含完整测试 argv 或显式 `argv_truncated=yes`。

输出格式以 [event-format.md](contracts/event-format.md) 为准。

## 6. Validate Reload

修改规则 key 后执行：

```bash
sudo kill -HUP "$(pidof auditd-ebpf)"
```

期望 stderr 出现新的 `rule_version` 和 reload success；后续事件只使用新 key。放入无效规则并
再次 SIGHUP 时，重载失败但旧 `rule_version` 继续生效。

## 7. Validate systemd and journalctl

```bash
sudo install -m 0755 target/release/auditd-ebpf /usr/sbin/auditd-ebpf
sudo install -m 0644 packaging/systemd/auditd-ebpf.service \
  /etc/systemd/system/auditd-ebpf.service
sudo systemctl daemon-reload
sudo systemctl enable --now auditd-ebpf.service

/usr/bin/true validation-argument
journalctl -u auditd-ebpf.service --since '-1 minute' --no-pager
```

期望：审计事件、诊断和状态均为单行；可按 `AUDITD_EBPF`、`AUDITD_EBPF_STATUS` 区分。

## 8. Validate rsyslog Routing

```bash
sudo install -m 0644 packaging/rsyslog/60-auditd-ebpf.conf \
  /etc/rsyslog.d/60-auditd-ebpf.conf
sudo rsyslogd -N1
sudo systemctl restart rsyslog

/usr/bin/id auditd-ebpf-rsyslog-test
sudo grep 'key="exec-test"' /var/log/auditd-ebpf/events.log
```

期望：目标文件中存在完整单行事件；状态和诊断不混入事件文件。具体路由必须符合
[health-and-logging.md](contracts/health-and-logging.md)。

## 9. Validate Backpressure and Loss Visibility

在测试配置中把用户队列上限降到 16 MiB，并暂停 rsyslog sink，运行高事件率 workload：

```bash
sudo systemctl stop rsyslog
sudo target/release/auditd-ebpf-bench workload \
  --scenario syscall --duration 60s --threads "$(nproc)"
sudo kill -USR1 "$(pidof auditd-ebpf)"
```

期望：业务 workload 不被阻塞；队列先增长到硬上限；发生丢弃时出现
`type=AUDITD_EBPF_GAP`，状态变为 degraded，`ring_lost` 或 `queue_lost` 非零且与 gap 数量一致。

## 10. Run Privileged Kernel Tests

```bash
sudo cargo xtask test-kernel --kernel 5.15
sudo cargo xtask test-kernel --kernel 6.1
sudo cargo xtask test-kernel --kernel 6.6
sudo cargo xtask test-kernel --kernel 6.12
```

测试必须覆盖加载、挂载、syscall/exec/path 事件、规则重载、RingBuf 丢失、异常停止和 link 清理。

## 11. Run the auditd Comparison

```bash
sudo target/release/auditd-ebpf-bench prepare --output benchmarks/reports
sudo target/release/auditd-ebpf-bench compare \
  --scenarios syscall,path,mixed \
  --modes capture-only,operational \
  --repetitions 5 \
  --warmup 30s \
  --duration 120s
```

按 [benchmark-protocol.md](contracts/benchmark-protocol.md) 检查：

- 所有用于比较的样本正确性门禁通过。
- 三类 CPU 中位数均降低至少 20%。
- 无类别吞吐回退超过 2%。
- 至少两类吞吐或 p95 改善达到 10%。
- 报告保留所有有效、无效和失败样本。

## 12. Shutdown Validation

```bash
sudo systemctl stop auditd-ebpf.service
sudo bpftool prog show | grep auditd-ebpf || true
sudo bpftool map show | grep auditd-ebpf || true
```

期望：服务在超时内排空并输出 `final=yes` 状态；无活动程序、map 或 link 遗留。

## 13. Validate argv Risk Acceptance and Log Access

exec 规则默认在事件上限内原样输出 argv。生产启用前，创建并审批风险接受记录，至少写明
审批人、责任人、审批时间、用途、获准读取主体、日志目的地、传输保护、访问策略、保留期、
事件响应要求和当前策略摘要。记录格式以
[risk-acceptance.md](contracts/risk-acceptance.md) 为准，审批不设置固定到期时间。

```bash
# 验证 journal 读取者仅限 root 和获准审计管理员组。
getent group systemd-journal
getent group auditd-ebpf-auditors

# 验证本地事件文件和离线导出权限。
sudo stat -c '%a %U %G %n' /var/log/auditd-ebpf/events.log
sudo find /var/lib/auditd-ebpf/exports -type f -printf '%m %u %g %p\n'

# 验证 rsyslog 配置语法，并确认远端 action 使用经认证的加密传输。
sudo rsyslogd -N1
sudo grep -R --line-number -E 'StreamDriver|StreamDriverMode|StreamDriverAuthMode' \
  /etc/rsyslog.conf /etc/rsyslog.d

# 生成当前有效策略摘要，交由审批人写入 root 可信风险接受 TOML。
sudo auditd-ebpf print-policy-digest \
  --rules-dir /etc/audit/rules.d \
  --config /etc/auditd-ebpf/config.toml

# 运行统一生产策略检查；任一强制项失败时返回退出码 9。
sudo auditd-ebpf check-production \
  --risk-acceptance-file /etc/auditd-ebpf/risk-acceptance.toml

# 验证关闭输出后内核仍采集 argv，但任何日志均不出现测试参数内容。
sudo cargo xtask test-kernel --case argv-output-policy

# 触发包含测试参数的 exec，确认默认原样输出并正确标记截断状态。
/usr/bin/printf '%s\n' auditd-ebpf-argv-validation
journalctl -u auditd-ebpf.service --since '-1 minute' --no-pager \
  | grep 'auditd-ebpf-argv-validation'
```

期望：事件日志不宽于 `0640`，导出文件不宽于 `0600`；远端转发验证服务端身份且使用加密
通道；journal 仅由获准主体读取；默认审计事件包含未脱敏测试参数。argv 抑制测试必须同时
证明 `argv_captured` 和 `argv_suppressed` 增加、事件包含 `argv_output=suppressed`、且 stdout、
stderr、journal 与 rsyslog 均不存在参数内容。缺少风险接受记录、摘要不匹配、权限过宽、保留
策略缺失或加密验证失败时，生产策略检查必须失败，服务不得声明生产就绪。风险接受不得用于
豁免访问控制、保留、加密或事件响应要求。
