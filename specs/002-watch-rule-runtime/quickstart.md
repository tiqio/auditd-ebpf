# Quickstart: 验证 `-w /tmp/ddtest -p rw -k ddtest`

本指南用于功能实现后的隔离主机验收。auditd-ebpf 技术上可以与传统 auditd 共存，但两者同时
运行会重复采集并污染单代理正确性结论，因此本验收仍要求在非生产测试机单独运行 auditd-ebpf。

## 1. Preconditions

```bash
uname -m
uname -r
test -r /sys/kernel/btf/vmlinux
id -u
```

期望：

- 架构为 `x86_64`；
- 内核不低于 5.15；
- BTF 可读；
- 执行特权步骤时为 root；
- 测试机没有需要持续保留的生产 auditd 审计任务。

## 2. Build

```bash
cargo xtask build-ebpf --release
cargo build --workspace --release
cargo fmt --check
cargo clippy --workspace --exclude auditd-ebpf-ebpf --all-targets -- -D warnings
cargo test --workspace --exclude auditd-ebpf-ebpf
```

确认对象存在：

```bash
test -x target/release/auditd-ebpf
test -f target/bpfel-unknown-none/release/auditd-ebpf-ebpf
```

## 3. Create the Watch Rule

```bash
sudo install -d -m 0750 -o root -g root /etc/auditd-ebpf/rules.d
sudo tee /etc/auditd-ebpf/rules.d/10-ddtest.rules >/dev/null <<'RULES'
-w /tmp/ddtest -p rw -k ddtest
RULES
sudo chown root:root /etc/auditd-ebpf/rules.d/10-ddtest.rules
sudo chmod 0640 /etc/auditd-ebpf/rules.d/10-ddtest.rules

sudo rm -f /tmp/ddtest /tmp/ddtest-other
sudo install -m 0600 -o root -g root /dev/null /tmp/ddtest
sudo install -m 0600 -o root -g root /dev/null /tmp/ddtest-other
sudo install -d -m 0700 -o root -g root /var/lib/auditd-ebpf
```

规则语法和规范化格式以
[check-rules-output.md](contracts/check-rules-output.md) 为准。

## 4. Validate Non-Empty Coverage

```bash
sudo target/release/auditd-ebpf check-rules \
  --rules-dir /etc/auditd-ebpf/rules.d \
  --print-normalized | tee /tmp/auditd-ebpf-watch-normalized.txt
```

必须满足：

```bash
grep -F 'kind=Watch' /tmp/auditd-ebpf-watch-normalized.txt
grep -F 'path=/tmp/ddtest' /tmp/auditd-ebpf-watch-normalized.txt
grep -F 'perm=rw' /tmp/auditd-ebpf-watch-normalized.txt
grep -F 'key=ddtest' /tmp/auditd-ebpf-watch-normalized.txt
grep -E 'syscalls=[^ ]+' /tmp/auditd-ebpf-watch-normalized.txt
grep -F 'coverage_version=1' /tmp/auditd-ebpf-watch-normalized.txt
grep -E 'coverage_b64=.*r:.*\|w:' /tmp/auditd-ebpf-watch-normalized.txt
grep -E 'coverage_b32=.*r:.*\|w:' /tmp/auditd-ebpf-watch-normalized.txt
```

以下旧行为必须消失：

```text
kind=Watch ... syscalls= ... perm=rw ...
```

任一请求权限覆盖为空时，命令必须返回 3，而不是输出可运行 rule version。

## 5. Run in Foreground

默认 systemd 部署允许与传统 auditd 共存；本节为了验证 auditd-ebpf 自身的正确性，建议在隔离
测试机临时停止传统 auditd，避免重复记录影响判断：

```bash
sudo systemctl stop auditd 2>/dev/null || sudo service auditd stop 2>/dev/null || true
```

终端 A：

```bash
sudo target/release/auditd-ebpf run \
  --ebpf-object target/bpfel-unknown-none/release/auditd-ebpf-ebpf \
  --rules-dir /etc/auditd-ebpf/rules.d \
  --lifecycle-state-file /var/lib/auditd-ebpf/lifecycle.toml \
  --node-name watch-validation
```

审计事件写 stdout，状态和诊断写 stderr。不要省略 `--ebpf-object`；省略后不会 attach eBPF，
无法进行事件测试。

## 6. Trigger Read, Write and Negative Controls

终端 B 依次执行，并记录每步开始时间：

```bash
# r: openat O_RDONLY
sudo /usr/bin/cat /tmp/ddtest >/dev/null

# w: openat O_WRONLY，tee 的 stdout 丢弃以避免混入测试观察
printf 'watch-write\n' | sudo /usr/bin/tee /tmp/ddtest >/dev/null

# rw: Python 以 O_RDWR 打开同一文件
sudo python3 - <<'PY'
import os
fd = os.open('/tmp/ddtest', os.O_RDWR)
os.close(fd)
PY

# negative control: 相同操作但路径不匹配
sudo /usr/bin/cat /tmp/ddtest-other >/dev/null
printf 'other\n' | sudo /usr/bin/tee /tmp/ddtest-other >/dev/null
```

终端 A 必须在每次目标操作后 10 秒内看到：

- `/tmp/ddtest` 读取：`key="ddtest"`、`path="/tmp/ddtest"`、`perm="r"`；
- `/tmp/ddtest` 写入：`key="ddtest"`、`path="/tmp/ddtest"`、`perm="w"`；
- O_RDWR：`key="ddtest"`、`path="/tmp/ddtest"`、`perm="rw"`；
- `/tmp/ddtest-other` 不得产生 `key="ddtest"`。

事件字段以 [watch-event-format.md](contracts/watch-event-format.md) 为准。

## 7. Validate Failed Access

为非 root 测试用户准备不可写文件。若主机没有 `nobody`，使用一个无特权测试账户替代：

```bash
sudo chmod 0400 /tmp/ddtest
sudo -u nobody sh -c 'printf denied > /tmp/ddtest' || true
sudo chmod 0600 /tmp/ddtest
```

如果目标路径和权限可可靠确定，应产生：

```text
key="ddtest" path="/tmp/ddtest" perm="w" success="no" exit=<negative errno>
```

不得因为 syscall 失败而丢弃 watch 记录。

## 8. Validate Attribute and Execute Permissions

临时把规则改为：

```bash
sudo tee /etc/auditd-ebpf/rules.d/10-ddtest.rules >/dev/null <<'RULES'
-w /tmp/ddtest -p rwxa -k ddtest
RULES
sudo chown root:root /etc/auditd-ebpf/rules.d/10-ddtest.rules
sudo chmod 0640 /etc/auditd-ebpf/rules.d/10-ddtest.rules
sudo kill -HUP "$(pidof auditd-ebpf)"
```

触发属性变化：

```bash
sudo chmod 0640 /tmp/ddtest
```

期望 `perm="a"`。执行权限测试使用单独可执行文件，避免把数据文件当程序：

```bash
sudo install -m 0755 /usr/bin/true /tmp/ddtest-exec
sudo tee /etc/auditd-ebpf/rules.d/10-ddtest.rules >/dev/null <<'RULES'
-w /tmp/ddtest-exec -p x -k ddtest-exec
RULES
sudo chown root:root /etc/auditd-ebpf/rules.d/10-ddtest.rules
sudo chmod 0640 /etc/auditd-ebpf/rules.d/10-ddtest.rules
sudo kill -HUP "$(pidof auditd-ebpf)"
/tmp/ddtest-exec watch-argument
```

期望 `key="ddtest-exec"`、`path="/tmp/ddtest-exec"`、`perm="x"`。exec argv 继续按现有默认原样
输出和截断契约处理。

## 9. Validate FD Association

恢复 `/tmp/ddtest` 的 `rw` 规则并重载，然后执行：

```bash
sudo python3 - <<'PY'
import os

path = '/tmp/ddtest'
fd = os.open(path, os.O_RDWR)
duplicate = os.dup(fd)
os.ftruncate(duplicate, 0)
os.close(fd)

# fd 复用：关闭后打开无关文件，禁止继续关联到 ddtest。
os.close(duplicate)
other = os.open('/tmp/ddtest-other', os.O_RDWR)
os.ftruncate(other, 0)
os.close(other)
PY
```

必须观察到 `/tmp/ddtest` 的 open/dup 后 ftruncate 写事件；复用到 `/tmp/ddtest-other` 后不得产生
`ddtest` 命中。任何无法可靠关联的步骤必须产生 `fd_association_*` gap 和 degraded，而不是错误
复用旧路径。

## 10. Validate Atomic Reload

把 key 从 `ddtest` 改为 `ddtest-new`，保持路径和权限不变：

```bash
sudo sed -i 's/-k ddtest$/-k ddtest-new/' /etc/auditd-ebpf/rules.d/10-ddtest.rules
sudo kill -HUP "$(pidof auditd-ebpf)"
sudo /usr/bin/cat /tmp/ddtest >/dev/null
```

期望 reload success 后只出现新 key 和新 rule version。然后写入无效候选：

```bash
sudo tee /etc/auditd-ebpf/rules.d/10-ddtest.rules >/dev/null <<'RULES'
-w /tmp/ddtest -p q -k invalid
RULES
sudo chown root:root /etc/auditd-ebpf/rules.d/10-ddtest.rules
sudo chmod 0640 /etc/auditd-ebpf/rules.d/10-ddtest.rules
sudo kill -HUP "$(pidof auditd-ebpf)"
sudo /usr/bin/cat /tmp/ddtest >/dev/null
```

重载必须失败，旧 `ddtest-new` 版本继续生效；不得观察到 bitmap 与 permission map 的非法中间
组合。

## 11. Validate Counters and Health

请求立即状态：

```bash
sudo kill -USR1 "$(pidof auditd-ebpf)"
```

状态至少能区分：

- watch candidates 与 watch matches；
- `r/w/x/a` 分类命中；
- permission classification failures；
- FD association failures；
- path、RingBuf、用户队列和 stdout 丢失。

无故障正确性负载中，分类/FD/path/ring/queue/output failure 必须全为零。故障注入产生非零计数
后，服务在 10 秒内进入 degraded，累计值不得因恢复健康而清零。

## 12. Run Privileged Test Gate

实现完成后，统一脚本必须覆盖本指南的确定性场景：

```bash
sudo tests/privileged/watch_rules.sh \
  target/release/auditd-ebpf \
  target/bpfel-unknown-none/release/auditd-ebpf-ebpf

sudo cargo xtask test-kernel --kernel host
```

如果环境支持 b32 compat，还必须运行 32 位 helper；不支持时测试报告明确 SKIP 理由，不能伪装
为 PASS。

## 13. Performance Evidence

只在正确性门禁全部通过后执行，且必须在隔离测试机至少保留 5 次有效样本：

```bash
sudo target/release/auditd-ebpf-bench qualify \
  --output benchmarks/reports/watch/qualification.json

sudo target/release/auditd-ebpf-bench compare \
  --scenarios path \
  --modes capture-only,operational \
  --repetitions 5 \
  --warmup 30s \
  --duration 120s \
  --seed 42 \
  --output benchmarks/reports/watch
```

报告必须包含关闭 watch 与启用 `-w /tmp/ddtest -p rw -k ddtest` 的同版本基线、CPU、RSS、业务
吞吐、p95、RingBuf/队列丢失、正确性 ledger 和全部复现命令。存在未解释漏报、重复、误报或
丢失时，报告标记 invalid，禁止声明性能收益。

## 14. Stop and Clean Up

终端 A 使用 Ctrl-C，或：

```bash
sudo kill -TERM "$(pidof auditd-ebpf)"
```

确认 lifecycle 为 clean，随后清理：

```bash
sudo grep -F 'state = "clean"' /var/lib/auditd-ebpf/lifecycle.toml
sudo rm -f /tmp/ddtest /tmp/ddtest-other /tmp/ddtest-exec
sudo rm -rf /etc/auditd-ebpf/rules.d
```

如测试前停止了 auditd，确认没有遗留 eBPF link/map 后再按测试机原配置恢复：

```bash
sudo systemctl start auditd 2>/dev/null || true
```
