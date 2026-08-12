# Watch US3 验证

日期：2026-08-12。

## 可观测性

新增稳定 `WatchGapReason`、watch candidates/matches、`r/w/x/a` 命中、permission/FD failure 计数。未知权限或路径候选只输出 gap/diag，不输出空 `perm`/`path` 假事件。持续缺口 10 秒升级 unhealthy；状态与诊断不接收 argv。

## 故障注入

运行 `tests/failure-injection/watch_rules.sh`。permission flags、FD stale、路径截断、用户队列满、stdout EPIPE 与 RingBuf 计数 ABI 均可重复验证。共享宿主无法确定性压满固定 256 MiB RingBuf，因此真实压满明确 SKIP，不伪装为 PASS。

## 门禁结果

- `cargo fmt --check`：PASS。
- `cargo clippy --workspace --all-targets --exclude auditd-ebpf-ebpf -- -D warnings`：PASS。
- `cargo test --workspace --exclude auditd-ebpf-ebpf`：PASS。
- `tests/failure-injection/watch_rules.sh`：PASS；真实 256 MiB RingBuf 压满按不可控宿主条件 SKIP。
- `cargo xtask build-ebpf --release`：PASS。
- `cargo xtask test-kernel --kernel host`：PASS，内核 `6.14.0-37-generic`；watch、reload、日志 quickstart 均通过。
