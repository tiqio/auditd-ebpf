# Watch US1 验证记录

验证日期：2026-08-11；主机内核：`6.14.0-37-generic`；架构：x86_64。

## 功能结果

- `-w /tmp/ddtest -p rw -k ddtest` 在真实内核输出 `perm=r`、`perm=w`、`perm=rw`，operation 为实际 `openat`。
- 无特权写失败输出 `success=no`、负 errno 与 `perm=w`。
- `rwxa` 重载后验证 `fchmodat perm=a`、`execve perm=x` 和 `renameat2 perm=w`。
- 无关路径与 fd 复用负例未产生 `key="ddtest"` 误报；b32 因当前主机没有兼容测试二进制而明确 SKIP。
- eBPF RingBuf 固定为 256 MiB；计数器继续暴露 reserve/correlation/内部丢失，RingBuf 本身不支持在线扩容。

## 内核候选削减

仅当 generation 全部为不超过 16 条的绝对精确 watch 时启用。绝对路径使用 FNV-1a 完整摘要，相对路径使用后缀签名；哈希只削减候选，最终命中仍由用户态完整路径比较决定。fd-only 和 close/dup 维护事件通过内核 `WATCH_FDS` 限制到已观察候选，避免全系统维护流量占满 RingBuf。

## 已执行门禁

```text
cargo test -p auditd-ebpf --lib --test rule_engine
cargo test -p auditd-ebpf --test event_format_golden --test output_streams
cargo xtask build-ebpf --release
cargo xtask test-kernel --kernel host
tests/privileged/watch_rules.sh target/debug/auditd-ebpf target/bpfel-unknown-none/release/auditd-ebpf-ebpf
```

host kernel smoke 验证 openat flags `0x102/0x104/0x106` 和 openat2 flags 缺失路径；特权脚本验证 stdout 事件、stderr 状态/诊断分流和优雅 detach 后排空。
