# auditd-ebpf

`auditd-ebpf` 是使用 Rust 与 Aya 构建的 Linux 审计服务，目标是在明确兼容边界、可观察丢失和
公平正确性门禁下替代传统 auditd。项目仍处于实现阶段，不能用于生产审计。

## 构建前提

- x86_64 Linux 5.15+、BTF、BPF syscall、raw tracepoint、tracepoint 与 RingBuf。
- Rust `1.97.1`；eBPF 使用 `nightly-2026-08-06`、`rust-src` 与 `bpf-linker 0.10.4`。
- 用户态只使用 Rust/Aya，不引入 C、libbpf 或 BCC 运行时。

```bash
cargo xtask build
cargo xtask build-ebpf --release
cargo test --workspace --exclude auditd-ebpf-ebpf
```

## 特权测试

特权测试会加载 eBPF、改变 mount namespace、停止 auditd 并验证 systemd/rsyslog。只能在隔离测试
主机或专用虚拟机执行，运行前必须确认没有生产审计与敏感业务。

## 安全警告

匹配 exec 规则时默认原样输出 argv，可能包含凭据、令牌、密钥和个人数据。生产部署必须限制
journal、rsyslog、本地文件和远端接收端的读取权限，并使用经认证加密传输和明确保留策略。

