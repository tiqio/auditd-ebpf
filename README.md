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

## 架构文档

- [eBPF 与 Aya 实现架构](docs/ebpf-aya-architecture.md)：内核采集链路、maps、RingBuf、规则
  generation、FD 生命周期，以及 Aya 与 C/libbpf 的详细对比和可视化图。
- [运维指南](docs/operations.md)：systemd、journal、rsyslog、健康状态与故障处理。
- [配置说明](docs/configuration.md)：配置层级、队列和 argv 输出策略。

## Watch 规则

支持 legacy 精确路径规则，例如：

```text
-w /tmp/ddtest -p rw -k ddtest
```

启动前使用以下命令证明规则已展开为非空 b64/b32 覆盖；任一规则非法时整体返回退出码 3：

```bash
target/release/auditd-ebpf check-rules \
  --rules-file /etc/audit/rules.d/auditd-ebpf.rules \
  --print-normalized
```

运行时向进程发送 `SIGHUP` 会先完整 staging 下一 generation 的 syscall bitmap、permission
table、维护集合、路径候选、rule version 和用户态 RuleEngine，最后才原子切换。无效候选保留
旧 generation，不产生部分新规则事件。

## 特权测试

特权测试会加载 eBPF、改变 mount namespace，并在部分单代理验收中临时停止 auditd，同时验证
systemd/rsyslog。只能在隔离测试主机或专用虚拟机执行，运行前必须确认没有生产审计与敏感业务。

## 安全警告

匹配 exec 规则时默认原样输出 argv，可能包含凭据、令牌、密钥和个人数据。生产部署必须限制
journal、rsyslog、本地文件和远端接收端的读取权限，并使用经认证加密传输和明确保留策略。
