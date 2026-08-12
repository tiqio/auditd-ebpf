# Watch US2 验证记录

验证日期：2026-08-12；主机内核：`6.14.0-37-generic`；架构：x86_64。

## 启动前覆盖证明

`check-rules --print-normalized` 已验证每条 watch 输出稳定字段：非空 `syscalls`、
`coverage_version=1`、`coverage_b64`、`coverage_b32`。同一输入连续执行逐字节相同，`r` 与
`rw` 规则摘要不同。

以下规则错误均返回退出码 3，并包含源文件、行号、列号和错误码：

- 缺失、空、重复或非法 `-p`：`E_PERMISSION`；
- 无法生成请求权限覆盖：`E_PERMISSION_COVERAGE`；
- 相对、通配符或包含父目录分量的 watch 路径：`E_WATCH_PATH`；
- key 缺失、重复或非法：`E_KEY`。

## 原子重载

真实内核测试从 `-p r -k reload-initial` 切换为 `-p w -k reload-active`，观察到 generation 0/1
和不同 rule version。随后提交缺少 `-p` 的候选，收到 `reload_rejected ... E_PERMISSION`；后续写
事件继续使用旧 `reload-active` key、旧 rule version 和 `perm=w`，未出现 rejected key。

## 对象兼容边界

loader staging 对双 ABI syscall bitmap、permission table、maintenance bitmap、watch path maps
和 rule version 任一缺失均返回可操作错误。syscall 解码允许旧对象 `flags=0`，但拒绝未知保留位；
permission watch 遇到旧对象缺失 flags 时由运行时产生明确 gap，而不是伪造权限。

## 已执行命令

```text
cargo test -p auditd-ebpf-rules --test parser_rejected --test permission_coverage
cargo test -p auditd-ebpf --test rule_compatibility --test reload --test event_decode
cargo xtask build-ebpf --release
tests/privileged/rule_reload.sh target/debug/auditd-ebpf target/bpfel-unknown-none/release/auditd-ebpf-ebpf
```

结果：全部 PASS；当前主机仅验证 b64 实际执行，b32 coverage 由规则契约和 host kernel staging
验证，缺少可执行 b32 workload 时不宣称运行时 b32 已覆盖。
