# Watch 内核权限投递验证

## 验证范围

本里程碑验证 schema 1 在不改变 `KernelEventHeader` 和 `SyscallEvent` 布局的前提下，通过 `flags` 投递权限候选；同时验证双 generation b64/b32 权限表、维护位图、open 动态分类、openat2 有界读取失败计数和原子切换。

## ABI 与 map

- permission bits：`x=1`、`w=2`、`r=4`、`a=8`
- `PERMISSION_VALID=0x100`
- syscall 已知 flags 掩码：`0x10f`
- schema 保持 `1`，`KernelEventHeader=56` 字节，`SyscallEvent=488` 字节。
- 旧对象 `flags=0` 被解码为“权限未知”，普通 syscall 规则仍兼容。
- 未知保留位、未设置 valid 却携带权限、valid 加空权限均被拒绝。
- b64/b32 各使用 1024 项 `Array<u8>`，索引为 `generation * 512 + syscall_nr`。该展平布局避免旧 verifier 对大 map value 动态指针偏移的限制。
- maintenance bitmap 与 permission table 同时在 inactive generation 完整 staging，最后只写一次 `ACTIVE_GENERATION`。

## eBPF 分类边界

- `open/openat` 根据 `O_ACCMODE` 分类。
- `O_RDONLY -> r`、`O_WRONLY -> w`、`O_RDWR -> rw`。
- `creat` 与静态覆盖 syscall 使用编译期权限类别。
- `openat2` 只通过 `bpf_probe_read_user` 读取 `open_how.flags` 的前 8 字节，不信任用户 size，不读取后续字段。
- openat2 用户指针读取失败时不伪造权限，事件保持 `flags=0`，并递增 `permission_classification_failed`。
- syscall 编号在入口拒绝 `>=512`；map helper 内再次约束或展平索引，以适配跨 BPF 子程序时 verifier 丢失范围证明的行为。

## 真实内核结果

- 日期：2026-08-11
- host kernel：`6.14.0-37-generic`
- 架构：x86_64 b64
- `openat(O_RDONLY)`：`flags=0x104`，即 `PERMISSION_VALID|r`
- `openat(O_WRONLY)`：`flags=0x102`，即 `PERMISSION_VALID|w`
- `openat(O_RDWR)`：`flags=0x106`，即 `PERMISSION_VALID|rw`
- 故意传入非法 `open_how` 用户指针：`syscall=437 flags=0x0`，分类失败计数至少增加 1。
- reload 并发期间只观察到旧/新完整 `rule_version`，没有中间 generation。
- maintenance syscall 不设置 permission valid，因此不能单独形成 permission 规则命中。

## 执行命令

以下命令全部通过：

```bash
cargo test -p auditd-ebpf-common -p auditd-ebpf --tests
cargo clippy -p auditd-ebpf-common -p auditd-ebpf-rules -p auditd-ebpf --all-targets -- -D warnings
cargo clippy -p xtask --all-targets -- -D warnings
cargo xtask build-ebpf --release
cargo xtask test-kernel --kernel host
git diff --check
```

host 内核命令还完成了 exec 参数边界、进程生命周期、路径采集、日志管道和运行时 reload 既有门禁。用户态 watch 路径/FD 关联和最终 `perm="..."` 输出仍属于 T032–T045，不在本里程碑中宣称完成。
