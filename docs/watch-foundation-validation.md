# Watch 规则编译基础验证

## 验证范围

本里程碑验证 watch 规则在进入 eBPF 加载阶段前，已经能够被编译为确定、可审计且同时覆盖 x86_64 b64/b32 ABI 的 syscall 权限计划。该阶段不声明 watch 已经能够在真实内核端到端输出事件；它只封板共享权限 ABI、规则覆盖矩阵和维护调用集合。

## 权限 ABI

- `x = 1`
- `w = 2`
- `r = 4`
- `a = 8`
- 有效位全集为 `0x0f`，任何未知位都由 `PermissionMask::from_bits` 拒绝。
- 文本输出固定使用 `rwxa` 顺序，避免输入顺序、集合实现或平台差异改变日志与版本摘要。

## 覆盖矩阵

- coverage version：`1`
- b64 与 b32 分别生成 512 项 permission table，syscall 编号必须小于 512。
- `open`、`openat`、`openat2` 标记为动态权限，由内核根据打开 flags 分类。
- `creat` 和写操作进入 `w`，读操作进入 `r`，执行操作进入 `x`，元数据操作进入 `a`。
- `link` 等双路径调用只在权限表中保存一次权限类别，后续路径解析阶段负责分别判断两个路径。
- watch 与带 `perm=` 的 syscall 规则都会展开为非空 syscall 覆盖；无法可靠分类时返回 `E_PERMISSION_COVERAGE`，禁止静默扩大或缩小规则语义。

## 维护调用

存在 path、dir 或 watch 条件时，编译器自动加入以下进程路径缓存维护调用：

- FD 生命周期：`close`、`dup`、`dup2`、`dup3`、`fcntl`
- 工作目录与根目录：`chdir`、`fchdir`、`chroot`、`pivot_root`
- mount namespace：`mount`、`umount2`、`unshare`、`setns`、`mount_setattr`

这些 syscall 会进入总 bitmap，但 permission table 保持为零，因此只能维护用户态关联状态，不能单独形成规则命中日志。

## 执行环境

- 日期：2026-08-11
- `rustc 1.97.1 (8bab26f4f 2026-07-14)`
- `cargo 1.97.1 (c980f4866 2026-06-30)`

## 验证结果

以下命令全部通过：

```bash
cargo fmt --check
cargo clippy -p auditd-ebpf-common -p auditd-ebpf-rules --all-targets -- -D warnings
cargo test -p auditd-ebpf-common -p auditd-ebpf-rules
git diff --check
```

测试覆盖共享 ABI 布局、权限位与文本顺序、b64/b32 覆盖、动态 open、watch/syscall 规则展开、版本摘要、维护调用隔离、解析拒绝和 syscall 表双向解析。测试结果为全部通过，无失败、忽略或文档测试失败。
