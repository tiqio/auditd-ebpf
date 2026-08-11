# Watch 进程文件表与路径关联验证

## 验证范围

本里程碑验证 watch 候选从 syscall 参数、进程级 FD 表和线程路径边界恢复 namespace 词法路径。这里只声明字符串级路径关联，不声明 inode、hard-link 或 symlink 与 auditd watch 完全等价。

## 进程级文件表

- `ProcessIdentity=(tgid,start_time)` 作为文件表稳定键，防止 PID reuse 继承旧 FD。
- 同一 tgid 的所有线程只引用同一个 `ProcessFileTable`；任意线程 open、dup 或 close 后立即对其他线程可见。
- fork 到新 tgid 时复制父进程文件表快照，此后父子更新互不影响。
- exec 成功优先使用 `/proc/<tgid>/fd` 权威替换文件表；刷新失败时保留诊断内容但整体标记 `Stale`，禁止产生可靠 watch 命中。
- 最后一个线程退出时删除进程文件表；单线程退出只删除线程上下文。
- `/proc` bootstrap 使用 `/proc/<tgid>/stat` 的 leader starttime，而不是各 task starttime，避免把同进程线程误判为 PID reuse。

## FD 状态转换

- `/proc` bootstrap、成功 open 和可靠 duplication 创建 `Reliable` 关联。
- 成功 open 复用 fd 会覆盖旧路径。
- 成功 close 删除关联。
- dup、dup2、dup3 和 `fcntl(F_DUPFD/F_DUPFD_CLOEXEC)` 复制关联到结果 fd。
- mount epoch 变化或 exec refresh 失败将表及条目标记 `Stale`。
- Missing/Stale FD 只能产生结构化路径缺口，不能回退到 collector cwd 猜测。

## 路径解析

- 解析顺序固定为 primary、secondary、fd-only。
- renameat、renameat2、linkat 的 secondary 使用 `args[2]` dirfd；symlinkat secondary 使用 `args[1]` dirfd。
- 路径缓冲截断返回 `path_argument_truncated`。
- fd-only 操作从共享文件表恢复路径。
- mount epoch、缺失线程、缺失 FD 和 stale FD 均返回独立错误。
- `..` 和平台前缀组件继续被 namespace lexical 边界拒绝。

## 验证环境与结果

- 日期：2026-08-11
- mount namespace 特权测试：通过
- 同 tgid 共享、fork 快照、exec stale、PID reuse、dup/close/fd reuse：通过
- primary/secondary 独立 dirfd、fd-only、截断和 mount stale：通过

以下命令全部通过：

```bash
cargo fmt --check
cargo clippy -p auditd-ebpf --all-targets -- -D warnings
cargo test -p auditd-ebpf --tests
tests/privileged/path_namespace.sh
git diff --check
```
