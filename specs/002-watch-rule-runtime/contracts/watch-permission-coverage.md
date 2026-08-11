# Contract: Watch Permission Coverage v1

## Purpose

固定 `-p rwxa` 在 x86_64 b64/b32 上的首版运行覆盖。实现可以增加新 syscall，但删除、重新分类
或改变路径来源必须提升 `coverage_version` 并更新正确性语料。

## Permission Values

| Symbol | Numeric bit | Output order |
|--------|-------------|--------------|
| `x` | 1 | 3 |
| `w` | 2 | 2 |
| `r` | 4 | 1 |
| `a` | 8 | 4 |

文本始终按 `rwxa` 顺序，不按数值位顺序。

## Dynamic Access Operations

| Operation | Permission | Path source | Notes |
|-----------|------------|-------------|-------|
| `open` | `r`, `w` or `rw` | primary path | 按 O_ACCMODE；额外 O_TRUNC 不改变访问 mask |
| `openat` | `r`, `w` or `rw` | dirfd + primary path | 按 O_ACCMODE |
| `openat2` | `r`, `w` or `rw` | dirfd + primary path | sys_enter 有界读取 open_how.flags；读取失败为 gap |
| `creat` | `w` | primary path | 固定写权限 |

O_RDONLY=read、O_WRONLY=write、O_RDWR=read+write。未知 access mode 不匹配权限规则并形成 gap。

## Fixed Read Coverage (`r`)

- Path: `readlink`, `readlinkat`, `getxattr`, `lgetxattr`, `listxattr`, `llistxattr`
- FD: `fgetxattr`, `flistxattr`
- Dynamic open operations listed above

原始 `read`、`pread*`、`readv*` 不属于 v1 watch 事件覆盖；通常文件读取通过产生 `r` 的 open
事件证明。该边界避免把每次数据块读取误报为独立 watch 事件。

## Fixed Write Coverage (`w`)

- Path content: `truncate`
- FD content: `ftruncate`, `fallocate`
- Directory/object mutation: `rename`, `renameat`, `renameat2`, `unlink`, `unlinkat`, `mkdir`,
  `mkdirat`, `rmdir`, `link`, `linkat`, `symlink`, `symlinkat`, `mknod`, `mknodat`
- Dynamic open operations and `creat`

原始 `write`、`pwrite*`、`writev*` 不属于 v1 watch 事件覆盖；通常文件写入通过产生 `w` 的 open
事件证明，截断和分配另有显式覆盖。

## Fixed Execute Coverage (`x`)

- `execve`
- `execveat`

执行事件继续使用现有 argv 采集与输出策略。watch 只增加路径与 permission 匹配，不改变 argv
风险接受边界。

## Fixed Attribute Coverage (`a`)

- Path: `chmod`, `fchmodat`, `fchmodat2`, `chown`, `lchown`, `fchownat`, `setxattr`, `lsetxattr`,
  `removexattr`, `lremovexattr`
- FD: `fchmod`, `fchown`, `fsetxattr`, `fremovexattr`
- Dual permission: `link`, `linkat` are both `w` and `a`

## Path Operand Rules

- Primary-only operations evaluate the normalized primary path.
- Dual-path operations evaluate primary first, then secondary；首个规则顺序命中决定输出。
- `*at` operations必须按各自 dirfd 解析，不能把 secondary path 错误地复用 primary dirfd。
- FD operations必须使用可靠 ProcessFileTable；Unknown/Stale 只能形成 gap。
- 路径截断、`..`、namespace 变化或无法读取上下文时不得猜测。

## ABI and Kernel Availability

- b64 与 b32 使用独立 syscall 编号表，同名不意味着同号。
- 最低内核不存在的较新 syscall 可以出现在覆盖矩阵中，但不会被工作负载调用；每个权限仍必须
  在最低内核具有至少一个实际可测试操作。
- syscall 编号必须小于 512；超过范围的覆盖在编译期拒绝。

## Explicit Exclusions

- io_uring 文件操作
- inode/hard-link 身份等价
- fanotify/inotify/fsnotify 事件
- 原始 read/write 数据块事件
- 其他架构和未列出的 syscall
- 根目录级、相对路径、通配符和父目录跳转 watch

## Maintenance Syscalls

以下调用不属于 `rwxa` 覆盖，但在存在 path/dir/watch 规则时必须进入内核总 bitmap，以维护用户态
关联：

- FD lifecycle：`close`, `dup`, `dup2`, `dup3` 与实现声明支持的 fcntl duplication；
- cwd lifecycle：`chdir`, `fchdir`；
- root/mount boundary：`chroot`, `pivot_root`, `mount`, `umount2`, `unshare`, `setns`,
  `mount_setattr` 及现有路径边界模块声明的等价调用。

maintenance 事件没有显式 syscall 规则且没有 permission 命中时不得输出 WatchAuditEvent；它们只
更新或失效 ProcessFileTable/ThreadPathContext。maintenance 集合必须版本化并进入规则摘要。
