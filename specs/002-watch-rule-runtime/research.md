# Research: Watch 规则端到端运行

**Date**: 2026-08-11

## 1. legacy watch 的兼容定位

**Decision**: 接受 `-w/-p/-k` 作为兼容输入，但在编译阶段转换成 syscall 权限覆盖，不实现新的
内核 inode watch。

**Rationale**: Linux audit-userspace 的 `auditctl.8` 明确将 `-w` 和 watch 上的 `-p/-k` 标记为
deprecated，并建议转换为 syscall 形式；同一文档说明文件 watch 近似 `-F path`，目录 watch
近似 `-F dir`。转换能保留管理员输入习惯，同时符合本项目用户态规则引擎与 syscall bitmap
架构。

**Alternatives considered**:

- 新增 LSM/inode/fsnotify hook：拒绝。会引入不同权限语义、内核版本与 attach 风险，也违背当前
  首版不宣称 inode 等价的规格边界。
- 仅让 parser 接受 watch：拒绝。当前空 syscall bitmap 已证明会形成静默审计盲区。

## 2. `rwxa` 权限分类基准

**Decision**: 以 Linux audit 的 permission bits、open access mode 特判和 x86 syscall class 为
语义基准，维护本项目版本化 b64/b32 覆盖矩阵。

**Rationale**: Linux `include/uapi/linux/audit.h` 定义 EXEC=1、WRITE=2、READ=4、ATTR=8；
`kernel/auditsc.c::audit_match_perm` 对 open/openat/openat2 按访问模式动态分类，对 execve 类固定
归为执行，对其他调用使用 READ/WRITE/CHATTR syscall class。x86 的 class 注册来自
`arch/x86/kernel/audit_64.c` 与 asm-generic class 清单。这比根据 syscall 名称直觉猜测更接近
传统 audit 行为，也避免把每次 `read(2)`/`write(2)` 都错误输出为 watch 事件。

**Alternatives considered**:

- 将所有 `read`/`write` syscall 视为 `r/w`：拒绝。会显著放大事件量，并偏离 Linux audit watch
  以 open 访问模式和 syscall class 匹配的行为。
- 只支持 openat：拒绝。不能覆盖 exec、属性变化、truncate、rename/unlink 和 compat ABI。

## 3. 内核与用户态职责

**Decision**: 内核完成 syscall bitmap 预选、请求权限交集、open/openat/openat2 动态访问模式和
有界路径复制；用户态完成路径规范化、FD 关联、规则顺序和日志策略。

**Rationale**: 动态 open 权限只需固定整数运算，可在 RingBuf reserve 前排除与已加载权限无交集
的事件；namespace 路径和规则匹配需要复杂状态，留在用户态更符合验证器安全与宪章要求。

**Alternatives considered**:

- 内核逐规则匹配路径：拒绝。路径语义、namespace、规则数量和循环上界会增加 verifier 与栈/map
  风险。
- 内核完全不看权限：可正确但拒绝作为最终方案。仅有 `w` watch 时仍会上送全部只读 open，
  不满足热路径资源目标。

## 4. ABI 扩展方式

**Decision**: 保持 `SyscallEvent` 布局和 schema 1，使用当前保留为零的
`KernelEventHeader.flags` 表示 permission-valid 与 Linux audit 数值一致的权限掩码。

**Rationale**: 当前 flags 尚未定义含义；使用保留位无需扩大 RingBuf 记录或改变对齐。旧 eBPF
对象的 flags=0 可被明确识别为“权限未知”，权限规则生成 gap，普通 syscall 规则继续兼容。

**Alternatives considered**:

- 扩大 `SyscallEvent` 并提升 schema：可行但拒绝。会同步改变 scratch map、RingBuf 记录和所有
  golden，且本需求只需 5 个 flag bits。
- 覆盖 `args[]` 存储 openat2 flags：拒绝。会破坏“原始 syscall 参数”契约并增加调试歧义。

## 5. openat2 用户指针

**Decision**: 仅在 sys_enter、仅当当前 permission map 对 openat2 有兴趣时，有界读取
`open_how.flags` 的前 8 字节；读取失败记录权限未知，不追随其他字段。

**Rationale**: Linux audit 本身对 openat2 使用保存的 `open_how.flags`；sys_exit 时用户内存可能
变化。固定 8 字节读取满足 verifier 边界，并避免复制完整结构。

**Alternatives considered**:

- 不支持 openat2：拒绝作为最终设计。现代程序可能使用该接口，会造成已声明 `r/w` 覆盖缺口。
- 在 sys_exit 读取：拒绝。TOCTOU 风险更高，无法证明是调用入口时的访问模式。

## 6. 文件描述符状态模型

**Decision**: FD 表以稳定进程身份为键并由同一 tgid 的线程共享；fork 复制快照，exec 通过
`/proc/<tgid>/fd` 刷新，dup/close/reuse 按成功结果更新；未知或 stale 状态生成 gap。

**Rationale**: 当前每线程复制 `fd_table` 会使一个线程 open、另一个线程 fchmod/ftruncate 时关联
失败。Falco libs 的用户态事件解析同样维护线程/进程与 FD 元数据，并在 open/dup/close 等事件
后更新；本项目只借鉴状态机思想，不复制代码或其完整数据模型。

**Alternatives considered**:

- 每次 fd-only syscall 都读取 `/proc/<pid>/fd/N`：拒绝作为常态。会增加热路径 I/O 和竞态；仅作为
  cache miss 的受控刷新候选。
- 把 fd 表放 eBPF map：拒绝。路径字符串、进程共享语义、exec refresh 和容量回收更适合用户态。

## 7. RingBuf 与动态缓冲

**Decision**: 保持 16 MiB eBPF RingBuf 固定 map，继续使用 reserve-failure per-CPU 计数；动态
扩缩只作用于现有用户态 AdaptiveQueue。

**Rationale**: Aya RingBuf 对应加载时创建的 BPF ringbuf map，容量是 map 属性，运行中不能原地
扩容。尝试切换新 map 需要重新加载/重新 attach，无法保证无缝且不属于本功能范围。计数器用于
判断容量不足和 degraded，不是存储空间的替代品。

**Alternatives considered**:

- 运行中替换 RingBuf：拒绝。需要双对象/双 link 迁移并引入事件重叠或空窗。
- 阻塞业务等待缓冲：拒绝。违反审计代理不得反向阻塞被审计业务的原则。

## 8. 规则重载原子性

**Decision**: permission maps 与 syscall bitmap、rule version 一起写入 inactive generation，全部
成功后单次切换 active generation；用户态 RuleEngine 同步按事件携带版本选择。

**Rationale**: 只切换 syscall bitmap 而未切换权限 map 会形成非法中间态；现有双 generation
机制已经验证，可扩展而无需新同步协议。

**Alternatives considered**:

- 原地逐 map 更新 active generation：拒绝。并发事件可能观察到新 bitmap 与旧权限表组合。
- 重启服务应用 watch：拒绝。不满足现有 SIGHUP 原子重载规格。

## 9. 参考源码、许可证与采用边界

| Project | Pinned commit | Reviewed paths | License impact | Adopted / Rejected |
|---------|---------------|----------------|----------------|--------------------|
| Linux kernel | `d58772d8520c7ef247c4b95c9bd76d3a25da9ff5` | `kernel/auditsc.c`, `include/uapi/linux/audit.h`, `arch/x86/kernel/audit_64.c`, `include/asm-generic/audit_*.h` | GPL-2.0-only；只研究公开语义，不复制实现代码 | 采用 permission bits、open 特判和 syscall class 语义；拒绝复制内核 inode watch |
| audit-userspace | `9bfa26df5cf1edf8993b465fa114912d82b948a3` | `docs/auditctl.8` | GPL-2.0-or-later/LGPL 组件；仅引用兼容行为 | 采用 legacy 输入兼容与转换建议 |
| Aya | `15a0de1b363e51d55d0fca4245df54a61e8d5521` | `aya/src/maps/ring_buf.rs`, `aya-ebpf/src/maps` | MIT OR Apache-2.0；现有依赖，无新增许可证 | 采用现有 RingBuf/Array/PerCpuArray 模式；拒绝运行时 RingBuf 扩容假设 |
| Falco libs | `1a1d1e7ec9374cff24e9d03f55422590acb8fc92` | `userspace/libsinsp` FD/event parser areas | Apache-2.0；只借鉴状态机，不复制代码 | 采用用户态维护 FD 元数据的思路；拒绝引入 Falco 依赖和完整事件模型 |

## 10. Resolved Clarifications

- watch 首版路径语义：namespace lexical，不承诺 inode/hard-link 等价。
- `r/w` 的主要 read/write 验收通过 open access mode 触发，不输出每次数据 I/O syscall。
- openat2：纳入支持并在入口有界读取 flags。
- RingBuf：固定容量；计数驱动告警和用户队列降级，不动态扩容内核 map。
- 事件 ABI：布局不变，使用保留 flags；权限未知必须形成 gap。
