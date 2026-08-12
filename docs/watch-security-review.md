# Watch 安全审查

日期：2026-08-12。

- **openat2 用户指针**：内核程序仅固定读取 `open_how.flags` 所需 8 字节；失败增加 permission classification failure，不猜测访问模式。
- **验证器边界**：事件 ABI 固定宽度且 `SyscallEvent <= 512`；大 argv 暂存于 per-CPU map，避免 eBPF 512 字节栈上限；动态索引均受常量上界约束。
- **syscall 范围**：规则编译和 map 索引验证 syscall `<512`；双 generation 展平为 `generation * 512 + nr`，不对大 map value 做动态指针偏移。
- **FD 缓存**：进程级表处理 dup/fork/close/复用；missing/stale 只生成 gap，禁止沿用过期路径。`WATCH_FDS` 只是候选削减，用户态路径比较仍为权威。
- **flags 兼容**：旧对象 `flags=0` 仅允许无 permission 条件的兼容事件；未知位、无 valid 的权限位和空有效权限均拒绝。
- **namespace 语义**：只承诺事件进程 root/cwd/dirfd/mount namespace 内的词法路径，不声明 inode、硬链接或符号链接等价。
- **日志边界**：watch 不新增 argv；exec 规则默认完整 argv 属于已接受风险。审计 stdout 与诊断 stderr 分离，诊断 API 不接收 argv；生产仍必须执行最小读取权限、认证加密、受控保留和书面风险接受。

审查结论：当前实现符合既定安全边界；隔离性能证据和 b32/多内核实机验证仍是环境性发布限制，不是可静默忽略项。
