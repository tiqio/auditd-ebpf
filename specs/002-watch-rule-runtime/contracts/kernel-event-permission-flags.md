# Contract: Kernel Syscall Permission Flags

## Layout

`KernelEventHeader.flags` 保持 `u32`，SyscallEvent 使用以下位：

| Mask | Name | Meaning |
|------|------|---------|
| `0x00000001` | `PERM_EXEC` | 本次事件满足执行权限 |
| `0x00000002` | `PERM_WRITE` | 本次事件满足写权限 |
| `0x00000004` | `PERM_READ` | 本次事件满足读权限 |
| `0x00000008` | `PERM_ATTR` | 本次事件满足属性变化权限 |
| `0x00000100` | `PERMISSION_VALID` | 低四位由当前 eBPF 对象可靠分类 |
| all other bits | Reserved | 必须为零；用户态看到非零未知位时生成 ABI 诊断 |

权限数值与 Linux audit permission bits 一致；valid 位位于 bit 8，不能与权限位重叠。

## Producer Rules

- 显式 syscall 规则即使没有 permission 兴趣，也可以提交 `PERMISSION_VALID` 未设置的事件。
- permission rule 候选只有在实际 mask 与当前 generation 的请求 mask 有交集时提交。
- 静态分类 syscall 设置 `PERMISSION_VALID | actual_mask`。
- open/openat/openat2 设置动态 access mask；openat2 读取失败时：
  - 若同时存在显式 syscall 规则，提交 flags=0，由用户态决定普通 syscall 规则；
  - 若只有 permission 规则，不得伪造 mask，增加分类失败计数并提交 InternalGap 或等价 gap 信号。
- event 的 rule_version、syscall bitmap 和 permission map 必须来自同一 active generation。

## Consumer Rules

- `(flags & PERMISSION_VALID) != 0` 时，低四位必须非零；否则视为 malformed event。
- 普通无 `perm` syscall 规则允许 flags=0。
- WatchRule 或带 `perm=` syscall 规则遇到 flags=0 时不得匹配，必须产生
  `permission_flags_missing` gap。
- 未知 flags 位不得静默忽略；增加解析/ABI 诊断并进入 degraded。

## Compatibility

- `SCHEMA_VERSION` 保持 1，记录长度与对齐不变。
- 旧 eBPF 对象持续产生 flags=0；因此新用户态可以处理普通 syscall 事件，但不能声称权限规则
  已完整工作。
- 更新后的加载/生产检查应验证对象具备 permission map；缺少 map 时，包含 permission 规则的
  启动必须失败，不能依赖运行时逐事件 gap 作为正常配置。
