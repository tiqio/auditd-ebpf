//! eBPF 与用户态共享的 per-CPU 健康计数槽位。
//!
//! 槽位编号属于稳定 map ABI。新增计数只能使用保留槽位或提升相应 ABI，禁止在两端分别维护
//! 魔法数字，否则升级期间会把一种丢失错误解释成另一种健康状态。

pub const COUNTER_RINGBUF_DROPPED: u32 = 0;
pub const COUNTER_INFLIGHT_DROPPED: u32 = 1;
/// 保留的入口/出口关联缺口 ABI 槽位。
///
/// raw `sys_exit` 会看到所有 syscall，而 `sys_enter` 会主动过滤绝大多数非候选调用，因此
/// “出口没有 inflight entry”本身不是丢失，不能递增此槽。当前真实入口保存失败统一计入
/// `COUNTER_INFLIGHT_DROPPED`；本槽保持兼容，直到未来有可证明的关联缺口检测信号。
pub const COUNTER_CORRELATION_MISSED: u32 = 2;
pub const COUNTER_EXEC_ARGV_CAPTURED: u32 = 3;
pub const COUNTER_EXEC_ARGV_DROPPED: u32 = 4;
pub const COUNTER_EVENTS_SEEN: u32 = 5;
pub const COUNTER_EVENTS_SUBMITTED: u32 = 6;
pub const COUNTER_INTERNAL_DROPPED: u32 = 7;
/// openat2 等动态参数无法安全读取时递增。它不等同于 ring buffer 丢失，
/// 但会使 permission 规则覆盖不完整，因此必须进入内核缺口总量。
pub const COUNTER_PERMISSION_CLASSIFICATION_FAILED: u32 = 8;
pub const EVENT_COUNTER_SLOTS: u32 = 9;
