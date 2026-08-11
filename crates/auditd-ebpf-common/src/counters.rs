//! eBPF 与用户态共享的 per-CPU 健康计数槽位。
//!
//! 槽位编号属于稳定 map ABI。新增计数只能使用保留槽位或提升相应 ABI，禁止在两端分别维护
//! 魔法数字，否则升级期间会把一种丢失错误解释成另一种健康状态。

pub const COUNTER_RINGBUF_DROPPED: u32 = 0;
pub const COUNTER_INFLIGHT_DROPPED: u32 = 1;
pub const COUNTER_CORRELATION_MISSED: u32 = 2;
pub const COUNTER_EXEC_ARGV_CAPTURED: u32 = 3;
pub const COUNTER_EXEC_ARGV_DROPPED: u32 = 4;
pub const COUNTER_EVENTS_SEEN: u32 = 5;
pub const COUNTER_EVENTS_SUBMITTED: u32 = 6;
pub const COUNTER_INTERNAL_DROPPED: u32 = 7;
pub const EVENT_COUNTER_SLOTS: u32 = 8;
