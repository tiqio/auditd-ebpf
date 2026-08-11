use aya_ebpf::maps::{Array, HashMap, PerCpuArray, RingBuf};

pub use auditd_ebpf_common::counters::{
    COUNTER_CORRELATION_MISSED, COUNTER_EVENTS_SEEN, COUNTER_EVENTS_SUBMITTED,
    COUNTER_EXEC_ARGV_CAPTURED, COUNTER_EXEC_ARGV_DROPPED, COUNTER_INFLIGHT_DROPPED,
    COUNTER_INTERNAL_DROPPED, COUNTER_PERMISSION_CLASSIFICATION_FAILED, COUNTER_RINGBUF_DROPPED,
    EVENT_COUNTER_SLOTS,
};
use auditd_ebpf_common::event::{
    ExecAttempt, ExecResult, MAX_PATH_ARG_BYTES, ProcessEvent, SyscallEvent,
};

#[derive(Clone, Copy)]
#[repr(C)]
pub struct InflightSyscall {
    pub arch: u32,
    pub syscall_nr: u32,
    pub args: [u64; 6],
    pub rule_version: u64,
    pub event_flags: u32,
    pub dirfd: i32,
    pub path_flags: u32,
    pub path_len: u16,
    pub path2_len: u16,
    pub path: [u8; MAX_PATH_ARG_BYTES],
    pub path2: [u8; MAX_PATH_ARG_BYTES],
}

#[aya_ebpf::macros::map]
pub static ACTIVE_GENERATION: Array<u32> = Array::with_max_entries(1, 0);

#[aya_ebpf::macros::map]
pub static SYSCALL_BITMAPS_B64: Array<[u64; 8]> = Array::with_max_entries(2, 0);

#[aya_ebpf::macros::map]
pub static SYSCALL_BITMAPS_B32: Array<[u64; 8]> = Array::with_max_entries(2, 0);

/// 以 `generation * 512 + syscall_nr` 展平两个 generation。每项只有一个字节，
/// 避免旧内核 verifier 拒绝对 512 字节 map value 做动态指针偏移。
#[aya_ebpf::macros::map]
pub static PERMISSION_MASKS_B64: Array<u8> = Array::with_max_entries(1024, 0);

#[aya_ebpf::macros::map]
pub static PERMISSION_MASKS_B32: Array<u8> = Array::with_max_entries(1024, 0);

/// 维护位图只驱动 FD/cwd/mount 缓存更新，不能单独形成审计输出。
#[aya_ebpf::macros::map]
pub static MAINTENANCE_BITMAPS_B64: Array<[u64; 8]> = Array::with_max_entries(2, 0);

#[aya_ebpf::macros::map]
pub static MAINTENANCE_BITMAPS_B32: Array<[u64; 8]> = Array::with_max_entries(2, 0);

/// 仅当一个 generation 全部由绝对精确 watch 规则组成时启用。每代最多 16 个
/// FNV-1a 路径摘要；哈希只做候选削减，碰撞仍由用户态完整路径比较消除。
#[aya_ebpf::macros::map]
pub static WATCH_PATH_HASHES: Array<u64> = Array::with_max_entries(32, 0);

/// 与完整路径摘要一一对应的末尾 8 字节签名。相对路径必须由用户态结合 cwd/dirfd
/// 最终解析，但词法后缀不同一定不可能命中该精确 watch，可在内核提前削减候选。
#[aya_ebpf::macros::map]
pub static WATCH_BASENAME_HASHES: Array<u64> = Array::with_max_entries(32, 0);

#[aya_ebpf::macros::map]
pub static WATCH_PATH_COUNTS: Array<u32> = Array::with_max_entries(2, 0);

#[aya_ebpf::macros::map]
pub static RULE_VERSIONS: Array<u64> = Array::with_max_entries(2, 0);

#[aya_ebpf::macros::map]
pub static EVENT_COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(EVENT_COUNTER_SLOTS, 0);

#[aya_ebpf::macros::map]
pub static SYSCALL_SCRATCH: PerCpuArray<InflightSyscall> = PerCpuArray::with_max_entries(1, 0);

#[aya_ebpf::macros::map]
pub static SYSCALL_EVENT_SCRATCH: PerCpuArray<SyscallEvent> = PerCpuArray::with_max_entries(1, 0);

#[aya_ebpf::macros::map]
pub static EXEC_ATTEMPT_SCRATCH: PerCpuArray<ExecAttempt> = PerCpuArray::with_max_entries(1, 0);

#[aya_ebpf::macros::map]
pub static EXEC_RESULT_SCRATCH: PerCpuArray<ExecResult> = PerCpuArray::with_max_entries(1, 0);

#[aya_ebpf::macros::map]
pub static PROCESS_EVENT_SCRATCH: PerCpuArray<ProcessEvent> = PerCpuArray::with_max_entries(1, 0);

/// 固定 256 MiB 为高并发主机保留短时突发窗口；运行时仍通过丢失计数暴露容量不足，
/// 不尝试对已创建的 BPF RingBuf 做不存在的在线扩容。
#[aya_ebpf::macros::map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024 * 1024, 0);

#[aya_ebpf::macros::map]
pub static INFLIGHT_SYSCALLS: HashMap<u64, InflightSyscall> = HashMap::with_max_entries(65_536, 0);

/// 仅记录已经通过 watch 路径候选过滤的文件描述符。key 高 32 位为 tgid，低 32 位为 fd；
/// 该表只削减 close/dup 维护流量，最终路径和规则命中仍由用户态决定。
#[aya_ebpf::macros::map]
pub static WATCH_FDS: HashMap<u64, u8> = HashMap::with_max_entries(65_536, 0);

#[aya_ebpf::macros::map]
pub static PROCESS_ABI: HashMap<u32, u32> = HashMap::with_max_entries(65_536, 0);

#[aya_ebpf::macros::map]
pub static EXEC_ATTEMPTS: HashMap<u64, u64> = HashMap::with_max_entries(65_536, 0);
