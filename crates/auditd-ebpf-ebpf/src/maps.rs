use aya_ebpf::maps::{Array, HashMap, PerCpuArray, RingBuf};

pub use auditd_ebpf_common::counters::{
    COUNTER_CORRELATION_MISSED, COUNTER_EVENTS_SEEN, COUNTER_EVENTS_SUBMITTED,
    COUNTER_EXEC_ARGV_CAPTURED, COUNTER_EXEC_ARGV_DROPPED, COUNTER_INFLIGHT_DROPPED,
    COUNTER_INTERNAL_DROPPED, COUNTER_RINGBUF_DROPPED, EVENT_COUNTER_SLOTS,
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

#[aya_ebpf::macros::map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

#[aya_ebpf::macros::map]
pub static INFLIGHT_SYSCALLS: HashMap<u64, InflightSyscall> = HashMap::with_max_entries(65_536, 0);

#[aya_ebpf::macros::map]
pub static PROCESS_ABI: HashMap<u32, u32> = HashMap::with_max_entries(65_536, 0);

#[aya_ebpf::macros::map]
pub static EXEC_ATTEMPTS: HashMap<u64, u64> = HashMap::with_max_entries(65_536, 0);
