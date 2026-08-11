use aya_ebpf::maps::{Array, HashMap, PerCpuArray, RingBuf};

#[aya_ebpf::macros::map]
pub static ACTIVE_GENERATION: Array<u32> = Array::with_max_entries(1, 0);

#[aya_ebpf::macros::map]
pub static EVENT_COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(8, 0);

#[aya_ebpf::macros::map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

#[aya_ebpf::macros::map]
pub static INFLIGHT_SYSCALLS: HashMap<u64, u32> = HashMap::with_max_entries(65_536, 0);

#[aya_ebpf::macros::map]
pub static PROCESS_ABI: HashMap<u32, u32> = HashMap::with_max_entries(65_536, 0);
