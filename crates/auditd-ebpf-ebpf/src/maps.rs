use aya_ebpf::maps::{Array, PerCpuArray};

#[aya_ebpf::macros::map]
pub static ACTIVE_GENERATION: Array<u32> = Array::with_max_entries(1, 0);

#[aya_ebpf::macros::map]
pub static EVENT_COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(8, 0);
