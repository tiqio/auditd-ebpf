use auditd_ebpf_common::{
    SCHEMA_VERSION,
    event::{
        KernelEventHeader, PROCESS_EVENT_EXEC, PROCESS_EVENT_EXIT, PROCESS_EVENT_FORK,
        ProcessEvent, RecordType,
    },
};
use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_smp_processor_id, bpf_ktime_get_ns},
    macros::tracepoint,
    programs::TracePointContext,
};

use crate::maps::{
    ACTIVE_GENERATION, COUNTER_RINGBUF_DROPPED, EVENT_COUNTERS, EVENTS, PROCESS_ABI,
    PROCESS_EVENT_SCRATCH, RULE_VERSIONS,
};

#[tracepoint]
pub fn auditd_sched_process_fork(context: TracePointContext) -> u32 {
    try_fork(&context).unwrap_or_default()
}

#[tracepoint]
pub fn auditd_sched_process_exec(context: TracePointContext) -> u32 {
    try_exec(&context).unwrap_or_default()
}

#[tracepoint]
pub fn auditd_sched_process_exit(context: TracePointContext) -> u32 {
    try_exit(&context).unwrap_or_default()
}

fn try_fork(context: &TracePointContext) -> Result<u32, i32> {
    // SAFETY: sched_process_fork 稳定 tracepoint 格式中 parent_pid/child_pid 的偏移
    // 分别为 24/44；加载器在 attach 前必须核对 tracefs format，不匹配则拒绝启用。
    let parent_pid = unsafe { context.read_at::<i32>(24)? } as u32;
    let child_pid = unsafe { context.read_at::<i32>(44)? } as u32;
    let current = bpf_get_current_pid_tgid();
    let parent_tgid = (current >> 32) as u32;
    let arch = unsafe { PROCESS_ABI.get(&parent_tgid).copied() }.unwrap_or(0);
    if arch != 0 {
        let _ = PROCESS_ABI.insert(child_pid, arch, 0);
    }
    emit(
        RecordType::Fork,
        PROCESS_EVENT_FORK,
        current,
        ((parent_pid as u64) << 32) | parent_pid as u64,
        arch,
    );
    Ok(0)
}

fn try_exec(context: &TracePointContext) -> Result<u32, i32> {
    // SAFETY: sched_process_exec 的 pid/old_pid 位于 12/16；与 fork 一样由加载器
    // 先验证 tracefs format，避免把内核版本布局差异解释为进程身份。
    let pid = unsafe { context.read_at::<i32>(12)? } as u32;
    let old_pid = unsafe { context.read_at::<i32>(16)? } as u32;
    let current = bpf_get_current_pid_tgid();
    let tgid = (current >> 32) as u32;
    let arch = unsafe { PROCESS_ABI.get(&tgid).copied() }.unwrap_or(0);
    if old_pid != pid {
        let _ = PROCESS_ABI.remove(old_pid);
    }
    if arch != 0 {
        let _ = PROCESS_ABI.insert(tgid, arch, 0);
    }
    emit(
        RecordType::ProcessExec,
        PROCESS_EVENT_EXEC,
        current,
        ((old_pid as u64) << 32) | old_pid as u64,
        arch,
    );
    Ok(0)
}

fn try_exit(context: &TracePointContext) -> Result<u32, i32> {
    // SAFETY: sched_process_exit 的 pid 位于偏移 24，attach 前核对格式。
    let pid = unsafe { context.read_at::<i32>(24)? } as u32;
    let current = bpf_get_current_pid_tgid();
    let tgid = (current >> 32) as u32;
    let arch = unsafe { PROCESS_ABI.get(&tgid).copied() }.unwrap_or(0);
    emit(RecordType::Exit, PROCESS_EVENT_EXIT, current, 0, arch);
    if pid == tgid {
        let _ = PROCESS_ABI.remove(tgid);
    }
    Ok(0)
}

fn emit(
    record_type: RecordType,
    event_kind: u32,
    pid_tgid: u64,
    parent_pid_tgid: u64,
    abi_arch: u32,
) {
    let Some(event_pointer) = PROCESS_EVENT_SCRATCH.get_ptr_mut(0) else {
        increment_counter(COUNTER_RINGBUF_DROPPED);
        return;
    };
    let generation = ACTIVE_GENERATION.get(0).copied().unwrap_or(0) & 1;
    let rule_version = RULE_VERSIONS.get(generation).copied().unwrap_or(0);
    // SAFETY: ProcessEvent scratch 为当前 CPU 独占，提交前覆盖完整结构。
    let event = unsafe { &mut *event_pointer };
    event.header = KernelEventHeader {
        schema_version: SCHEMA_VERSION,
        record_type: record_type as u16,
        record_len: core::mem::size_of::<ProcessEvent>() as u32,
        cpu: unsafe { bpf_get_smp_processor_id() },
        flags: 0,
        ktime_ns: unsafe { bpf_ktime_get_ns() },
        sequence: 0,
        rule_version,
        pid_tgid,
        process_start_ns: 0,
    };
    event.parent_pid_tgid = parent_pid_tgid;
    event.event_kind = event_kind;
    event.abi_arch = abi_arch;
    if EVENTS.output::<ProcessEvent>(&*event, 0).is_err() {
        increment_counter(COUNTER_RINGBUF_DROPPED);
    }
}

fn increment_counter(index: u32) {
    let Some(pointer) = EVENT_COUNTERS.get_ptr_mut(index) else {
        return;
    };
    // SAFETY: 当前 CPU 独占 PerCpuArray 槽位。
    unsafe { *pointer = (*pointer).wrapping_add(1) };
}
