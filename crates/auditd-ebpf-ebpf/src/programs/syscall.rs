use auditd_ebpf_common::{
    SCHEMA_VERSION,
    event::{KernelEventHeader, RecordType, SyscallEvent},
};
use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_get_smp_processor_id,
        bpf_ktime_get_ns,
    },
    macros::raw_tracepoint,
    programs::RawTracePointContext,
};

use crate::maps::EVENTS;

#[raw_tracepoint]
pub fn auditd_sys_enter(context: RawTracePointContext) -> u32 {
    emit(&context, 0)
}

#[raw_tracepoint]
pub fn auditd_sys_exit(context: RawTracePointContext) -> u32 {
    emit(&context, context.arg::<i64>(1))
}

fn emit(context: &RawTracePointContext, return_value: i64) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let syscall_nr = context.arg::<i64>(1) as u32;
    let event = SyscallEvent {
        header: KernelEventHeader {
            schema_version: SCHEMA_VERSION,
            record_type: RecordType::Syscall as u16,
            record_len: core::mem::size_of::<SyscallEvent>() as u32,
            cpu: unsafe { bpf_get_smp_processor_id() },
            flags: 0,
            ktime_ns: unsafe { bpf_ktime_get_ns() },
            sequence: 0,
            rule_version: 0,
            pid_tgid,
            process_start_ns: 0,
        },
        arch: 0xc000_003e,
        syscall_nr,
        args: [0; 6],
        return_value,
        uid: uid_gid as u32,
        gid: (uid_gid >> 32) as u32,
        euid: uid_gid as u32,
        egid: (uid_gid >> 32) as u32,
        ppid: 0,
        comm: [0; 16],
        dirfd: -100,
        path_flags: 0,
    };
    let _ = EVENTS.output::<SyscallEvent>(&event, 0);
    0
}
