use auditd_ebpf_common::{
    SCHEMA_VERSION,
    event::{
        EXEC_ARGV_FLAG_ARGC_TRUNCATED, EXEC_ARGV_FLAG_ARGUMENT_TRUNCATED,
        EXEC_ARGV_FLAG_READ_ERROR, ExecAttempt, ExecResult, KernelEventHeader, MAX_EXEC_ARG_BYTES,
        MAX_EXEC_ARGS, MAX_EXEC_BYTES, RecordType,
    },
};
use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_smp_processor_id, bpf_ktime_get_ns, bpf_probe_read_user,
    bpf_probe_read_user_str_bytes,
};

use crate::maps::{
    COUNTER_EXEC_ARGV_CAPTURED, COUNTER_EXEC_ARGV_DROPPED, EVENT_COUNTERS, EVENTS,
    EXEC_ATTEMPT_SCRATCH, EXEC_ATTEMPTS, EXEC_RESULT_SCRATCH,
};

pub fn is_exec_syscall(arch: u32, syscall_nr: u32) -> bool {
    match arch {
        0xc000_003e => matches!(syscall_nr, 59 | 322),
        0x4000_0003 => matches!(syscall_nr, 11 | 358),
        _ => false,
    }
}

pub fn argv_pointer_index(arch: u32, syscall_nr: u32) -> usize {
    match (arch, syscall_nr) {
        (0xc000_003e, 322) | (0x4000_0003, 358) => 2,
        _ => 1,
    }
}

#[inline(never)]
pub fn capture_attempt(pid_tgid: u64, argv_pointer: u64, rule_version: u64) {
    let Some(attempt_pointer) = EXEC_ATTEMPT_SCRATCH.get_ptr_mut(0) else {
        increment_counter(COUNTER_EXEC_ARGV_DROPPED);
        return;
    };
    // SAFETY: PerCpuArray 槽位只由当前 CPU 使用；大对象不进入 512 字节 eBPF 栈。
    let attempt = unsafe { &mut *attempt_pointer };
    let attempt_id = unsafe { bpf_ktime_get_ns() };
    attempt.header = header(
        RecordType::ExecAttempt,
        core::mem::size_of::<ExecAttempt>() as u32,
        pid_tgid,
        rule_version,
    );
    attempt.attempt_id = attempt_id;
    attempt.argc_observed = 0;
    attempt.argc_captured = 0;
    attempt.argv_flags = 0;
    // SAFETY: 固定长度数组属于当前 CPU scratch；每次事件都清零，避免把上一次参数残留
    // 泄露到本次 RingBuf 记录，即使用户态只按 offsets 读取也保持完整 ABI 数据洁净。
    unsafe {
        core::ptr::write_bytes(attempt.argv_offsets.as_mut_ptr(), 0, MAX_EXEC_ARGS + 1);
        core::ptr::write_bytes(attempt.argv_bytes.as_mut_ptr(), 0, MAX_EXEC_BYTES);
    }

    let mut index = 0_usize;
    while index < MAX_EXEC_ARGS {
        let pointer_address = (argv_pointer as *const u64).wrapping_add(index);
        // SAFETY: argv 是用户指针数组，只通过 probe_read_user 逐项读取；读取失败会设置
        // 明确标志并停止，绝不直接解引用用户地址。
        let user_argument = match unsafe { bpf_probe_read_user(pointer_address) } {
            Ok(pointer) => pointer,
            Err(_) => {
                attempt.argv_flags |= EXEC_ARGV_FLAG_READ_ERROR;
                break;
            }
        };
        if user_argument == 0 {
            break;
        }
        attempt.argc_observed = (index + 1) as u32;
        let slot_start = index * MAX_EXEC_ARG_BYTES;
        // SAFETY: index 严格小于 32，所以 slot_start + 192 不超过 6144；slice 直接指向
        // 当前 ExecAttempt scratch 的固定槽，helper 无需再经过逐字节复制循环。
        let slot = unsafe {
            core::slice::from_raw_parts_mut(
                attempt.argv_bytes.as_mut_ptr().add(slot_start),
                MAX_EXEC_ARG_BYTES,
            )
        };
        let bytes = match unsafe { bpf_probe_read_user_str_bytes(user_argument as *const u8, slot) }
        {
            Ok(bytes) => bytes,
            Err(_) => {
                attempt.argv_flags |= EXEC_ARGV_FLAG_READ_ERROR;
                break;
            }
        };
        if bytes.len() == MAX_EXEC_ARG_BYTES - 1 {
            attempt.argv_flags |= EXEC_ARGV_FLAG_ARGUMENT_TRUNCATED;
        }
        attempt.argc_captured = (index + 1) as u16;
        attempt.argv_offsets[index + 1] = ((index + 1) * MAX_EXEC_ARG_BYTES) as u16;
        index += 1;
    }

    if index == MAX_EXEC_ARGS {
        let next_address = (argv_pointer as *const u64).wrapping_add(MAX_EXEC_ARGS);
        // SAFETY: 只探测第 33 个指针是否非空，用于显式标记 argc 截断，不读取其内容。
        if unsafe { bpf_probe_read_user(next_address) }.is_ok_and(|pointer: u64| pointer != 0) {
            attempt.argc_observed = (MAX_EXEC_ARGS + 1) as u32;
            attempt.argv_flags |= EXEC_ARGV_FLAG_ARGC_TRUNCATED;
        }
    }

    if EXEC_ATTEMPTS.insert(pid_tgid, attempt_id, 0).is_err()
        || EVENTS.output::<ExecAttempt>(&*attempt, 0).is_err()
    {
        let _ = EXEC_ATTEMPTS.remove(pid_tgid);
        increment_counter(COUNTER_EXEC_ARGV_DROPPED);
    } else {
        increment_counter(COUNTER_EXEC_ARGV_CAPTURED);
    }
}

#[inline(never)]
pub fn emit_result(pid_tgid: u64, result: i64, rule_version: u64) {
    let Some(attempt_id) = (unsafe { EXEC_ATTEMPTS.get(&pid_tgid).copied() }) else {
        return;
    };
    let Some(result_pointer) = EXEC_RESULT_SCRATCH.get_ptr_mut(0) else {
        increment_counter(COUNTER_EXEC_ARGV_DROPPED);
        let _ = EXEC_ATTEMPTS.remove(pid_tgid);
        return;
    };
    // SAFETY: 当前 CPU 独占 result scratch，提交前覆盖全部字段。
    let event = unsafe { &mut *result_pointer };
    event.header = header(
        RecordType::ExecResult,
        core::mem::size_of::<ExecResult>() as u32,
        pid_tgid,
        rule_version,
    );
    event.attempt_id = attempt_id;
    event.result = result;
    event.new_comm = bpf_get_current_comm().unwrap_or([0; 16]);
    if EVENTS.output::<ExecResult>(&*event, 0).is_err() {
        increment_counter(COUNTER_EXEC_ARGV_DROPPED);
    }
    let _ = EXEC_ATTEMPTS.remove(pid_tgid);
}

fn header(
    record_type: RecordType,
    record_len: u32,
    pid_tgid: u64,
    rule_version: u64,
) -> KernelEventHeader {
    KernelEventHeader {
        schema_version: SCHEMA_VERSION,
        record_type: record_type as u16,
        record_len,
        cpu: unsafe { bpf_get_smp_processor_id() },
        flags: 0,
        ktime_ns: unsafe { bpf_ktime_get_ns() },
        sequence: 0,
        rule_version,
        pid_tgid,
        process_start_ns: 0,
    }
}

fn increment_counter(index: u32) {
    let Some(pointer) = EVENT_COUNTERS.get_ptr_mut(index) else {
        return;
    };
    // SAFETY: PerCpuArray 的当前 CPU 槽位不与其他 CPU 共享。
    unsafe { *pointer = (*pointer).wrapping_add(1) };
}
