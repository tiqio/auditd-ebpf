use auditd_ebpf_common::{
    SCHEMA_VERSION,
    event::{
        KernelEventHeader, MAX_PATH_ARG_BYTES, PATH_FLAG_MOUNT_BOUNDARY_CHANGED,
        PATH_FLAG_PRIMARY_PRESENT, PATH_FLAG_SECONDARY_PRESENT, PATH_FLAG_TRUNCATED, RecordType,
        SyscallEvent,
    },
};
use aya_ebpf::{
    bindings::pt_regs,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_get_smp_processor_id, bpf_ktime_get_ns, bpf_probe_read_kernel,
        bpf_probe_read_user_str_bytes,
    },
    macros::raw_tracepoint,
    programs::RawTracePointContext,
};

use crate::maps::{
    ACTIVE_GENERATION, COUNTER_CORRELATION_MISSED, COUNTER_EVENTS_SEEN, COUNTER_EVENTS_SUBMITTED,
    COUNTER_INFLIGHT_DROPPED, COUNTER_INTERNAL_DROPPED, COUNTER_RINGBUF_DROPPED, EVENT_COUNTERS,
    EVENTS, INFLIGHT_SYSCALLS, InflightSyscall, PROCESS_ABI, RULE_VERSIONS, SYSCALL_BITMAPS_B32,
    SYSCALL_BITMAPS_B64, SYSCALL_EVENT_SCRATCH, SYSCALL_SCRATCH,
};
use crate::programs::exec::{argv_pointer_index, capture_attempt, emit_result, is_exec_syscall};

const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const AUDIT_ARCH_I386: u32 = 0x4000_0003;

#[raw_tracepoint]
pub fn auditd_sys_enter(context: RawTracePointContext) -> u32 {
    try_sys_enter(&context).unwrap_or_default()
}

#[raw_tracepoint]
pub fn auditd_sys_exit(context: RawTracePointContext) -> u32 {
    try_sys_exit(&context).unwrap_or_default()
}

#[inline(never)]
fn try_sys_enter(context: &RawTracePointContext) -> Result<u32, i32> {
    let syscall_nr = context.arg::<i64>(1) as u32;
    if syscall_nr >= 512 {
        return Ok(0);
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let generation = ACTIVE_GENERATION.get(0).copied().unwrap_or(0) & 1;
    let hinted_arch = unsafe { PROCESS_ABI.get(&tgid).copied() };
    let arch = select_arch(generation, syscall_nr, hinted_arch);
    if arch == 0 {
        return Ok(0);
    }

    let regs_ptr = context.arg::<*const pt_regs>(0);
    // SAFETY: raw sys_enter 的 arg(0) 由内核定义为当前 syscall 的 pt_regs 指针；
    // helper 负责探测内核地址，失败时直接放弃本次事件，不解引用任意地址。
    let regs = unsafe { bpf_probe_read_kernel(regs_ptr)? };
    let args = syscall_args(&regs, arch);
    let rule_version = RULE_VERSIONS.get(generation).copied().unwrap_or(0);
    if is_exec_syscall(arch, syscall_nr) {
        capture_attempt(
            pid_tgid,
            args[argv_pointer_index(arch, syscall_nr)],
            rule_version,
        );
    }
    let Some(scratch_pointer) = SYSCALL_SCRATCH.get_ptr_mut(0) else {
        increment_counter(COUNTER_INFLIGHT_DROPPED);
        return Ok(0);
    };
    // SAFETY: PerCpuArray 槽位仅由当前 CPU 的本次程序调用修改；先完整重置可变长度
    // 路径区，再把引用交给 map update helper，避免在 512 字节 eBPF 栈上构造大对象。
    let inflight = unsafe { &mut *scratch_pointer };
    inflight.arch = arch;
    inflight.syscall_nr = syscall_nr;
    inflight.args = args;
    inflight.rule_version = rule_version;
    inflight.dirfd = path_dirfd(arch, syscall_nr, &args);
    inflight.path_flags = 0;
    inflight.path_len = 0;
    inflight.path2_len = 0;
    unsafe {
        core::ptr::write_bytes(inflight.path.as_mut_ptr(), 0, MAX_PATH_ARG_BYTES);
        core::ptr::write_bytes(inflight.path2.as_mut_ptr(), 0, MAX_PATH_ARG_BYTES);
    }
    capture_paths(inflight);
    if INFLIGHT_SYSCALLS.insert(pid_tgid, &*inflight, 0).is_err() {
        increment_counter(COUNTER_INFLIGHT_DROPPED);
    }
    Ok(0)
}

#[inline(never)]
fn try_sys_exit(context: &RawTracePointContext) -> Result<u32, i32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let Some(inflight) = (unsafe { INFLIGHT_SYSCALLS.get(&pid_tgid) }) else {
        increment_counter(COUNTER_CORRELATION_MISSED);
        return Ok(0);
    };
    let return_value = context.arg::<i64>(1);
    if is_exec_syscall(inflight.arch, inflight.syscall_nr) {
        emit_result(pid_tgid, return_value, inflight.rule_version);
    }
    let uid_gid = bpf_get_current_uid_gid();
    let mut path_flags = inflight.path_flags;
    if return_value >= 0 && changes_mount_boundary(inflight.arch, inflight.syscall_nr) {
        path_flags |= PATH_FLAG_MOUNT_BOUNDARY_CHANGED;
    }
    let Some(event_pointer) = SYSCALL_EVENT_SCRATCH.get_ptr_mut(0) else {
        increment_counter(COUNTER_INTERNAL_DROPPED);
        let _ = INFLIGHT_SYSCALLS.remove(pid_tgid);
        return Ok(0);
    };
    // SAFETY: 与入口 scratch 相同，当前 CPU 独占此槽；所有字段在提交前均被覆盖。
    let event = unsafe { &mut *event_pointer };
    event.header = header(RecordType::Syscall, pid_tgid, inflight.rule_version);
    event.arch = inflight.arch;
    event.syscall_nr = inflight.syscall_nr;
    event.args = inflight.args;
    event.return_value = return_value;
    event.uid = uid_gid as u32;
    event.gid = (uid_gid >> 32) as u32;
    event.euid = uid_gid as u32;
    event.egid = (uid_gid >> 32) as u32;
    event.ppid = 0;
    event.comm = bpf_get_current_comm().unwrap_or([0; 16]);
    event.dirfd = inflight.dirfd;
    event.path_flags = path_flags;
    event.path_len = inflight.path_len;
    event.path2_len = inflight.path2_len;
    event.path = inflight.path;
    event.path2 = inflight.path2;
    increment_counter(COUNTER_EVENTS_SEEN);
    if EVENTS.output::<SyscallEvent>(&*event, 0).is_err() {
        increment_counter(COUNTER_RINGBUF_DROPPED);
    } else {
        increment_counter(COUNTER_EVENTS_SUBMITTED);
    }
    let _ = INFLIGHT_SYSCALLS.remove(pid_tgid);
    Ok(0)
}

fn header(record_type: RecordType, pid_tgid: u64, rule_version: u64) -> KernelEventHeader {
    KernelEventHeader {
        schema_version: SCHEMA_VERSION,
        record_type: record_type as u16,
        record_len: core::mem::size_of::<SyscallEvent>() as u32,
        cpu: unsafe { bpf_get_smp_processor_id() },
        flags: 0,
        ktime_ns: unsafe { bpf_ktime_get_ns() },
        sequence: 0,
        rule_version,
        pid_tgid,
        process_start_ns: 0,
    }
}

fn select_arch(generation: u32, syscall_nr: u32, hinted_arch: Option<u32>) -> u32 {
    match hinted_arch {
        Some(AUDIT_ARCH_X86_64)
            if bitmap_contains(&SYSCALL_BITMAPS_B64, generation, syscall_nr) =>
        {
            AUDIT_ARCH_X86_64
        }
        Some(AUDIT_ARCH_I386) if bitmap_contains(&SYSCALL_BITMAPS_B32, generation, syscall_nr) => {
            AUDIT_ARCH_I386
        }
        Some(_) => 0,
        None if bitmap_contains(&SYSCALL_BITMAPS_B64, generation, syscall_nr) => AUDIT_ARCH_X86_64,
        None if bitmap_contains(&SYSCALL_BITMAPS_B32, generation, syscall_nr) => AUDIT_ARCH_I386,
        None => 0,
    }
}

fn bitmap_contains(
    map: &aya_ebpf::maps::Array<[u64; 8]>,
    generation: u32,
    syscall_nr: u32,
) -> bool {
    let Some(bitmap) = map.get(generation) else {
        return false;
    };
    let word = (syscall_nr / 64) as usize;
    let bit = syscall_nr % 64;
    // SAFETY: 调用方在进入位图检查前保证 syscall_nr < 512，因此 word 必在 0..8；
    // 使用 unchecked 是为了禁止 Rust panic 冷路径进入 eBPF 对象，失败会导致程序无法加载。
    let word_value = unsafe { *bitmap.get_unchecked(word) };
    word_value & (1_u64 << bit) != 0
}

fn syscall_args(regs: &pt_regs, arch: u32) -> [u64; 6] {
    if arch == AUDIT_ARCH_I386 {
        [regs.rbx, regs.rcx, regs.rdx, regs.rsi, regs.rdi, regs.rbp]
    } else {
        [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9]
    }
}

#[inline(never)]
fn capture_paths(inflight: &mut InflightSyscall) {
    let (primary, secondary) = path_argument_indexes(inflight.arch, inflight.syscall_nr);
    if primary < 6 {
        inflight.path_len = read_path(inflight.args[primary], &mut inflight.path);
        if inflight.path_len > 0 {
            inflight.path_flags |= PATH_FLAG_PRIMARY_PRESENT;
            if inflight.path_len as usize == MAX_PATH_ARG_BYTES {
                inflight.path_flags |= PATH_FLAG_TRUNCATED;
            }
        }
    }
    if secondary < 6 {
        inflight.path2_len = read_path(inflight.args[secondary], &mut inflight.path2);
        if inflight.path2_len > 0 {
            inflight.path_flags |= PATH_FLAG_SECONDARY_PRESENT;
            if inflight.path2_len as usize == MAX_PATH_ARG_BYTES {
                inflight.path_flags |= PATH_FLAG_TRUNCATED;
            }
        }
    }
}

#[inline(never)]
fn read_path(pointer: u64, destination: &mut [u8; MAX_PATH_ARG_BYTES]) -> u16 {
    if pointer == 0 {
        return 0;
    }
    // SAFETY: syscall 参数是用户指针，只通过 probe_read_user helper 访问；目标缓冲固定 160
    // 字节，helper 失败时返回 0，绝不在 eBPF 中追随或解释该指针。
    unsafe { bpf_probe_read_user_str_bytes(pointer as *const u8, destination) }
        .map(|bytes| bytes.len() as u16)
        .unwrap_or(0)
}

#[inline(never)]
fn path_argument_indexes(arch: u32, syscall_nr: u32) -> (usize, usize) {
    if arch == AUDIT_ARCH_I386 {
        match syscall_nr {
            5 | 10 | 12 | 40 | 61 => (0, 6),
            38 | 39 | 52 => (0, 1),
            295 | 301 | 358 => (1, 6),
            302 | 353 => (1, 3),
            _ => (6, 6),
        }
    } else {
        match syscall_nr {
            2 | 59 | 80 | 87 | 161 | 166 => (0, 6),
            82 | 83 | 155 | 165 => (0, 1),
            257 | 263 | 322 | 439 | 442 => (1, 6),
            264 | 316 | 429 => (1, 3),
            _ => (6, 6),
        }
    }
}

#[inline(never)]
fn path_dirfd(arch: u32, syscall_nr: u32, args: &[u64; 6]) -> i32 {
    let has_dirfd = if arch == AUDIT_ARCH_I386 {
        matches!(syscall_nr, 295 | 301 | 302 | 353 | 358)
    } else {
        matches!(syscall_nr, 257 | 263 | 264 | 316 | 322 | 429 | 439 | 442)
    };
    if has_dirfd { args[0] as i32 } else { -100 }
}

#[inline(never)]
fn changes_mount_boundary(arch: u32, syscall_nr: u32) -> bool {
    if arch == AUDIT_ARCH_I386 {
        matches!(syscall_nr, 21 | 52 | 61 | 120 | 346)
    } else {
        matches!(syscall_nr, 155 | 161 | 165 | 166 | 272 | 308 | 429 | 442)
    }
}

fn increment_counter(index: u32) {
    let Some(pointer) = EVENT_COUNTERS.get_ptr_mut(index) else {
        return;
    };
    // SAFETY: PerCpuArray 返回当前 CPU 独占槽位；每次程序调用只在本 CPU 上执行，
    // 因此这里的读改写不会与其他 CPU 共享同一地址。
    unsafe { *pointer = (*pointer).wrapping_add(1) };
}
