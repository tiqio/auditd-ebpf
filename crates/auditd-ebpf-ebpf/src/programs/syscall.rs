use auditd_ebpf_common::{
    SCHEMA_VERSION,
    event::{
        KernelEventHeader, MAX_PATH_ARG_BYTES, PATH_FLAG_MOUNT_BOUNDARY_CHANGED,
        PATH_FLAG_PRIMARY_PRESENT, PATH_FLAG_SECONDARY_PRESENT, PATH_FLAG_TRUNCATED,
        PERMISSION_VALID, RecordType, SyscallEvent,
    },
};
use aya_ebpf::{
    bindings::pt_regs,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_get_smp_processor_id, bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_user,
        bpf_probe_read_user_str_bytes,
    },
    macros::raw_tracepoint,
    programs::RawTracePointContext,
};

use crate::maps::{
    ACTIVE_GENERATION, COUNTER_CORRELATION_MISSED, COUNTER_EVENTS_SEEN, COUNTER_EVENTS_SUBMITTED,
    COUNTER_INFLIGHT_DROPPED, COUNTER_INTERNAL_DROPPED, COUNTER_PERMISSION_CLASSIFICATION_FAILED,
    COUNTER_RINGBUF_DROPPED, EVENT_COUNTERS, EVENTS, INFLIGHT_SYSCALLS, InflightSyscall,
    MAINTENANCE_BITMAPS_B32, MAINTENANCE_BITMAPS_B64, PERMISSION_MASKS_B32, PERMISSION_MASKS_B64,
    PROCESS_ABI, RULE_VERSIONS, SYSCALL_BITMAPS_B32, SYSCALL_BITMAPS_B64, SYSCALL_EVENT_SCRATCH,
    SYSCALL_SCRATCH, WATCH_BASENAME_HASHES, WATCH_FDS, WATCH_PATH_COUNTS, WATCH_PATH_HASHES,
};
use crate::programs::exec::{argv_pointer_index, capture_attempt, emit_result, is_exec_syscall};

const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const AUDIT_ARCH_I386: u32 = 0x4000_0003;
const PERM_WRITE: u8 = 1 << 1;
const PERM_READ: u8 = 1 << 2;

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
    let requested_permissions = permission_mask(generation, arch, syscall_nr);
    let maintenance_only = maintenance_contains(generation, arch, syscall_nr);
    if requested_permissions == 0
        && maintenance_only
        && !maintenance_fd_candidate(arch, syscall_nr, pid_tgid, &args)
    {
        return Ok(0);
    }
    let event_flags = if requested_permissions == 0 {
        0
    } else {
        match classify_permission(arch, syscall_nr, args[1], args[2], requested_permissions) {
            Some(actual) if actual & requested_permissions != 0 => {
                PERMISSION_VALID | u32::from(actual)
            }
            Some(_) if !maintenance_only => return Ok(0),
            Some(_) => 0,
            None => {
                // 动态参数读取失败时绝不猜测权限。保留 flags=0 事件可让同时存在的普通
                // syscall 规则继续工作，用户态 permission 规则必须把它记录为明确缺口。
                increment_counter(COUNTER_PERMISSION_CLASSIFICATION_FAILED);
                0
            }
        }
    };
    let rule_version = RULE_VERSIONS.get(generation).copied().unwrap_or(0);
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
    inflight.event_flags = event_flags;
    inflight.dirfd = path_dirfd(arch, syscall_nr, &args);
    inflight.path_flags = 0;
    inflight.path_len = 0;
    inflight.path2_len = 0;
    unsafe {
        core::ptr::write_bytes(inflight.path.as_mut_ptr(), 0, MAX_PATH_ARG_BYTES);
        core::ptr::write_bytes(inflight.path2.as_mut_ptr(), 0, MAX_PATH_ARG_BYTES);
    }
    capture_paths(inflight);
    if requested_permissions != 0 {
        let (primary_index, secondary_index) = path_argument_indexes(arch, syscall_nr);
        let fd_only = primary_index >= 6 && secondary_index >= 6;
        if fd_only {
            let key = watch_fd_key(pid_tgid, args[0] as i32);
            if unsafe { WATCH_FDS.get(&key).is_none() } {
                return Ok(0);
            }
        } else if !watch_path_candidate(generation, inflight) {
            return Ok(0);
        }
    }
    // exec argv 体积远大于普通 syscall 事件，只能在路径候选过滤通过后采集；否则一条
    // `-p x` watch 会为全系统 exec 复制参数并淹没共享 RingBuf。
    if is_exec_syscall(arch, syscall_nr) {
        capture_attempt(
            pid_tgid,
            args[argv_pointer_index(arch, syscall_nr)],
            rule_version,
        );
    }
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
    event.header = header(
        RecordType::Syscall,
        pid_tgid,
        inflight.rule_version,
        inflight.event_flags,
    );
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
    update_watch_fds(pid_tgid, inflight, return_value);
    let _ = INFLIGHT_SYSCALLS.remove(pid_tgid);
    Ok(0)
}

#[inline(never)]
fn maintenance_fd_candidate(arch: u32, syscall_nr: u32, pid_tgid: u64, args: &[u64; 6]) -> bool {
    if !is_fd_maintenance(arch, syscall_nr) {
        return true;
    }
    let source = watch_fd_key(pid_tgid, args[0] as i32);
    if unsafe { WATCH_FDS.get(&source).is_some() } {
        return true;
    }
    if is_dup_target_syscall(arch, syscall_nr) {
        let target = watch_fd_key(pid_tgid, args[1] as i32);
        return unsafe { WATCH_FDS.get(&target).is_some() };
    }
    false
}

#[inline(never)]
fn update_watch_fds(pid_tgid: u64, inflight: &InflightSyscall, return_value: i64) {
    if return_value < 0 {
        return;
    }
    let arch = inflight.arch;
    let syscall_nr = inflight.syscall_nr;
    if is_open(arch, syscall_nr)
        || is_openat(arch, syscall_nr)
        || is_openat2(arch, syscall_nr)
        || is_creat(arch, syscall_nr)
    {
        if inflight.path_len == 0 && inflight.path2_len == 0 {
            return;
        }
        let key = watch_fd_key(pid_tgid, return_value as i32);
        let _ = WATCH_FDS.insert(&key, &1, 0);
        return;
    }
    if is_close(arch, syscall_nr) {
        let key = watch_fd_key(pid_tgid, inflight.args[0] as i32);
        let _ = WATCH_FDS.remove(&key);
        return;
    }
    if is_dup_syscall(arch, syscall_nr) || is_fcntl_dup(arch, syscall_nr, inflight.args[1]) {
        let source = watch_fd_key(pid_tgid, inflight.args[0] as i32);
        let target = watch_fd_key(pid_tgid, return_value as i32);
        if unsafe { WATCH_FDS.get(&source).is_some() } {
            let _ = WATCH_FDS.insert(&target, &1, 0);
        } else {
            let _ = WATCH_FDS.remove(&target);
        }
    }
}

#[inline(always)]
fn watch_fd_key(pid_tgid: u64, fd: i32) -> u64 {
    (pid_tgid & 0xffff_ffff_0000_0000) | u64::from(fd as u32)
}

#[inline(always)]
fn is_fd_maintenance(arch: u32, syscall_nr: u32) -> bool {
    is_close(arch, syscall_nr)
        || is_dup_syscall(arch, syscall_nr)
        || is_dup_target_syscall(arch, syscall_nr)
        || is_fcntl(arch, syscall_nr)
}

#[inline(always)]
fn is_close(arch: u32, syscall_nr: u32) -> bool {
    (arch == AUDIT_ARCH_X86_64 && syscall_nr == 3) || (arch == AUDIT_ARCH_I386 && syscall_nr == 6)
}

#[inline(always)]
fn is_dup_syscall(arch: u32, syscall_nr: u32) -> bool {
    (arch == AUDIT_ARCH_X86_64 && syscall_nr == 32) || (arch == AUDIT_ARCH_I386 && syscall_nr == 41)
}

#[inline(always)]
fn is_dup_target_syscall(arch: u32, syscall_nr: u32) -> bool {
    (arch == AUDIT_ARCH_X86_64 && matches!(syscall_nr, 33 | 292))
        || (arch == AUDIT_ARCH_I386 && matches!(syscall_nr, 63 | 330))
}

#[inline(always)]
fn is_fcntl(arch: u32, syscall_nr: u32) -> bool {
    (arch == AUDIT_ARCH_X86_64 && syscall_nr == 72)
        || (arch == AUDIT_ARCH_I386 && matches!(syscall_nr, 55 | 221))
}

#[inline(always)]
fn is_fcntl_dup(arch: u32, syscall_nr: u32, command: u64) -> bool {
    is_fcntl(arch, syscall_nr) && matches!(command, 0 | 1030)
}

fn header(
    record_type: RecordType,
    pid_tgid: u64,
    rule_version: u64,
    flags: u32,
) -> KernelEventHeader {
    KernelEventHeader {
        schema_version: SCHEMA_VERSION,
        record_type: record_type as u16,
        record_len: core::mem::size_of::<SyscallEvent>() as u32,
        cpu: unsafe { bpf_get_smp_processor_id() },
        flags,
        ktime_ns: unsafe { bpf_ktime_get_ns() },
        sequence: 0,
        rule_version,
        pid_tgid,
        process_start_ns: 0,
    }
}

#[inline(never)]
fn permission_mask(generation: u32, arch: u32, syscall_nr: u32) -> u8 {
    // verifier 不保证把调用方分支收窄结果传播到独立子程序，因此必须在发生
    // 512 字节 map value 指针运算的同一函数内再次证明索引上界。
    if syscall_nr >= 512 {
        return 0;
    }
    let index = (generation & 1) * 512 + syscall_nr;
    let permission = if arch == AUDIT_ARCH_I386 {
        PERMISSION_MASKS_B32.get(index)
    } else {
        PERMISSION_MASKS_B64.get(index)
    };
    permission.copied().unwrap_or(0)
}

#[inline(never)]
fn maintenance_contains(generation: u32, arch: u32, syscall_nr: u32) -> bool {
    if arch == AUDIT_ARCH_I386 {
        bitmap_contains(&MAINTENANCE_BITMAPS_B32, generation, syscall_nr)
    } else {
        bitmap_contains(&MAINTENANCE_BITMAPS_B64, generation, syscall_nr)
    }
}

#[inline(always)]
fn classify_permission(
    arch: u32,
    syscall_nr: u32,
    arg1: u64,
    arg2: u64,
    static_permissions: u8,
) -> Option<u8> {
    if is_open(arch, syscall_nr) {
        return open_access_mode(arg1);
    }
    if is_openat(arch, syscall_nr) {
        return open_access_mode(arg2);
    }
    if is_openat2(arch, syscall_nr) {
        if arg2 == 0 {
            return None;
        }
        // SAFETY: open_how 的首字段固定为 u64 flags；只读取 8 字节且通过 user helper，
        // 不信任用户提供的 size，也不读取结构后续字段，边界适用于 5.15+ ABI。
        let flags = unsafe { bpf_probe_read_user(arg2 as *const u64) }.ok()?;
        return open_access_mode(flags);
    }
    Some(static_permissions)
}

#[inline(always)]
fn open_access_mode(flags: u64) -> Option<u8> {
    match flags & 0x3 {
        0 => Some(PERM_READ),
        1 => Some(PERM_WRITE),
        2 => Some(PERM_READ | PERM_WRITE),
        _ => None,
    }
}

#[inline(always)]
fn is_open(arch: u32, syscall_nr: u32) -> bool {
    (arch == AUDIT_ARCH_I386 && syscall_nr == 5) || (arch == AUDIT_ARCH_X86_64 && syscall_nr == 2)
}

#[inline(always)]
fn is_openat(arch: u32, syscall_nr: u32) -> bool {
    (arch == AUDIT_ARCH_I386 && syscall_nr == 295)
        || (arch == AUDIT_ARCH_X86_64 && syscall_nr == 257)
}

#[inline(always)]
fn is_openat2(_arch: u32, syscall_nr: u32) -> bool {
    syscall_nr == 437
}

#[inline(always)]
fn is_creat(arch: u32, syscall_nr: u32) -> bool {
    (arch == AUDIT_ARCH_I386 && syscall_nr == 8) || (arch == AUDIT_ARCH_X86_64 && syscall_nr == 85)
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
    // 子程序边界会丢失调用方的 `<512` 证明；掩码让实际参与 map value
    // 指针运算的寄存器始终有 9 位上界。
    let bounded_syscall_nr = syscall_nr & 511;
    let word = (bounded_syscall_nr / 64) as usize;
    let bit = bounded_syscall_nr % 64;
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
fn watch_path_candidate(generation: u32, inflight: &InflightSyscall) -> bool {
    let count = WATCH_PATH_COUNTS
        .get(generation)
        .copied()
        .unwrap_or(0)
        .min(16);
    if count == 0 {
        return true;
    }
    // ftruncate/fchmod 等 fd-only 操作没有用户路径，必须交给用户态 FD 表关联。
    if inflight.path_len == 0 && inflight.path2_len == 0 {
        return true;
    }
    let primary_absolute = inflight.path_len > 0 && inflight.path[0] == b'/';
    let secondary_absolute = inflight.path2_len > 0 && inflight.path2[0] == b'/';
    let base = (generation & 1) * 16;
    if !primary_absolute && !secondary_absolute {
        let primary_suffix = path_suffix_hash(&inflight.path, inflight.path_len);
        let secondary_suffix = path_suffix_hash(&inflight.path2, inflight.path2_len);
        let mut index = 0;
        while index < 16 {
            if index >= count {
                break;
            }
            let expected = WATCH_BASENAME_HASHES
                .get(base + index)
                .copied()
                .unwrap_or(0);
            if (inflight.path_len > 0 && primary_suffix == expected)
                || (inflight.path2_len > 0 && secondary_suffix == expected)
            {
                return true;
            }
            index += 1;
        }
        return false;
    }
    // 双路径 syscall 若混合绝对与相对参数，相对一侧仍需 dirfd/cwd 解析；该少见形态
    // 保守送往用户态，避免为了候选削减制造静默漏报。
    if (primary_absolute && inflight.path2_len > 0 && !secondary_absolute)
        || (secondary_absolute && inflight.path_len > 0 && !primary_absolute)
    {
        return true;
    }
    // 显式初始化哈希寄存器，避免 verifier 将 Option 分支识别为“可能未写入”。
    // absolute 布尔值仍保护比较，因此 0 只作为未计算时的占位值。
    let mut primary_hash = 0_u64;
    if primary_absolute {
        primary_hash = path_hash(&inflight.path, inflight.path_len);
    }
    let mut secondary_hash = 0_u64;
    if secondary_absolute {
        secondary_hash = path_hash(&inflight.path2, inflight.path2_len);
    }
    let mut index = 0;
    while index < 16 {
        if index >= count {
            break;
        }
        let expected = WATCH_PATH_HASHES.get(base + index).copied().unwrap_or(0);
        if (primary_absolute && primary_hash == expected)
            || (secondary_absolute && secondary_hash == expected)
        {
            return true;
        }
        index += 1;
    }
    false
}

#[inline(never)]
fn path_suffix_hash(path: &[u8; MAX_PATH_ARG_BYTES], declared_length: u16) -> u64 {
    let mut length = (declared_length as usize).min(MAX_PATH_ARG_BYTES);
    if length > 0 && path[length - 1] == 0 {
        length -= 1;
    }
    if length == 0 {
        return 0;
    }
    let mut signature = u64::from(path[length - 1]);
    if length > 1 {
        signature |= u64::from(path[length - 2]) << 8;
    }
    if length > 2 {
        signature |= u64::from(path[length - 3]) << 16;
    }
    if length > 3 {
        signature |= u64::from(path[length - 4]) << 24;
    }
    if length > 4 {
        signature |= u64::from(path[length - 5]) << 32;
    }
    if length > 5 {
        signature |= u64::from(path[length - 6]) << 40;
    }
    if length > 6 {
        signature |= u64::from(path[length - 7]) << 48;
    }
    if length > 7 {
        signature |= u64::from(path[length - 8]) << 56;
    }
    signature
}

#[inline(always)]
fn path_hash(path: &[u8; MAX_PATH_ARG_BYTES], declared_length: u16) -> u64 {
    let length = (declared_length as usize).min(MAX_PATH_ARG_BYTES);
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    let mut index = 0;
    while index < MAX_PATH_ARG_BYTES {
        if index >= length || path[index] == 0 {
            break;
        }
        hash = (hash ^ u64::from(path[index])).wrapping_mul(0x100_0000_01b3);
        index += 1;
    }
    hash
}

#[inline(never)]
fn path_argument_indexes(arch: u32, syscall_nr: u32) -> (usize, usize) {
    if arch == AUDIT_ARCH_I386 {
        match syscall_nr {
            5
            | 8
            | 10
            | 11
            | 12
            | 14..=16
            | 39..=40
            | 61
            | 85
            | 92
            | 182
            | 226
            | 227
            | 229
            | 230
            | 232
            | 233
            | 235
            | 236 => (0, 6),
            9 | 38 | 83 => (0, 1),
            295..=301 | 305 | 306 | 358 | 437 | 452 => (1, 6),
            302 | 303 | 353 => (1, 3),
            304 => (0, 2),
            _ => (6, 6),
        }
    } else {
        match syscall_nr {
            2
            | 59
            | 76
            | 83..=85
            | 87
            | 89
            | 90
            | 92
            | 94
            | 133
            | 188
            | 189
            | 191
            | 192
            | 194
            | 195
            | 197
            | 198 => (0, 6),
            82 | 86 | 88 => (0, 1),
            257..=263 | 267 | 268 | 322 | 437 | 452 => (1, 6),
            264 | 265 | 316 => (1, 3),
            266 => (0, 2),
            _ => (6, 6),
        }
    }
}

#[inline(never)]
fn path_dirfd(arch: u32, syscall_nr: u32, args: &[u64; 6]) -> i32 {
    let has_dirfd = if arch == AUDIT_ARCH_I386 {
        matches!(syscall_nr, 295..=306 | 353 | 358 | 437 | 452)
    } else {
        matches!(
            syscall_nr,
            257..=268 | 316 | 322 | 429 | 437 | 439 | 442 | 452
        )
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
