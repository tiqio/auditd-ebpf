#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum RecordType {
    Syscall = 1,
    ExecAttempt = 2,
    ExecResult = 3,
    Fork = 4,
    Exit = 5,
    InternalGap = 6,
    ProcessExec = 7,
}

/// 固定宽度公共头；用户态必须验证 schema 与长度后再读取其余字段。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct KernelEventHeader {
    pub schema_version: u16,
    pub record_type: u16,
    pub record_len: u32,
    pub cpu: u32,
    pub flags: u32,
    pub ktime_ns: u64,
    pub sequence: u64,
    pub rule_version: u64,
    pub pid_tgid: u64,
    pub process_start_ns: u64,
}

/// syscall 事件 flags 的 permission 有效标记，位于 bit 8，避免与 Linux audit
/// 兼容的低四位权限掩码重叠。schema 1 的结构布局不变，只解释原有 `flags` 字段。
pub const PERMISSION_VALID: u32 = 1 << 8;
pub const EVENT_PERMISSION_BITS: u32 = PermissionMask::ALL.bits() as u32;
pub const SYSCALL_EVENT_KNOWN_FLAGS: u32 = PERMISSION_VALID | EVENT_PERMISSION_BITS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermissionFlagsError {
    UnknownBits,
    PermissionWithoutValid,
    EmptyValidPermission,
}

/// 校验并解码 syscall 事件权限。旧 eBPF 对象产生的 `flags=0` 返回 `None`，
/// 因而仍可服务不带权限条件的普通 syscall 规则；任何保留位都不能被静默忽略。
pub const fn permission_from_event_flags(
    flags: u32,
) -> Result<Option<PermissionMask>, PermissionFlagsError> {
    if flags & !SYSCALL_EVENT_KNOWN_FLAGS != 0 {
        return Err(PermissionFlagsError::UnknownBits);
    }
    let permission_bits = (flags & EVENT_PERMISSION_BITS) as u8;
    if flags & PERMISSION_VALID == 0 {
        return if permission_bits == 0 {
            Ok(None)
        } else {
            Err(PermissionFlagsError::PermissionWithoutValid)
        };
    }
    if permission_bits == 0 {
        return Err(PermissionFlagsError::EmptyValidPermission);
    }
    match PermissionMask::from_bits(permission_bits) {
        Some(permission) => Ok(Some(permission)),
        None => Err(PermissionFlagsError::UnknownBits),
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct SyscallEvent {
    pub header: KernelEventHeader,
    pub arch: u32,
    pub syscall_nr: u32,
    pub args: [u64; 6],
    pub return_value: i64,
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    pub ppid: u32,
    pub comm: [u8; 16],
    pub dirfd: i32,
    pub path_flags: u32,
    pub path_len: u16,
    pub path2_len: u16,
    pub path: [u8; MAX_PATH_ARG_BYTES],
    pub path2: [u8; MAX_PATH_ARG_BYTES],
}

pub const MAX_PATH_ARG_BYTES: usize = 160;
pub const PATH_FLAG_PRIMARY_PRESENT: u32 = 1 << 0;
pub const PATH_FLAG_SECONDARY_PRESENT: u32 = 1 << 1;
pub const PATH_FLAG_TRUNCATED: u32 = 1 << 2;
pub const PATH_FLAG_MOUNT_BOUNDARY_CHANGED: u32 = 1 << 3;

pub const MAX_EXEC_ARGS: usize = 32;
pub const MAX_EXEC_ARG_BYTES: usize = 192;
pub const MAX_EXEC_BYTES: usize = MAX_EXEC_ARGS * MAX_EXEC_ARG_BYTES;
pub const EXEC_ARGV_FLAG_ARGUMENT_TRUNCATED: u16 = 1 << 0;
pub const EXEC_ARGV_FLAG_ARGC_TRUNCATED: u16 = 1 << 1;
pub const EXEC_ARGV_FLAG_READ_ERROR: u16 = 1 << 2;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct ExecAttempt {
    pub header: KernelEventHeader,
    pub attempt_id: u64,
    pub argc_observed: u32,
    pub argc_captured: u16,
    pub argv_flags: u16,
    pub argv_offsets: [u16; MAX_EXEC_ARGS + 1],
    pub argv_bytes: [u8; MAX_EXEC_BYTES],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct ExecResult {
    pub header: KernelEventHeader,
    pub attempt_id: u64,
    pub result: i64,
    pub new_comm: [u8; 16],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct ProcessEvent {
    pub header: KernelEventHeader,
    pub parent_pid_tgid: u64,
    /// fork 时为 child pid/tgid，exec 时为被替换的旧 tid，exit 时为零。
    pub related_pid_tgid: u64,
    pub event_kind: u32,
    pub abi_arch: u32,
}

pub const PROCESS_EVENT_FORK: u32 = 1;
pub const PROCESS_EVENT_EXEC: u32 = 2;
pub const PROCESS_EVENT_EXIT: u32 = 3;
use crate::permission::PermissionMask;
