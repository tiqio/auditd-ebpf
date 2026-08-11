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
    pub event_kind: u32,
    pub abi_arch: u32,
}

pub const PROCESS_EVENT_FORK: u32 = 1;
pub const PROCESS_EVENT_EXEC: u32 = 2;
pub const PROCESS_EVENT_EXIT: u32 = 3;
