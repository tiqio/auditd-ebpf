#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum RecordType {
    Syscall = 1,
    ExecAttempt = 2,
    ExecResult = 3,
    Fork = 4,
    Exit = 5,
    InternalGap = 6,
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
}
