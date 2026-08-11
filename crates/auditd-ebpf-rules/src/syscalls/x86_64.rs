use crate::Arch;

pub fn syscall_number(arch: Arch, value: &str) -> Option<u32> {
    if let Ok(number) = value.parse() {
        return Some(number);
    }
    match (arch, value) {
        (Arch::B64, "read") => Some(0),
        (Arch::B64, "write") => Some(1),
        (Arch::B64, "close") => Some(3),
        (Arch::B64, "getpid") => Some(39),
        (Arch::B64, "rename") => Some(82),
        (Arch::B64, "unlink") => Some(87),
        (Arch::B64, "execve") => Some(59),
        (Arch::B64, "openat") => Some(257),
        (Arch::B64, "execveat") => Some(322),
        (Arch::B32, "read") => Some(3),
        (Arch::B32, "write") => Some(4),
        (Arch::B32, "close") => Some(6),
        (Arch::B32, "getpid") => Some(20),
        (Arch::B32, "rename") => Some(38),
        (Arch::B32, "unlink") => Some(10),
        (Arch::B32, "execve") => Some(11),
        (Arch::B32, "openat") => Some(295),
        (Arch::B32, "execveat") => Some(358),
        _ => None,
    }
}

#[must_use]
pub fn syscall_name(arch: Arch, number: u32) -> Option<&'static str> {
    match (arch, number) {
        (Arch::B64, 0) => Some("read"),
        (Arch::B64, 1) => Some("write"),
        (Arch::B64, 3) => Some("close"),
        (Arch::B64, 39) => Some("getpid"),
        (Arch::B64, 82) => Some("rename"),
        (Arch::B64, 87) => Some("unlink"),
        (Arch::B64, 59) => Some("execve"),
        (Arch::B64, 257) => Some("openat"),
        (Arch::B64, 322) => Some("execveat"),
        (Arch::B32, 3) => Some("read"),
        (Arch::B32, 4) => Some("write"),
        (Arch::B32, 6) => Some("close"),
        (Arch::B32, 20) => Some("getpid"),
        (Arch::B32, 38) => Some("rename"),
        (Arch::B32, 10) => Some("unlink"),
        (Arch::B32, 11) => Some("execve"),
        (Arch::B32, 295) => Some("openat"),
        (Arch::B32, 358) => Some("execveat"),
        _ => None,
    }
}
