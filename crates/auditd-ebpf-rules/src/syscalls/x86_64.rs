use crate::Arch;

const SYSCALLS: &[(&str, u32, u32)] = &[
    ("read", 0, 3),
    ("write", 1, 4),
    ("open", 2, 5),
    ("close", 3, 6),
    ("link", 86, 9),
    ("unlink", 87, 10),
    ("execve", 59, 11),
    ("chdir", 80, 12),
    ("mknod", 133, 14),
    ("chmod", 90, 15),
    ("lchown", 94, 16),
    ("mount", 165, 21),
    ("dup", 32, 41),
    ("rename", 82, 38),
    ("mkdir", 83, 39),
    ("rmdir", 84, 40),
    ("umount2", 166, 52),
    ("fcntl", 72, 55),
    ("dup2", 33, 63),
    ("symlink", 88, 83),
    ("readlink", 89, 85),
    ("truncate", 76, 92),
    ("ftruncate", 77, 93),
    ("fchmod", 91, 94),
    ("fchown", 93, 95),
    ("fchdir", 81, 133),
    ("chroot", 161, 61),
    ("pivot_root", 155, 217),
    ("chown", 92, 182),
    ("setxattr", 188, 226),
    ("lsetxattr", 189, 227),
    ("fsetxattr", 190, 228),
    ("getxattr", 191, 229),
    ("lgetxattr", 192, 230),
    ("fgetxattr", 193, 231),
    ("listxattr", 194, 232),
    ("llistxattr", 195, 233),
    ("flistxattr", 196, 234),
    ("removexattr", 197, 235),
    ("lremovexattr", 198, 236),
    ("fremovexattr", 199, 237),
    ("openat", 257, 295),
    ("mkdirat", 258, 296),
    ("mknodat", 259, 297),
    ("fchownat", 260, 298),
    ("unlinkat", 263, 301),
    ("renameat", 264, 302),
    ("linkat", 265, 303),
    ("symlinkat", 266, 304),
    ("readlinkat", 267, 305),
    ("fchmodat", 268, 306),
    ("unshare", 272, 310),
    ("fallocate", 285, 324),
    ("dup3", 292, 330),
    ("setns", 308, 346),
    ("renameat2", 316, 353),
    ("execveat", 322, 358),
    ("openat2", 437, 437),
    ("mount_setattr", 442, 442),
    ("fchmodat2", 452, 452),
    ("creat", 85, 8),
    ("getpid", 39, 20),
];

pub fn syscall_number(arch: Arch, value: &str) -> Option<u32> {
    if let Ok(number) = value.parse::<u32>() {
        return (number < 512).then_some(number);
    }
    SYSCALLS
        .iter()
        .find(|(name, _, _)| *name == value)
        .map(|(_, b64, b32)| match arch {
            Arch::B64 => *b64,
            Arch::B32 => *b32,
        })
}

#[must_use]
pub fn syscall_name(arch: Arch, number: u32) -> Option<&'static str> {
    SYSCALLS
        .iter()
        .find(|(_, b64, b32)| match arch {
            Arch::B64 => *b64 == number,
            Arch::B32 => *b32 == number,
        })
        .map(|(name, _, _)| *name)
}
