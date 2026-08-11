use std::collections::{BTreeMap, BTreeSet};

use auditd_ebpf_common::permission::PermissionMask;

use crate::{Arch, syscall_number};

pub const COVERAGE_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PermissionCoverageEntry {
    pub permissions: PermissionMask,
    pub dynamic_open: bool,
    pub primary_path: bool,
    pub secondary_path: bool,
    pub fd_path: bool,
}

impl PermissionCoverageEntry {
    const fn path(permissions: PermissionMask) -> Self {
        Self {
            permissions,
            dynamic_open: false,
            primary_path: true,
            secondary_path: false,
            fd_path: false,
        }
    }

    const fn dual_path(permissions: PermissionMask) -> Self {
        Self {
            permissions,
            dynamic_open: false,
            primary_path: true,
            secondary_path: true,
            fd_path: false,
        }
    }

    const fn fd(permissions: PermissionMask) -> Self {
        Self {
            permissions,
            dynamic_open: false,
            primary_path: false,
            secondary_path: false,
            fd_path: true,
        }
    }

    const fn dynamic_open(permissions: PermissionMask) -> Self {
        Self {
            permissions,
            dynamic_open: true,
            primary_path: true,
            secondary_path: false,
            fd_path: false,
        }
    }
}

#[must_use]
pub fn permission_coverage(
    arch: Arch,
    requested: PermissionMask,
) -> BTreeMap<u32, PermissionCoverageEntry> {
    let mut coverage = BTreeMap::new();
    let rw = requested & (PermissionMask::READ | PermissionMask::WRITE);
    if !rw.is_empty() {
        for name in ["open", "openat", "openat2"] {
            insert(
                &mut coverage,
                arch,
                name,
                PermissionCoverageEntry::dynamic_open(rw),
            );
        }
    }
    insert_if_requested(
        &mut coverage,
        arch,
        "creat",
        requested,
        PermissionCoverageEntry::path(PermissionMask::WRITE),
    );

    for name in [
        "readlink",
        "readlinkat",
        "getxattr",
        "lgetxattr",
        "listxattr",
        "llistxattr",
    ] {
        insert_if_requested(
            &mut coverage,
            arch,
            name,
            requested,
            PermissionCoverageEntry::path(PermissionMask::READ),
        );
    }
    for name in ["fgetxattr", "flistxattr"] {
        insert_if_requested(
            &mut coverage,
            arch,
            name,
            requested,
            PermissionCoverageEntry::fd(PermissionMask::READ),
        );
    }

    for name in [
        "truncate", "unlink", "unlinkat", "mkdir", "mkdirat", "rmdir", "mknod", "mknodat",
    ] {
        insert_if_requested(
            &mut coverage,
            arch,
            name,
            requested,
            PermissionCoverageEntry::path(PermissionMask::WRITE),
        );
    }
    for name in ["ftruncate", "fallocate"] {
        insert_if_requested(
            &mut coverage,
            arch,
            name,
            requested,
            PermissionCoverageEntry::fd(PermissionMask::WRITE),
        );
    }
    for name in ["rename", "renameat", "renameat2", "symlink", "symlinkat"] {
        insert_if_requested(
            &mut coverage,
            arch,
            name,
            requested,
            PermissionCoverageEntry::dual_path(PermissionMask::WRITE),
        );
    }
    for name in ["link", "linkat"] {
        insert_if_requested(
            &mut coverage,
            arch,
            name,
            requested,
            PermissionCoverageEntry::dual_path(PermissionMask::WRITE | PermissionMask::ATTR),
        );
    }

    for name in ["execve", "execveat"] {
        insert_if_requested(
            &mut coverage,
            arch,
            name,
            requested,
            PermissionCoverageEntry::path(PermissionMask::EXEC),
        );
    }

    for name in [
        "chmod",
        "fchmodat",
        "fchmodat2",
        "chown",
        "lchown",
        "fchownat",
        "setxattr",
        "lsetxattr",
        "removexattr",
        "lremovexattr",
    ] {
        insert_if_requested(
            &mut coverage,
            arch,
            name,
            requested,
            PermissionCoverageEntry::path(PermissionMask::ATTR),
        );
    }
    for name in ["fchmod", "fchown", "fsetxattr", "fremovexattr"] {
        insert_if_requested(
            &mut coverage,
            arch,
            name,
            requested,
            PermissionCoverageEntry::fd(PermissionMask::ATTR),
        );
    }

    coverage
}

#[must_use]
pub fn maintenance_syscalls(arch: Arch) -> BTreeSet<u32> {
    [
        "close",
        "dup",
        "dup2",
        "dup3",
        "fcntl",
        "chdir",
        "fchdir",
        "chroot",
        "pivot_root",
        "mount",
        "umount2",
        "unshare",
        "setns",
        "mount_setattr",
    ]
    .into_iter()
    .filter_map(|name| syscall_number(arch, name))
    .collect()
}

fn insert_if_requested(
    coverage: &mut BTreeMap<u32, PermissionCoverageEntry>,
    arch: Arch,
    name: &str,
    requested: PermissionMask,
    mut entry: PermissionCoverageEntry,
) {
    entry.permissions &= requested;
    if !entry.permissions.is_empty() {
        insert(coverage, arch, name, entry);
    }
}

fn insert(
    coverage: &mut BTreeMap<u32, PermissionCoverageEntry>,
    arch: Arch,
    name: &str,
    entry: PermissionCoverageEntry,
) {
    if let Some(number) = syscall_number(arch, name).filter(|number| *number < 512) {
        coverage
            .entry(number)
            .and_modify(|current| {
                current.permissions |= entry.permissions;
                current.dynamic_open |= entry.dynamic_open;
                current.primary_path |= entry.primary_path;
                current.secondary_path |= entry.secondary_path;
                current.fd_path |= entry.fd_path;
            })
            .or_insert(entry);
    }
}
