use auditd_ebpf_common::permission::PermissionMask;
use auditd_ebpf_rules::{Arch, COVERAGE_VERSION, permission_coverage, syscall_number};

#[test]
fn coverage_version_and_dynamic_open_are_stable_for_both_abis() {
    assert_eq!(COVERAGE_VERSION, 1);
    for arch in [Arch::B64, Arch::B32] {
        let coverage = permission_coverage(arch, PermissionMask::READ | PermissionMask::WRITE);
        for name in ["open", "openat", "openat2"] {
            let syscall = syscall_number(arch, name).unwrap();
            let entry = coverage.get(&syscall).unwrap();
            assert_eq!(
                entry.permissions,
                PermissionMask::READ | PermissionMask::WRITE
            );
            assert!(entry.dynamic_open);
        }
        assert_eq!(
            coverage
                .get(&syscall_number(arch, "creat").unwrap())
                .unwrap()
                .permissions,
            PermissionMask::WRITE
        );
    }
}

#[test]
fn fixed_permission_classes_include_dual_link_and_exec() {
    for arch in [Arch::B64, Arch::B32] {
        let all = permission_coverage(arch, PermissionMask::ALL);
        let link = all.get(&syscall_number(arch, "link").unwrap()).unwrap();
        assert_eq!(
            link.permissions,
            PermissionMask::WRITE | PermissionMask::ATTR
        );
        let exec = all.get(&syscall_number(arch, "execve").unwrap()).unwrap();
        assert_eq!(exec.permissions, PermissionMask::EXEC);
        let fchmod = all.get(&syscall_number(arch, "fchmod").unwrap()).unwrap();
        assert!(fchmod.fd_path);
        assert_eq!(fchmod.permissions, PermissionMask::ATTR);
    }
}
