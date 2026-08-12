use auditd_ebpf_common::permission::PermissionMask;
use auditd_ebpf_rules::{
    Arch, COVERAGE_VERSION, RuleCompiler, parse_rules, permission_coverage, syscall_number,
};

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

#[test]
fn watch_plan_has_non_empty_coverage_for_every_requested_permission_and_abi() {
    let plan = RuleCompiler::compile(
        parse_rules("watch.rules", "-w /tmp/ddtest -p rwxa -k ddtest").unwrap(),
        0,
        Default::default(),
    )
    .unwrap();
    let by_arch = plan.coverage_by_rule.get(&0).unwrap();
    for arch in [Arch::B64, Arch::B32] {
        let coverage = by_arch.get(&arch).unwrap();
        assert!(!coverage.effective_syscalls.is_empty());
        for permission in [
            PermissionMask::READ,
            PermissionMask::WRITE,
            PermissionMask::EXEC,
            PermissionMask::ATTR,
        ] {
            assert!(
                coverage
                    .syscall_permission_masks
                    .values()
                    .any(|mask| mask.intersects(permission)),
                "arch={arch:?} permission={permission:?}"
            );
        }
    }
}
