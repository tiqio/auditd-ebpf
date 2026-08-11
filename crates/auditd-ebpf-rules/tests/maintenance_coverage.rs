use auditd_ebpf_rules::{Arch, RuleCompiler, parse_rules, syscall_number};

#[test]
fn path_rules_add_cache_maintenance_without_permission_interest() {
    let plan = RuleCompiler::compile(
        parse_rules("watch.rules", "-w /tmp/ddtest -p rw -k ddtest").unwrap(),
        0,
        Default::default(),
    )
    .unwrap();

    for arch in [Arch::B64, Arch::B32] {
        for name in ["close", "dup", "dup2", "dup3", "fcntl", "chdir", "fchdir"] {
            let number = syscall_number(arch, name).unwrap();
            let (overall, maintenance, permissions) = match arch {
                Arch::B64 => (
                    &plan.syscalls_b64,
                    &plan.maintenance_syscalls_b64,
                    &plan.permission_masks_b64,
                ),
                Arch::B32 => (
                    &plan.syscalls_b32,
                    &plan.maintenance_syscalls_b32,
                    &plan.permission_masks_b32,
                ),
            };
            assert!(overall.contains(&number), "missing {arch:?} {name}");
            assert!(
                maintenance.contains(&number),
                "not maintenance {arch:?} {name}"
            );
            assert_eq!(permissions[number as usize], 0);
        }
    }
}
