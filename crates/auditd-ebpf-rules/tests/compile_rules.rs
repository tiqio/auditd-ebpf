use auditd_ebpf_common::permission::PermissionMask;
use auditd_ebpf_rules::{Arch, ArgvOutput, RuleCompiler, parse_rules, syscall_number};

#[test]
fn compiler_preserves_first_match_and_builds_generation_plan() {
    let rules = parse_rules(
        "ok.rules",
        "-a always,exit -S execve -k first\n-a always,exit -S execve -k second",
    )
    .unwrap();
    let plan = RuleCompiler::compile(rules, 1, Default::default()).unwrap();
    assert_eq!(plan.generation, 1);
    assert!(plan.exec_capture_enabled);
    assert_eq!(plan.rules[0].key, "first");
}

#[test]
fn unique_argv_override_changes_output_not_capture() {
    let rules = parse_rules("ok.rules", "-a always,exit -S execve -k exec").unwrap();
    let plan = RuleCompiler::compile(
        rules,
        0,
        [("exec".to_string(), ArgvOutput::Disabled)].into(),
    )
    .unwrap();
    assert!(plan.exec_capture_enabled);
    assert_eq!(plan.rules[0].argv_output, ArgvOutput::Disabled);
}

#[test]
fn every_exact_match_condition_changes_rule_version() {
    let base = RuleCompiler::compile(
        parse_rules(
            "base.rules",
            "-a always,exit -F arch=b64 -S openat -F uid=1000 -F gid=100 -F success=yes -F path=/a -F perm=r -k exact",
        )
        .unwrap(),
        0,
        Default::default(),
    )
    .unwrap();
    let changed = RuleCompiler::compile(
        parse_rules(
            "changed.rules",
            "-a always,exit -F arch=b64 -S openat -F uid=1001 -F gid=100 -F success=yes -F path=/a -F perm=r -k exact",
        )
        .unwrap(),
        0,
        Default::default(),
    )
    .unwrap();
    assert_ne!(base.version_hash, changed.version_hash);
}

#[test]
fn watch_compiles_to_non_empty_permission_tables_for_both_abis() {
    let plan = RuleCompiler::compile(
        parse_rules("watch.rules", "-w /tmp/ddtest -p rw -k ddtest").unwrap(),
        0,
        Default::default(),
    )
    .unwrap();

    for arch in [Arch::B64, Arch::B32] {
        let openat = syscall_number(arch, "openat").unwrap() as usize;
        let (syscalls, permissions) = match arch {
            Arch::B64 => (&plan.syscalls_b64, &plan.permission_masks_b64),
            Arch::B32 => (&plan.syscalls_b32, &plan.permission_masks_b32),
        };
        assert!(syscalls.contains(&(openat as u32)));
        assert_eq!(
            PermissionMask::from_bits(permissions[openat]).unwrap(),
            PermissionMask::READ | PermissionMask::WRITE
        );
    }
    assert_eq!(plan.coverage_by_rule.get(&0).unwrap().len(), 2);
}

#[test]
fn syscall_perm_rejects_unknown_permission_class() {
    let rules = parse_rules(
        "unknown.rules",
        "-a always,exit -F arch=b64 -S getpid -F perm=r -k invalid",
    )
    .unwrap();
    let error = RuleCompiler::compile(rules, 0, Default::default()).unwrap_err();
    assert_eq!(error.0[0].code, "E_PERMISSION_COVERAGE");
}
