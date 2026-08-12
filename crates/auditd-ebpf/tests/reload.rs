use auditd_ebpf::reload::ReloadService;
use auditd_ebpf_common::permission::PermissionMask;
use auditd_ebpf_rules::{Arch, RuleCompiler, parse_rules, syscall_number};

#[test]
fn invalid_candidate_keeps_previous_generation() {
    let initial = RuleCompiler::compile(
        parse_rules("initial.rules", "-a always,exit -S execve -k initial").unwrap(),
        0,
        Default::default(),
    )
    .unwrap();
    let service = ReloadService::new(initial);
    assert!(
        service
            .reload("bad.rules", "-a always,exit -S execve", Default::default())
            .is_err()
    );
    assert_eq!(service.snapshot().generation, 0);
    assert_eq!(service.snapshot().rules[0].key, "initial");
}

#[test]
fn watch_reload_switches_generation_version_bitmap_and_permissions_together() {
    let initial = RuleCompiler::compile(
        parse_rules("initial.rules", "-w /tmp/ddtest -p r -k initial").unwrap(),
        0,
        Default::default(),
    )
    .unwrap();
    let initial_version = initial.rule_version();
    let service = ReloadService::new(initial);
    service
        .reload(
            "active.rules",
            "-w /tmp/ddtest -p w -k active",
            Default::default(),
        )
        .unwrap();
    let active = service.snapshot();
    assert_eq!(active.generation, 1);
    assert_ne!(active.rule_version(), initial_version);
    assert_eq!(active.rules[0].key, "active");
    for arch in [Arch::B64, Arch::B32] {
        let openat = syscall_number(arch, "openat").unwrap() as usize;
        let masks = if arch == Arch::B64 {
            &active.permission_masks_b64
        } else {
            &active.permission_masks_b32
        };
        assert_eq!(
            PermissionMask::from_bits(masks[openat]).unwrap(),
            PermissionMask::WRITE
        );
        let syscalls = if arch == Arch::B64 {
            &active.syscalls_b64
        } else {
            &active.syscalls_b32
        };
        assert!(syscalls.contains(&(openat as u32)));
    }
}
