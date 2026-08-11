use auditd_ebpf::reload::ReloadService;
use auditd_ebpf_rules::{RuleCompiler, parse_rules};

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
