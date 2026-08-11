use auditd_ebpf_rules::{ArgvOutput, RuleCompiler, parse_rules};

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
