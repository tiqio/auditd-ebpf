use std::{collections::BTreeMap, path::Path};

use auditd_ebpf::rules::{
    argv_policy::EffectiveArgvOutput,
    engine::{CandidateEvent, RuleEngine},
};
use auditd_ebpf_common::permission::PermissionMask;
use auditd_ebpf_rules::{ArgvOutput, RuleCompiler, parse_rules};

fn engine(input: &str, global_argv_enabled: bool) -> RuleEngine {
    let rules = parse_rules("engine.rules", input).expect("规则应可解析");
    let plan = RuleCompiler::compile(rules, 0, BTreeMap::new()).expect("规则应可编译");
    RuleEngine::new(plan, global_argv_enabled)
}

#[test]
fn evaluates_identity_result_permission_and_first_match_exactly() {
    let engine = engine(
        "-a always,exit -F arch=b64 -S openat -F uid=1000 -F gid=100 -F success=yes -F path=/srv/a -F perm=r -k first\n\
         -a always,exit -F arch=b64 -S openat -F path=/srv/a -k fallback\n",
        true,
    );
    let event = CandidateEvent::new(auditd_ebpf_rules::Arch::B64, "openat")
        .with_identity(1000, 100)
        .with_success(true)
        .with_path(Path::new("/srv/a"))
        .with_permissions(PermissionMask::READ);

    let matched = engine.evaluate(&event).expect("事件应匹配");
    assert_eq!(matched.rule.key, "first");
    assert_eq!(matched.argv_output, EffectiveArgvOutput::Emitted);

    let wrong_uid = CandidateEvent::new(auditd_ebpf_rules::Arch::B64, "openat")
        .with_identity(0, 100)
        .with_success(true)
        .with_path(Path::new("/srv/a"))
        .with_permissions(PermissionMask::READ);
    assert_eq!(engine.evaluate(&wrong_uid).unwrap().rule.key, "fallback");
}

#[test]
fn rdwr_intersects_read_and_write_rules_but_preserves_first_rule() {
    let engine = engine(
        "-w /srv/file -p r -k read-first\n-w /srv/file -p w -k write-second\n",
        true,
    );
    let event = CandidateEvent::new(auditd_ebpf_rules::Arch::B64, "openat")
        .with_path(Path::new("/srv/file"))
        .with_permissions(PermissionMask::READ | PermissionMask::WRITE);
    assert_eq!(engine.evaluate(&event).unwrap().rule.key, "read-first");
}

#[test]
fn directory_matching_obeys_component_boundaries_and_argv_policy() {
    let mut overrides = BTreeMap::new();
    overrides.insert("exec-dir".to_owned(), ArgvOutput::Disabled);
    let rules = parse_rules(
        "engine.rules",
        "-a always,exit -F arch=b64 -S execve -F dir=/srv/bin -k exec-dir\n",
    )
    .unwrap();
    let plan = RuleCompiler::compile(rules, 0, overrides).unwrap();
    let engine = RuleEngine::new(plan, true);

    let inside = CandidateEvent::new(auditd_ebpf_rules::Arch::B64, "execve")
        .with_path(Path::new("/srv/bin/tool"));
    let outside = CandidateEvent::new(auditd_ebpf_rules::Arch::B64, "execve")
        .with_path(Path::new("/srv/binary/tool"));

    assert_eq!(
        engine.evaluate(&inside).unwrap().argv_output,
        EffectiveArgvOutput::Suppressed
    );
    assert!(engine.evaluate(&outside).is_none());
}

#[test]
fn 按key开启策略优先于全局关闭() {
    let rules = parse_rules(
        "engine.rules",
        "-a always,exit -F arch=b64 -S execve -k visible\n",
    )
    .unwrap();
    let plan = RuleCompiler::compile(
        rules,
        0,
        [("visible".to_owned(), ArgvOutput::Enabled)].into(),
    )
    .unwrap();
    assert!(plan.exec_capture_enabled, "关闭输出不得关闭内核 argv 采集");
    let overridden_engine = RuleEngine::new(plan, false);
    let event = CandidateEvent::new(auditd_ebpf_rules::Arch::B64, "execve");

    assert_eq!(
        overridden_engine.evaluate(&event).unwrap().argv_output,
        EffectiveArgvOutput::Emitted
    );

    let inherited = engine("-a always,exit -F arch=b64 -S execve -k inherited\n", false);
    assert_eq!(
        inherited.evaluate(&event).unwrap().argv_output,
        EffectiveArgvOutput::Suppressed
    );
}
