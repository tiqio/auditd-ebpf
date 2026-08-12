use auditd_ebpf_rules::{RuleCompiler, parse_rules};

#[test]
fn rejects_missing_empty_duplicate_and_mixed_key_forms() {
    for input in [
        "-a always,exit -S execve",
        "-a always,exit -S execve -k",
        "-a always,exit -S execve -k one -k two",
        "-a always,exit -S execve -k one -F key=two",
    ] {
        assert!(
            parse_rules("bad.rules", input).is_err(),
            "accepted: {input}"
        );
    }
}

#[test]
fn rejects_unsupported_fields_and_parent_components() {
    assert!(parse_rules("bad.rules", "-a always,exit -S openat -F auid=1000 -k x").is_err());
    assert!(parse_rules("bad.rules", "-w /tmp/../etc -p wa -k x").is_err());
    assert!(parse_rules("bad.rules", "-a always,exit -S openat -F uid!=1000 -k x").is_err());
    assert!(
        parse_rules(
            "bad.rules",
            "-a always,exit -S openat -F success=maybe -k x"
        )
        .is_err()
    );
}

#[test]
fn watch_permission_and_path_diagnostics_are_precise() {
    for (input, code) in [
        ("-w /tmp/ddtest -k x", "E_PERMISSION"),
        ("-w /tmp/ddtest -p '' -k x", "E_PERMISSION"),
        ("-w /tmp/ddtest -p rr -k x", "E_PERMISSION"),
        ("-w /tmp/ddtest -p rz -k x", "E_PERMISSION"),
        ("-w relative -p r -k x", "E_WATCH_PATH"),
        ("-w /tmp/../etc -p r -k x", "E_WATCH_PATH"),
    ] {
        let errors = parse_rules("watch.rules", input).unwrap_err();
        assert_eq!(errors.0.len(), 1, "input={input}");
        assert_eq!(errors.0[0].code, code, "input={input}");
        assert_eq!(errors.0[0].file, "watch.rules");
        assert_eq!(errors.0[0].line, 1);
    }
}

#[test]
fn watch_requested_permissions_must_have_non_empty_coverage() {
    let mut rule = parse_rules("watch.rules", "-w /tmp/ddtest -p r -k x")
        .unwrap()
        .remove(0);
    rule.permissions.clear();
    let errors = RuleCompiler::compile(vec![rule], 0, Default::default()).unwrap_err();
    assert_eq!(errors.0[0].code, "E_PERMISSION_COVERAGE");
}
