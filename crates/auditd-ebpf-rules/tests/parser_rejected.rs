use auditd_ebpf_rules::parse_rules;

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
