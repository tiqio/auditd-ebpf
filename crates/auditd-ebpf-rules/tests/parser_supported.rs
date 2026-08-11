use auditd_ebpf_rules::{RuleKind, parse_rules};

#[test]
fn parses_comments_crlf_syscall_watch_and_multiple_syscall_terms() {
    let input = "# comment\r\n\r\n-a always,exit -F arch=b64 -S openat -S close,execve -k sys\r\n-w /tmp/demo -p wa -k watch\r\n";
    let rules = parse_rules("supported.rules", input).unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].key, "sys");
    assert_eq!(rules[0].syscalls, ["openat", "close", "execve"]);
    assert!(matches!(rules[1].kind, RuleKind::Watch));
}
