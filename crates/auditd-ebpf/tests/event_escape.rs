use auditd_ebpf::{
    output::event_formatter::{AuditEvent, MAX_EVENT_LINE_BYTES, escape, format_event},
    rules::argv_policy::EffectiveArgvOutput,
};

#[test]
fn escapes_quotes_slashes_controls_nul_and_non_utf8_reversibly() {
    assert_eq!(
        escape(b"a\"b\\c\r\n\0\xff"),
        "\"a\\\"b\\\\c\\x0D\\x0A\\x00\\xFF\""
    );
}

#[test]
fn output_never_exceeds_sixteen_kib() {
    let argv = vec![vec![b'x'; 2048]; 32];
    let event = AuditEvent {
        unix_seconds: 1,
        millis: 0,
        sequence: 1,
        host: b"host",
        machine_id: "?",
        event_id: b"id",
        rule_version: 1,
        rule_id: 1,
        key: b"key",
        arch: 0xc000_003e,
        syscall: "execve",
        operation: "exec",
        success: true,
        exit: 0,
        pid: 1,
        ppid: None,
        uid: 0,
        gid: 0,
        euid: 0,
        egid: 0,
        comm: b"cmd",
        exe: Some(b"/bin/cmd"),
        path: b"/bin/cmd",
        perm: Some("x"),
        argv_output: EffectiveArgvOutput::Emitted,
        argc: 32,
        argv: &argv,
        argv_truncated: false,
        path_confidence: "proc-snapshot",
    };
    let line = format_event(&event);
    assert!(line.len() <= MAX_EVENT_LINE_BYTES);
    assert!(line.contains("truncated=yes"));
    assert!(!line[..line.len() - 1].contains('\n'));
}
