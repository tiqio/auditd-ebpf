use auditd_ebpf::{
    identity::HostIdentity,
    output::{
        event_formatter::{AuditEvent, format_event},
        status_formatter::unclean_shutdown_gap,
        status_formatter::{diagnostic, status},
    },
    rules::argv_policy::EffectiveArgvOutput,
};

fn event(output: EffectiveArgvOutput, argv: &[Vec<u8>]) -> AuditEvent<'_> {
    AuditEvent {
        unix_seconds: 1_786_352_400,
        millis: 123,
        sequence: 42,
        host: b"node-a",
        machine_id: "0123456789abcdef0123456789abcdef",
        event_id: b"boot:42",
        rule_version: 7,
        rule_id: 3,
        key: b"exec",
        arch: 0xc000_003e,
        syscall: "execve",
        operation: "exec",
        success: true,
        exit: 0,
        pid: 1200,
        ppid: 1180,
        uid: 1000,
        gid: 1000,
        euid: 1000,
        egid: 1000,
        comm: b"bash",
        exe: b"/usr/bin/id",
        path: b"/usr/bin/id",
        perm: "x",
        argv_output: output,
        argc: 2,
        argv,
        argv_truncated: false,
        path_confidence: "proc-snapshot",
    }
}

#[test]
fn emitted_and_suppressed_match_golden_contract() {
    let argv = [b"id".to_vec(), b"-u".to_vec()];
    assert_eq!(
        format_event(&event(EffectiveArgvOutput::Emitted, &argv)),
        include_str!("../../../tests/golden/events/emitted.log")
    );
    let suppressed = format_event(&event(EffectiveArgvOutput::Suppressed, &argv));
    assert_eq!(
        suppressed,
        include_str!("../../../tests/golden/events/suppressed.log")
    );
    assert!(!suppressed.contains(" a0="));
}

#[test]
fn unclean_shutdown_is_the_only_unknown_count_gap_shape() {
    let identity = HostIdentity {
        host: "node-a".into(),
        machine_id: "0123456789abcdef0123456789abcdef".into(),
        machine_id_diagnostic: None,
    };
    assert_eq!(
        unclean_shutdown_gap(
            &identity,
            "audit(1786352401.000:43)",
            "boot:43",
            1_786_352_401_000
        ),
        include_str!("../../../tests/golden/events/unclean-gap.log")
    );
}

#[test]
fn diagnostic_and_status_match_golden_and_never_contain_argv() {
    let identity = HostIdentity {
        host: "node-a".into(),
        machine_id: "0123456789abcdef0123456789abcdef".into(),
        machine_id_diagnostic: None,
    };
    let diag = diagnostic(
        &identity,
        "error",
        "path_stale",
        "process_cache",
        b"context expired",
    );
    let state = status(&identity, "degraded", 10, 2, false);
    assert_eq!(diag, include_str!("../../../tests/golden/events/diag.log"));
    assert_eq!(
        state,
        include_str!("../../../tests/golden/events/status.log")
    );
    assert!(!diag.contains(" a0="));
    assert!(!state.contains(" a0="));
}
