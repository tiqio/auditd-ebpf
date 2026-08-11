use auditd_ebpf::{
    health::counters::HealthCounters,
    identity::HostIdentity,
    output::{
        event_formatter::{AuditEvent, format_event},
        status_formatter::unclean_shutdown_gap,
        status_formatter::{StatusRecord, diagnostic, status},
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
        ppid: Some(1180),
        uid: 1000,
        gid: 1000,
        euid: 1000,
        egid: 1000,
        comm: b"bash",
        exe: Some(b"/usr/bin/id"),
        path: b"/usr/bin/id",
        perm: Some("x"),
        argv_output: output,
        argc: 2,
        argv,
        argv_truncated: false,
        path_confidence: "proc-snapshot",
    }
}

#[test]
fn 重要但不可靠的字段显式输出未知值() {
    let mut unknown = event(EffectiveArgvOutput::Suppressed, &[]);
    unknown.ppid = None;
    unknown.exe = None;
    unknown.perm = None;

    let line = format_event(&unknown);
    assert!(line.contains(" ppid=? "));
    assert!(line.contains(" exe=? "));
    assert!(line.contains(" perm=? "));
    assert!(!line.contains(" ppid=0 "));
    assert!(!line.contains(" exe=\"\" "));
    assert!(!line.contains(" perm= argv_output="));
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
fn watch_permissions_failed_result_and_real_operation_match_golden() {
    for (permission, golden) in [
        (
            "r",
            include_str!("../../../tests/golden/events/watch-r.log"),
        ),
        (
            "w",
            include_str!("../../../tests/golden/events/watch-w.log"),
        ),
        (
            "rw",
            include_str!("../../../tests/golden/events/watch-rw.log"),
        ),
    ] {
        let mut watch = event(EffectiveArgvOutput::Emitted, &[]);
        watch.key = b"ddtest";
        watch.syscall = "openat";
        watch.operation = "openat";
        watch.path = b"/tmp/ddtest";
        watch.perm = Some(permission);
        watch.argc = 0;
        assert_eq!(format_event(&watch), golden);
    }

    let mut failed = event(EffectiveArgvOutput::Emitted, &[]);
    failed.key = b"ddtest";
    failed.syscall = "openat";
    failed.operation = "openat";
    failed.success = false;
    failed.exit = -13;
    failed.path = b"/tmp/ddtest";
    failed.perm = Some("w");
    failed.argc = 0;
    assert_eq!(
        format_event(&failed),
        include_str!("../../../tests/golden/events/watch-failed.log")
    );
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
    let counters = HealthCounters {
        exec_argv_captured_total: 10,
        exec_argv_suppressed_total: 2,
        ..HealthCounters::default()
    };
    let state = status(
        &identity,
        &StatusRecord {
            state: "degraded",
            reason: Some("test_gap"),
            uptime_seconds: 60,
            rule_version: Some(7),
            programs_attached: 5,
            counters: &counters,
            queue_used_bytes: 1024,
            queue_limit_bytes: 2048,
            queue_max_bytes: 4096,
            final_record: false,
        },
    );
    assert_eq!(diag, include_str!("../../../tests/golden/events/diag.log"));
    assert_eq!(
        state,
        include_str!("../../../tests/golden/events/status.log")
    );
    assert!(!diag.contains(" a0="));
    assert!(!state.contains(" a0="));
}
