use auditd_ebpf::{
    output::{
        event_formatter::AuditEvent,
        writer::{OutputPipeline, OutputRecordKind},
    },
    rules::argv_policy::EffectiveArgvOutput,
};

fn event<'a>(argv_output: EffectiveArgvOutput, argv: &'a [Vec<u8>]) -> AuditEvent<'a> {
    AuditEvent {
        unix_seconds: 1,
        millis: 2,
        sequence: 3,
        host: b"node-a",
        machine_id: "machine-a",
        event_id: b"event-a",
        rule_version: 7,
        rule_id: 8,
        key: b"exec-key",
        arch: 0xc000_003e,
        syscall: "execve",
        operation: "exec",
        success: true,
        exit: 0,
        pid: 10,
        ppid: 9,
        uid: 0,
        gid: 0,
        euid: 0,
        egid: 0,
        comm: b"sh",
        exe: b"/bin/sh",
        path: b"/bin/sh",
        perm: "x",
        argv_output,
        argc: argv.len() as u32,
        argv,
        argv_truncated: false,
        path_confidence: "exact",
    }
}

#[test]
fn emitted_argv逐字节进入审计输出() {
    let secret = vec![b"/bin/echo".to_vec(), b"a\xffb\n".to_vec()];
    let mut pipeline = OutputPipeline::memory(1024, 4096).unwrap();

    pipeline
        .enqueue_event(&event(EffectiveArgvOutput::Emitted, &secret))
        .unwrap();
    let queued = pipeline.queued_records();

    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].kind, OutputRecordKind::Audit);
    assert!(
        queued[0]
            .bytes
            .windows(b"a0=\"/bin/echo\"".len())
            .any(|part| part == b"a0=\"/bin/echo\"")
    );
    assert!(
        queued[0]
            .bytes
            .windows(b"a1=\"a\\xFFb\\x0A\"".len())
            .any(|part| part == b"a1=\"a\\xFFb\\x0A\"")
    );
}

#[test]
fn suppressed_argv在入队前被彻底移除() {
    let marker = b"TOP-SECRET-ARGV".to_vec();
    let argv = vec![marker.clone()];
    let mut pipeline = OutputPipeline::memory(1024, 4096).unwrap();

    pipeline
        .enqueue_event(&event(EffectiveArgvOutput::Suppressed, &argv))
        .unwrap();
    pipeline
        .enqueue_gap(b"type=AUDITD_EBPF_GAP reason=test\n")
        .unwrap();
    pipeline
        .write_operational(b"type=AUDITD_EBPF_STATUS state=healthy\n")
        .unwrap();
    pipeline
        .write_operational(b"type=AUDITD_EBPF_DIAG code=test\n")
        .unwrap();

    assert!(pipeline.queued_records().iter().all(|record| {
        !record
            .bytes
            .windows(marker.len())
            .any(|part| part == marker)
    }));
    assert!(
        !pipeline
            .stdout_bytes()
            .windows(marker.len())
            .any(|part| part == marker)
    );
    assert!(
        !pipeline
            .stderr_bytes()
            .windows(marker.len())
            .any(|part| part == marker)
    );
    assert!(!String::from_utf8_lossy(&pipeline.queued_records()[0].bytes).contains(" a0="));
}
