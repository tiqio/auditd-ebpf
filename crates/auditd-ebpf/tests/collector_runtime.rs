use std::{
    mem::size_of,
    time::{Duration, Instant},
};

use auditd_ebpf::collector::runtime::{CollectedRecord, CollectorRuntime};
use auditd_ebpf_common::{
    SCHEMA_VERSION,
    event::{ExecAttempt, ExecResult, KernelEventHeader, RecordType},
};

fn header(record_type: RecordType, len: usize) -> KernelEventHeader {
    KernelEventHeader {
        schema_version: SCHEMA_VERSION,
        record_type: record_type as u16,
        record_len: len as u32,
        cpu: 0,
        flags: 0,
        ktime_ns: 1,
        sequence: 1,
        rule_version: 7,
        pid_tgid: 9,
        process_start_ns: 10,
    }
}

fn bytes<T>(value: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts((value as *const T).cast(), size_of::<T>()) }
}

#[test]
fn correlates_exec_and_releases_argv_after_result() {
    let mut attempt = ExecAttempt {
        header: header(RecordType::ExecAttempt, size_of::<ExecAttempt>()),
        attempt_id: 3,
        argc_observed: 2,
        argc_captured: 2,
        argv_flags: 0,
        argv_offsets: [0; 33],
        argv_bytes: [0; 6144],
    };
    attempt.argv_offsets[1] = 3;
    attempt.argv_offsets[2] = 6;
    attempt.argv_bytes[..6].copy_from_slice(b"cmdarg");
    let result = ExecResult {
        header: header(RecordType::ExecResult, size_of::<ExecResult>()),
        attempt_id: 3,
        result: 0,
        new_comm: [0; 16],
    };
    let mut runtime = CollectorRuntime::new(8, Duration::from_secs(1));
    runtime.accept(bytes(&attempt)).unwrap();
    runtime.accept(bytes(&result)).unwrap();
    let output = runtime.take_output();
    let CollectedRecord::Exec(exec) = &output[0] else {
        panic!("应得到关联 exec")
    };
    assert_eq!(exec.argv, [b"cmd".to_vec(), b"arg".to_vec()]);
    assert_eq!(exec.argv_flags, 0);
    runtime.accept(bytes(&result)).unwrap();
    assert!(matches!(runtime.take_output()[0], CollectedRecord::Gap(_)));
}

#[test]
fn missing_result_expires_to_gap_and_releases_argv() {
    let attempt = ExecAttempt {
        header: header(RecordType::ExecAttempt, size_of::<ExecAttempt>()),
        attempt_id: 4,
        argc_observed: 1,
        argc_captured: 1,
        argv_flags: 0,
        argv_offsets: [0; 33],
        argv_bytes: [0; 6144],
    };
    let mut runtime = CollectorRuntime::new(8, Duration::ZERO);
    runtime.accept(bytes(&attempt)).unwrap();
    runtime.expire(Instant::now());
    assert!(matches!(runtime.take_output()[0], CollectedRecord::Gap(_)));
}
