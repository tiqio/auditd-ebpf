use core::mem::size_of;

use auditd_ebpf_common::event::{ExecAttempt, ExecResult, ProcessEvent};

#[test]
fn exec_and_process_records_are_fixed_and_bounded() {
    assert!(size_of::<ExecAttempt>() <= 8192);
    assert!(size_of::<ExecResult>() <= 128);
    assert!(size_of::<ProcessEvent>() <= 128);
}
