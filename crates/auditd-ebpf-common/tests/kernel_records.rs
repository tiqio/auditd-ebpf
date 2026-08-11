use core::mem::size_of;

use auditd_ebpf_common::event::{
    ExecAttempt, ExecResult, PERMISSION_VALID, PermissionFlagsError, ProcessEvent,
    permission_from_event_flags,
};

#[test]
fn exec_and_process_records_are_fixed_and_bounded() {
    assert!(size_of::<ExecAttempt>() <= 8192);
    assert!(size_of::<ExecResult>() <= 128);
    assert!(size_of::<ProcessEvent>() <= 128);
}

#[test]
fn old_object_flags_zero_remain_compatible_but_malformed_flags_are_rejected() {
    assert_eq!(permission_from_event_flags(0), Ok(None));
    assert_eq!(
        permission_from_event_flags(1),
        Err(PermissionFlagsError::PermissionWithoutValid)
    );
    assert_eq!(
        permission_from_event_flags(PERMISSION_VALID),
        Err(PermissionFlagsError::EmptyValidPermission)
    );
}
