use core::mem::{align_of, size_of};

use auditd_ebpf_common::{
    event::{
        EVENT_PERMISSION_BITS, KernelEventHeader, PERMISSION_VALID, PermissionFlagsError,
        RecordType, SYSCALL_EVENT_KNOWN_FLAGS, SyscallEvent, permission_from_event_flags,
    },
    permission::PermissionMask,
};

#[test]
fn kernel_header_layout_is_stable() {
    assert_eq!(size_of::<KernelEventHeader>(), 56);
    assert_eq!(align_of::<KernelEventHeader>(), 8);
    assert_eq!(RecordType::Syscall as u16, 1);
}

#[test]
fn syscall_record_is_bounded_and_aligned() {
    assert_eq!(align_of::<SyscallEvent>(), 8);
    assert!(size_of::<SyscallEvent>() <= 512);
}

#[test]
fn schema_one_reuses_flags_without_changing_layout() {
    assert_eq!(PERMISSION_VALID, 0x100);
    assert_eq!(EVENT_PERMISSION_BITS, 0x0f);
    assert_eq!(SYSCALL_EVENT_KNOWN_FLAGS, 0x10f);
    assert_eq!(size_of::<KernelEventHeader>(), 56);
    assert_eq!(size_of::<SyscallEvent>(), 488);

    assert_eq!(
        permission_from_event_flags(PERMISSION_VALID | u32::from(PermissionMask::READ.bits())),
        Ok(Some(PermissionMask::READ))
    );
    assert_eq!(
        permission_from_event_flags(1 << 9),
        Err(PermissionFlagsError::UnknownBits)
    );
}
