use core::mem::{align_of, size_of};

use auditd_ebpf_common::event::{KernelEventHeader, RecordType, SyscallEvent};

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
