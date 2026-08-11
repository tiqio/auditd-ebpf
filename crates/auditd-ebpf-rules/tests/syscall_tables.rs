use auditd_ebpf_rules::{Arch, syscall_number};

#[test]
fn resolves_names_numbers_and_compat_arch() {
    assert_eq!(syscall_number(Arch::B64, "execve"), Some(59));
    assert_eq!(syscall_number(Arch::B32, "execve"), Some(11));
    assert_eq!(syscall_number(Arch::B64, "257"), Some(257));
    assert_eq!(syscall_number(Arch::B64, "not_a_syscall"), None);
}
