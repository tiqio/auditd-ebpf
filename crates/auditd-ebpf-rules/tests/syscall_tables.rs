use auditd_ebpf_rules::{Arch, syscall_number};

#[test]
fn resolves_names_numbers_and_compat_arch() {
    assert_eq!(syscall_number(Arch::B64, "execve"), Some(59));
    assert_eq!(syscall_number(Arch::B32, "execve"), Some(11));
    assert_eq!(syscall_number(Arch::B64, "257"), Some(257));
    assert_eq!(syscall_number(Arch::B64, "not_a_syscall"), None);
}

#[test]
fn resolves_getpid_for_operation_id_workload() {
    assert_eq!(
        auditd_ebpf_rules::syscall_number(Arch::B64, "getpid"),
        Some(39)
    );
    assert_eq!(
        auditd_ebpf_rules::syscall_name(Arch::B64, 39),
        Some("getpid")
    );
}

#[test]
fn resolves_path_workload_syscalls() {
    for (name, number) in [("openat", 257), ("rename", 82), ("unlink", 87)] {
        assert_eq!(
            auditd_ebpf_rules::syscall_number(Arch::B64, name),
            Some(number)
        );
        assert_eq!(
            auditd_ebpf_rules::syscall_name(Arch::B64, number),
            Some(name)
        );
    }
}
