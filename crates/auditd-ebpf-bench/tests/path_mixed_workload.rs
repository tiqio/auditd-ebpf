use std::path::Path;

use auditd_ebpf_bench::workloads::{mixed, path};

#[test]
fn path覆盖绝对cwd_dirfd_rename和unlink() {
    let operations = path::generate(Path::new("/tmp/auditd-ebpf-bench"), 10);
    let names: Vec<_> = operations
        .iter()
        .map(|operation| operation.kind.as_str())
        .collect();
    for required in ["absolute", "cwd", "dirfd", "rename", "unlink"] {
        assert!(names.contains(&required));
    }
    assert!(
        operations.iter().all(
            |operation| operation.expected_events.iter().all(|event| event
                .path
                .as_deref()
                .is_some_and(|path| path.starts_with("/tmp/auditd-ebpf-bench")))
        )
    );
}

#[test]
fn mixed固定比例包含exec_syscall和path期望集合() {
    let operations = mixed::generate(7, Path::new("/tmp/mixed"), 20);
    assert_eq!(operations.len(), 20);
    assert_eq!(operations.iter().filter(|op| op.kind == "exec").count(), 4);
    assert_eq!(operations.iter().filter(|op| op.kind == "path").count(), 6);
    assert_eq!(
        operations.iter().filter(|op| op.kind == "syscall").count(),
        10
    );
    assert!(
        operations
            .iter()
            .all(|operation| !operation.expected_events.is_empty())
    );
}
