use auditd_ebpf_bench::correctness::{normalize_auditd, normalize_ebpf};

#[test]
fn 两种实现规范化为同一事件并按event_id去重() {
    let ebpf = [
        "type=AUDITD_EBPF event_id=e-1 operation_id=op-1 key=bench syscall=openat success=yes identity=0 path=/tmp/a",
        "type=AUDITD_EBPF event_id=e-1 operation_id=op-1 key=bench syscall=openat success=yes identity=0 path=/tmp/a",
    ];
    let auditd = [
        "type=SYSCALL msg=audit(1.0:9) operation_id=op-1 key=bench syscall=openat success=yes identity=0",
        "type=PATH msg=audit(1.0:9) name=/tmp/a",
    ];
    let ebpf_result = normalize_ebpf(ebpf).unwrap();
    let auditd_result = normalize_auditd(auditd).unwrap();
    assert_eq!(ebpf_result.events, auditd_result.events);
    assert_eq!(ebpf_result.duplicates, 1);
    assert_eq!(auditd_result.duplicates, 0);
}

#[test]
fn 缺少必填字段时规范化失败() {
    assert!(normalize_ebpf(["type=AUDITD_EBPF event_id=e-1 key=bench"]).is_err());
    assert!(normalize_auditd(["type=PATH msg=audit(1.0:9) name=/tmp/a"]).is_err());
}

#[test]
fn 从comm路径和argv标记推导operation_id() {
    let ebpf = [
        "type=AUDITD_EBPF event_id=e-2 key=bench syscall=execve success=yes identity=0 comm=worker a1=ope000000000001",
    ];
    let auditd = [
        "type=SYSCALL msg=audit(1.0:10) key=bench syscall=execve success=yes identity=0 comm=worker",
        "type=EXECVE msg=audit(1.0:10) argc=2 a0=/usr/bin/true a1=ope000000000001",
    ];
    let ebpf_result = normalize_ebpf(ebpf).unwrap();
    let auditd_result = normalize_auditd(auditd).unwrap();
    assert_eq!(ebpf_result.events, auditd_result.events);
    assert_eq!(
        ebpf_result.events.iter().next().unwrap().operation_id,
        "ope000000000001"
    );
}
