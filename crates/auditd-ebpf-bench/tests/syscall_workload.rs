use auditd_ebpf_bench::workloads::syscall::generate;

#[test]
fn 固定seed生成稳定操作序号和期望事件() {
    let first = generate(42, 32);
    let second = generate(42, 32);
    let changed = generate(43, 32);

    assert_eq!(first, second);
    assert_ne!(first, changed);
    assert_eq!(first.len(), 32);
    for (index, operation) in first.iter().enumerate() {
        assert_eq!(operation.sequence, index as u64);
        assert_eq!(operation.id, format!("syscall-{index:08}"));
        assert!(!operation.expected_events.is_empty());
        assert!(
            operation
                .expected_events
                .iter()
                .all(|event| event.operation_id == operation.id)
        );
    }
}
