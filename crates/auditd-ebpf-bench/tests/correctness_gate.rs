use std::collections::BTreeSet;

use auditd_ebpf_bench::{correctness::evaluate, model::NormalizedEvent};

#[test]
fn 仅百分百覆盖零误报零重复零丢失才有效() {
    let expected = BTreeSet::from([event("op-1"), event("op-2")]);
    let valid = evaluate(&expected, &expected, 0, 0);
    assert!(valid.valid);
    assert_eq!(valid.coverage, 1.0);

    let missing = evaluate(&expected, &BTreeSet::from([event("op-1")]), 0, 1);
    assert!(!missing.valid);
    assert_eq!(missing.missing, 1);
    assert!(
        missing
            .reasons
            .iter()
            .any(|reason| reason.contains("coverage"))
    );

    let mut false_positive = expected.clone();
    false_positive.insert(event("op-3"));
    assert!(!evaluate(&expected, &false_positive, 0, 0).valid);
    assert!(!evaluate(&expected, &expected, 1, 0).valid);
    assert!(!evaluate(&expected, &expected, 0, 1).valid);
}

fn event(operation_id: &str) -> NormalizedEvent {
    NormalizedEvent {
        operation_id: operation_id.into(),
        rule_key: "bench".into(),
        syscall: "openat".into(),
        success: true,
        identity: "0".into(),
        path: Some(format!("/tmp/{operation_id}")),
    }
}
