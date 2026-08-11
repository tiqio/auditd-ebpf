use auditd_ebpf_bench::statistics::{ImprovementKind, bootstrap_ci, improvement, mad, median};

#[test]
fn 中位数mad和bootstrap区间稳定() {
    let values = [1.0, 2.0, 3.0, 4.0, 100.0];
    assert_eq!(median(&values).unwrap(), 3.0);
    assert_eq!(mad(&values).unwrap(), 1.0);
    let interval = bootstrap_ci(&values, 42, 2000).unwrap();
    assert!(interval.low <= 3.0 && interval.high >= 3.0);
    assert_eq!(interval, bootstrap_ci(&values, 42, 2000).unwrap());
}

#[test]
fn cpu吞吐和延迟改善公式及阈值边界正确() {
    assert!(
        (improvement(100.0, 80.0, ImprovementKind::LowerIsBetter).unwrap() - 0.2).abs() < 1e-12
    );
    assert!(
        (improvement(100.0, 110.0, ImprovementKind::HigherIsBetter).unwrap() - 0.1).abs() < 1e-12
    );
    assert_eq!(improvement(0.0, 1.0, ImprovementKind::HigherIsBetter), None);
}
