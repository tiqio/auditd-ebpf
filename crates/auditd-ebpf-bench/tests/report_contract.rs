use auditd_ebpf_bench::{
    model::{BenchmarkSample, SampleStatus},
    report::{build_report, randomized_order},
};

#[test]
fn 固定seed运行顺序可复现且两种实现平衡() {
    let first = randomized_order(42, 10);
    assert_eq!(first, randomized_order(42, 10));
    assert_ne!(first, randomized_order(43, 10));
    assert_eq!(
        first
            .iter()
            .filter(|name| name.as_str() == "auditd")
            .count(),
        5
    );
    assert_eq!(
        first
            .iter()
            .filter(|name| name.as_str() == "auditd-ebpf")
            .count(),
        5
    );
}

#[test]
fn 报告保留污染无效和失败样本不得选择隐藏() {
    let samples = vec![
        sample("raw/valid.json", SampleStatus::Valid),
        sample("raw/invalid.json", SampleStatus::Invalid("coverage".into())),
        sample(
            "raw/contaminated.json",
            SampleStatus::Contaminated("load".into()),
        ),
        sample("raw/failed.json", SampleStatus::Failed("runner".into())),
    ];
    let report = build_report(samples.clone());
    assert_eq!(report.samples, samples);
    assert_eq!(report.raw_artifacts.len(), 4);
    assert_eq!(report.invalid_samples, 3);
}

fn sample(path: &str, status: SampleStatus) -> BenchmarkSample {
    BenchmarkSample {
        id: path.into(),
        raw_path: path.into(),
        status,
        operations_per_second: 1.0,
        agent_cpu_percent: 1.0,
        p95_latency_us: 1.0,
    }
}
