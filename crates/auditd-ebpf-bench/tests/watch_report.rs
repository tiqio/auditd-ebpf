use std::path::Path;

use auditd_ebpf_bench::{
    model::{BenchmarkMode, SampleStatus, WatchBenchmarkSample, WatchMode},
    report::build_watch_report,
    runner::schedule_watch_comparison,
    workloads::path,
};

#[test]
fn path账本包含目标操作权限和未完成状态() {
    let operations = path::generate(Path::new("/tmp/ddtest-bench"), 5);
    let ledger = path::ledger(&operations);
    assert_eq!(ledger.len(), 5);
    assert!(ledger.iter().all(|entry| !entry.completed));
    assert!(
        ledger
            .iter()
            .all(|entry| entry.target_path.starts_with("/tmp/ddtest-bench"))
    );
    assert!(ledger.iter().all(|entry| !entry.operation_id.is_empty()));
    assert!(
        ledger
            .iter()
            .all(|entry| !entry.expected_permission.is_empty())
    );
}

#[test]
fn watch开关两种模式每侧至少五次且阶段固定() {
    assert!(schedule_watch_comparison(4, 30, 120, 10).is_err());
    let runs = schedule_watch_comparison(5, 30, 120, 10).unwrap();
    assert_eq!(runs.len(), 20);
    assert!(runs.iter().all(|run| run.warmup_seconds == 30));
    assert!(runs.iter().all(|run| run.measurement_seconds == 120));
    assert!(runs.iter().all(|run| run.cooldown_seconds == 10));
}

#[test]
fn 正确性失败使watch性能报告无效() {
    let mut samples = Vec::new();
    for watch in [WatchMode::Disabled, WatchMode::Enabled] {
        for attempt in 0..5 {
            samples.push(sample(watch, attempt));
        }
    }
    assert!(build_watch_report(samples.clone()).performance_claim_allowed);
    samples[0].matched_entries = 9;
    let report = build_watch_report(samples);
    assert!(!report.performance_claim_allowed);
    assert!(
        report
            .reasons
            .iter()
            .any(|reason| reason.contains("正确性失败"))
    );
}

fn sample(watch: WatchMode, attempt: usize) -> WatchBenchmarkSample {
    WatchBenchmarkSample {
        id: format!("{watch:?}-{attempt}"),
        mode: BenchmarkMode::CaptureOnly,
        watch,
        status: SampleStatus::Valid,
        operations_per_second: 10_000.0,
        agent_cpu_percent: 2.0,
        process_rss_kib: 4096,
        p95_latency_us: 100.0,
        lost_events: 0,
        ledger_entries: 10,
        matched_entries: 10,
        raw_path: format!("raw/{attempt}.json"),
    }
}
