//! 报告聚合与固定 seed 运行顺序。

use crate::{
    model::{BENCHMARK_PROTOCOL_VERSION, BenchmarkReport, BenchmarkSample, SampleStatus},
    workloads::StableRng,
};

pub fn randomized_order(seed: u64, count: usize) -> Vec<String> {
    let auditd_count = count / 2;
    let mut order = Vec::with_capacity(count);
    order.extend(std::iter::repeat_n("auditd".to_owned(), auditd_count));
    order.extend(std::iter::repeat_n(
        "auditd-ebpf".to_owned(),
        count - auditd_count,
    ));
    let mut rng = StableRng::new(seed);
    for index in (1..order.len()).rev() {
        let target = rng.index(index + 1);
        order.swap(index, target);
    }
    order
}

pub fn build_report(samples: Vec<BenchmarkSample>) -> BenchmarkReport {
    let raw_artifacts = samples
        .iter()
        .map(|sample| sample.raw_path.clone())
        .collect();
    let valid_samples = samples
        .iter()
        .filter(|sample| matches!(sample.status, SampleStatus::Valid))
        .count();
    BenchmarkReport {
        protocol_version: BENCHMARK_PROTOCOL_VERSION,
        invalid_samples: samples.len() - valid_samples,
        valid_samples,
        raw_artifacts,
        samples,
    }
}
