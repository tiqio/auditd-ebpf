//! 不依赖平台的稳健统计函数。

use serde::{Deserialize, Serialize};

use crate::workloads::StableRng;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ConfidenceInterval {
    pub low: f64,
    pub high: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImprovementKind {
    LowerIsBetter,
    HigherIsBetter,
}

pub fn median(values: &[f64]) -> Option<f64> {
    if values.is_empty() || values.iter().any(|value| !value.is_finite()) {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let middle = sorted.len() / 2;
    Some(if sorted.len().is_multiple_of(2) {
        (sorted[middle - 1] + sorted[middle]) / 2.0
    } else {
        sorted[middle]
    })
}

pub fn mad(values: &[f64]) -> Option<f64> {
    let center = median(values)?;
    let deviations: Vec<_> = values.iter().map(|value| (value - center).abs()).collect();
    median(&deviations)
}

pub fn bootstrap_ci(values: &[f64], seed: u64, iterations: usize) -> Option<ConfidenceInterval> {
    if values.is_empty() || iterations == 0 || values.iter().any(|value| !value.is_finite()) {
        return None;
    }
    let mut rng = StableRng::new(seed);
    let mut medians = Vec::with_capacity(iterations);
    let mut sample = vec![0.0; values.len()];
    for _ in 0..iterations {
        for value in &mut sample {
            *value = values[rng.index(values.len())];
        }
        medians.push(median(&sample)?);
    }
    medians.sort_by(f64::total_cmp);
    let low_index = ((iterations - 1) as f64 * 0.025).floor() as usize;
    let high_index = ((iterations - 1) as f64 * 0.975).ceil() as usize;
    Some(ConfidenceInterval {
        low: medians[low_index],
        high: medians[high_index.min(iterations - 1)],
    })
}

pub fn improvement(baseline: f64, candidate: f64, kind: ImprovementKind) -> Option<f64> {
    if baseline == 0.0 || !baseline.is_finite() || !candidate.is_finite() {
        return None;
    }
    Some(match kind {
        ImprovementKind::LowerIsBetter => (baseline - candidate) / baseline,
        ImprovementKind::HigherIsBetter => (candidate - baseline) / baseline,
    })
}
