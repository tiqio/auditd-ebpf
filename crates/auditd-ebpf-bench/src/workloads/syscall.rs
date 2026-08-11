//! syscall 密集型 workload。

use crate::model::{NormalizedEvent, WorkloadOperation};

use super::StableRng;

const SYSCALLS: [&str; 6] = ["getpid", "openat", "close", "read", "write", "fstat"];

pub fn generate(seed: u64, count: usize) -> Vec<WorkloadOperation> {
    let mut rng = StableRng::new(seed);
    (0..count)
        .map(|index| {
            let id = format!("syscall-{index:08}");
            let syscall = SYSCALLS[rng.index(SYSCALLS.len())].to_owned();
            WorkloadOperation {
                sequence: index as u64,
                id: id.clone(),
                kind: syscall.clone(),
                expected_events: vec![NormalizedEvent {
                    operation_id: id,
                    rule_key: "bench-syscall".into(),
                    syscall,
                    success: true,
                    identity: "0".into(),
                    path: None,
                }],
            }
        })
        .collect()
}
