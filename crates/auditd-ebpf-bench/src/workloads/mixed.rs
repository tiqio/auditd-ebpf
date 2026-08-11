//! mixed workload：50% syscall、30% path、20% exec。

use std::path::Path;

use crate::model::{NormalizedEvent, WorkloadOperation};

use super::{StableRng, path, syscall};

pub fn generate(seed: u64, root: &Path, count: usize) -> Vec<WorkloadOperation> {
    let syscall_count = count / 2;
    let path_count = count.saturating_mul(3) / 10;
    let exec_count = count - syscall_count - path_count;
    let mut operations = Vec::with_capacity(count);

    for mut operation in syscall::generate(seed, syscall_count) {
        operation.kind = "syscall".into();
        operations.push(operation);
    }
    for mut operation in path::generate(root, path_count) {
        operation.kind = "path".into();
        operations.push(operation);
    }
    for index in 0..exec_count {
        let id = format!("exec-{index:08}");
        operations.push(WorkloadOperation {
            sequence: 0,
            id: id.clone(),
            kind: "exec".into(),
            expected_events: vec![NormalizedEvent {
                operation_id: id,
                rule_key: "bench-exec".into(),
                syscall: "execve".into(),
                success: true,
                identity: "0".into(),
                path: Some("/usr/bin/true".into()),
            }],
        });
    }

    let mut rng = StableRng::new(seed ^ 0x6d69_7865_64);
    for index in (1..operations.len()).rev() {
        let target = rng.index(index + 1);
        operations.swap(index, target);
    }
    for (index, operation) in operations.iter_mut().enumerate() {
        operation.sequence = index as u64;
    }
    operations
}
