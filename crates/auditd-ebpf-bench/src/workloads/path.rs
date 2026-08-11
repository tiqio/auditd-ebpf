//! 文件路径 workload，仅在调用者提供的专用临时目录内构造路径。

use std::path::Path;

use crate::model::{NormalizedEvent, WorkloadOperation};

const KINDS: [&str; 5] = ["absolute", "cwd", "dirfd", "rename", "unlink"];

pub fn generate(root: &Path, count: usize) -> Vec<WorkloadOperation> {
    (0..count)
        .map(|index| {
            let id = format!("path-{index:08}");
            let kind = KINDS[index % KINDS.len()];
            let path = root.join(format!("{kind}-{index:08}"));
            WorkloadOperation {
                sequence: index as u64,
                id: id.clone(),
                kind: kind.into(),
                expected_events: vec![NormalizedEvent {
                    operation_id: id,
                    rule_key: "bench-path".into(),
                    syscall: match kind {
                        "rename" => "renameat2",
                        "unlink" => "unlinkat",
                        _ => "openat",
                    }
                    .into(),
                    success: true,
                    identity: "0".into(),
                    path: Some(path.to_string_lossy().into_owned()),
                }],
            }
        })
        .collect()
}
