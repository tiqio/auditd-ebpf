//! 文件路径 workload，仅在调用者提供的专用临时目录内构造路径。

use std::path::Path;

use crate::model::{NormalizedEvent, PathLedgerEntry, WorkloadOperation};

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

/// 从确定性操作生成预期账本。完成状态必须在执行器确认 syscall 返回后再更新。
pub fn ledger(operations: &[WorkloadOperation]) -> Vec<PathLedgerEntry> {
    operations
        .iter()
        .flat_map(|operation| {
            operation
                .expected_events
                .iter()
                .map(|event| PathLedgerEntry {
                    target_path: event.path.clone().unwrap_or_else(|| "?".into()),
                    operation_id: operation.id.clone(),
                    expected_permission: match event.syscall.as_str() {
                        "openat" => "rw",
                        "renameat2" | "unlinkat" => "w",
                        _ => "?",
                    }
                    .into(),
                    completed: false,
                })
        })
        .collect()
}
