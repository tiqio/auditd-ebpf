use std::path::{Path, PathBuf};

use super::model::{
    AssociationConfidence, AssociationSource, FileAssociation, FileTableState, ProcessFileTable,
};

pub fn associate_open(
    table: &mut ProcessFileTable,
    fd: i32,
    path: PathBuf,
    mount_epoch: u64,
    sequence: u64,
) {
    // 成功 open 复用已有 fd 时必须覆盖旧条目；保留旧路径会造成严重误报。
    table.fds.insert(
        fd,
        FileAssociation {
            path,
            confidence: AssociationConfidence::Reliable,
            source: AssociationSource::OpenResult,
            mount_epoch,
            last_sequence: sequence,
        },
    );
}

pub fn associate_bootstrap(table: &mut ProcessFileTable, fd: i32, path: &Path, mount_epoch: u64) {
    table.fds.insert(
        fd,
        FileAssociation {
            path: path.to_path_buf(),
            confidence: AssociationConfidence::Reliable,
            source: AssociationSource::ProcBootstrap,
            mount_epoch,
            last_sequence: 0,
        },
    );
}

pub fn duplicate(table: &mut ProcessFileTable, from: i32, to: i32, sequence: u64) -> bool {
    let Some(mut association) = table.fds.get(&from).cloned() else {
        return false;
    };
    association.source = AssociationSource::Duplication;
    association.last_sequence = sequence;
    table.fds.insert(to, association);
    true
}

pub fn close(table: &mut ProcessFileTable, fd: i32) {
    table.fds.remove(&fd);
}

pub fn mark_stale(table: &mut ProcessFileTable, reason: impl Into<String>) {
    table.state = FileTableState::Stale;
    table.refresh_failure = Some(reason.into());
    for association in table.fds.values_mut() {
        association.confidence = AssociationConfidence::Stale;
    }
}
