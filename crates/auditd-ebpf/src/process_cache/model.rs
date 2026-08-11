use std::{collections::BTreeMap, path::PathBuf};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProcessIdentity {
    pub tgid: u32,
    pub start_time: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MountNamespaceId {
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessAbi {
    B64,
    B32,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssociationConfidence {
    Reliable,
    Stale,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssociationSource {
    ProcBootstrap,
    OpenResult,
    Duplication,
    ExecRefresh,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileAssociation {
    pub path: PathBuf,
    pub confidence: AssociationConfidence,
    pub source: AssociationSource,
    pub mount_epoch: u64,
    pub last_sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileTableState {
    Reliable,
    Stale,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessFileTable {
    pub process: ProcessIdentity,
    pub fds: BTreeMap<i32, FileAssociation>,
    pub state: FileTableState,
    pub refresh_failure: Option<String>,
}

impl ProcessFileTable {
    #[must_use]
    pub fn empty(process: ProcessIdentity) -> Self {
        Self {
            process,
            fds: BTreeMap::new(),
            state: FileTableState::Reliable,
            refresh_failure: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ThreadPathContext {
    pub process: ProcessIdentity,
    pub tid: u32,
    pub root: Option<PathBuf>,
    pub mount_namespace: Option<MountNamespaceId>,
    pub mount_epoch: u64,
    pub cwd: Option<PathBuf>,
    pub abi: ProcessAbi,
    pub mountinfo: String,
}

impl ThreadPathContext {
    #[must_use]
    pub const fn is_current(&self, current_epoch: u64) -> bool {
        self.mount_epoch == current_epoch
    }
}

#[derive(Clone, Debug)]
pub struct BootstrapSnapshot {
    pub thread: ThreadPathContext,
    pub file_table: ProcessFileTable,
}
