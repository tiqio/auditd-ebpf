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

#[derive(Clone, Debug)]
pub struct ThreadPathContext {
    pub process: ProcessIdentity,
    pub tid: u32,
    pub root: Option<PathBuf>,
    pub mount_namespace: Option<MountNamespaceId>,
    pub mount_epoch: u64,
    pub cwd: Option<PathBuf>,
    pub fd_table: BTreeMap<i32, PathBuf>,
}

impl ThreadPathContext {
    #[must_use]
    pub const fn is_current(&self, current_epoch: u64) -> bool {
        self.mount_epoch == current_epoch
    }
}
