pub mod bootstrap;
pub mod fd_table;
pub mod lifecycle;
pub mod model;
pub mod mounts;
pub mod path;

use std::{collections::BTreeMap, path::PathBuf};

use model::{MountNamespaceId, ProcessIdentity, ThreadPathContext};

#[derive(Default)]
pub struct ProcessCache {
    mount_epoch: u64,
    threads: BTreeMap<u32, ThreadPathContext>,
}

impl ProcessCache {
    pub fn insert_thread(
        &mut self,
        process: ProcessIdentity,
        tid: u32,
        root: impl Into<PathBuf>,
        cwd: impl Into<PathBuf>,
        mount_namespace: MountNamespaceId,
    ) {
        self.threads.insert(
            tid,
            ThreadPathContext {
                process,
                tid,
                root: Some(root.into()),
                mount_namespace: Some(mount_namespace),
                mount_epoch: self.mount_epoch,
                cwd: Some(cwd.into()),
                fd_table: BTreeMap::new(),
            },
        );
    }
    pub fn invalidate_mounts(&mut self) {
        self.mount_epoch = self.mount_epoch.wrapping_add(1);
    }
    #[must_use]
    pub const fn mount_epoch(&self) -> u64 {
        self.mount_epoch
    }
    #[must_use]
    pub fn thread(&self, tid: u32) -> Option<&ThreadPathContext> {
        self.threads.get(&tid)
    }
}
