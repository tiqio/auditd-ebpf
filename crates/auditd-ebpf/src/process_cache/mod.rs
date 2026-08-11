pub mod bootstrap;
pub mod fd_table;
pub mod lifecycle;
pub mod model;
pub mod mounts;
pub mod path;

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use thiserror::Error;

use model::{MountNamespaceId, ProcessAbi, ProcessIdentity, ThreadPathContext};
use path::{PathError, normalize_in_boundary};

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CacheError {
    #[error("线程 {0} 不在进程缓存中")]
    MissingThread(u32),
    #[error("线程 {tid} 的 fd {fd} 不在进程缓存中")]
    MissingFd { tid: u32, fd: i32 },
}

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
        self.insert_thread_with_abi(
            process,
            tid,
            root,
            cwd,
            mount_namespace,
            ProcessAbi::Unknown,
            String::new(),
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_thread_with_abi(
        &mut self,
        process: ProcessIdentity,
        tid: u32,
        root: impl Into<PathBuf>,
        cwd: impl Into<PathBuf>,
        mount_namespace: MountNamespaceId,
        abi: ProcessAbi,
        mountinfo: impl Into<String>,
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
                abi,
                mountinfo: mountinfo.into(),
            },
        );
    }

    pub fn insert_context(&mut self, mut context: ThreadPathContext) {
        context.mount_epoch = self.mount_epoch;
        self.threads.insert(context.tid, context);
    }

    pub fn fork_thread(
        &mut self,
        parent_tid: u32,
        child_process: ProcessIdentity,
        child_tid: u32,
    ) -> Result<(), CacheError> {
        let mut child = self
            .threads
            .get(&parent_tid)
            .cloned()
            .ok_or(CacheError::MissingThread(parent_tid))?;
        child.process = child_process;
        child.tid = child_tid;
        child.mount_epoch = self.mount_epoch;
        self.threads.insert(child_tid, child);
        Ok(())
    }

    pub fn exec_thread(&mut self, tid: u32, abi: ProcessAbi) -> Result<(), CacheError> {
        let context = self
            .threads
            .get_mut(&tid)
            .ok_or(CacheError::MissingThread(tid))?;
        context.abi = abi;
        context.fd_table.clear();
        Ok(())
    }

    pub fn exit_thread(&mut self, tid: u32) {
        self.threads.remove(&tid);
    }

    pub fn open_fd(
        &mut self,
        tid: u32,
        fd: i32,
        path: impl Into<PathBuf>,
    ) -> Result<(), CacheError> {
        self.threads
            .get_mut(&tid)
            .ok_or(CacheError::MissingThread(tid))?
            .fd_table
            .insert(fd, path.into());
        Ok(())
    }

    pub fn duplicate_fd(&mut self, tid: u32, from: i32, to: i32) -> Result<(), CacheError> {
        let context = self
            .threads
            .get_mut(&tid)
            .ok_or(CacheError::MissingThread(tid))?;
        let path = context
            .fd_table
            .get(&from)
            .cloned()
            .ok_or(CacheError::MissingFd { tid, fd: from })?;
        context.fd_table.insert(to, path);
        Ok(())
    }

    pub fn close_fd(&mut self, tid: u32, fd: i32) -> Result<(), CacheError> {
        self.threads
            .get_mut(&tid)
            .ok_or(CacheError::MissingThread(tid))?
            .fd_table
            .remove(&fd);
        Ok(())
    }

    pub fn change_cwd(&mut self, tid: u32, cwd: impl Into<PathBuf>) -> Result<(), CacheError> {
        self.threads
            .get_mut(&tid)
            .ok_or(CacheError::MissingThread(tid))?
            .cwd = Some(cwd.into());
        Ok(())
    }

    pub fn fchdir(&mut self, tid: u32, fd: i32) -> Result<(), CacheError> {
        let path = self
            .threads
            .get(&tid)
            .ok_or(CacheError::MissingThread(tid))?
            .fd_table
            .get(&fd)
            .cloned()
            .ok_or(CacheError::MissingFd { tid, fd })?;
        self.change_cwd(tid, path)
    }

    pub fn resolve_path(
        &self,
        tid: u32,
        dirfd: Option<i32>,
        raw: &Path,
    ) -> Result<PathBuf, PathError> {
        let context = self.threads.get(&tid).ok_or(PathError::MissingThread)?;
        if !context.is_current(self.mount_epoch) {
            return Err(PathError::StaleMountEpoch);
        }
        let root = context.root.as_deref().ok_or(PathError::MissingBase)?;
        let cwd = context.cwd.as_deref().ok_or(PathError::MissingBase)?;
        let dirfd_path = match dirfd {
            Some(fd) => Some(
                context
                    .fd_table
                    .get(&fd)
                    .ok_or(PathError::MissingBase)?
                    .as_path(),
            ),
            None => None,
        };
        normalize_in_boundary(root, cwd, dirfd_path, raw)
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
