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

use fd_table::{associate_open, close, duplicate, mark_stale};
use model::{
    AssociationConfidence, BootstrapSnapshot, FileTableState, MountNamespaceId, ProcessAbi,
    ProcessFileTable, ProcessIdentity, ThreadPathContext,
};
use path::{PathError, normalize_in_boundary};

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CacheError {
    #[error("线程 {0} 不在进程缓存中")]
    MissingThread(u32),
    #[error("线程 {tid} 的 fd {fd} 不在进程缓存中")]
    MissingFd { tid: u32, fd: i32 },
    #[error("线程 {tid} 的进程文件表已失效")]
    StaleFileTable { tid: u32 },
}

#[derive(Default)]
pub struct ProcessCache {
    mount_epoch: u64,
    process_mount_epochs: BTreeMap<ProcessIdentity, u64>,
    threads: BTreeMap<u32, ThreadPathContext>,
    file_tables: BTreeMap<ProcessIdentity, ProcessFileTable>,
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
        self.remove_reused_process(process);
        let mount_epoch = *self
            .process_mount_epochs
            .entry(process)
            .or_insert(self.mount_epoch);
        self.file_tables
            .entry(process)
            .or_insert_with(|| ProcessFileTable::empty(process));
        self.threads.insert(
            tid,
            ThreadPathContext {
                process,
                tid,
                root: Some(root.into()),
                mount_namespace: Some(mount_namespace),
                mount_epoch,
                cwd: Some(cwd.into()),
                abi,
                mountinfo: mountinfo.into(),
            },
        );
    }

    pub fn insert_context(&mut self, mut snapshot: BootstrapSnapshot) {
        let process = snapshot.thread.process;
        self.remove_reused_process(process);
        let mount_epoch = *self
            .process_mount_epochs
            .entry(process)
            .or_insert(self.mount_epoch);
        snapshot.thread.mount_epoch = mount_epoch;
        for association in snapshot.file_table.fds.values_mut() {
            association.mount_epoch = mount_epoch;
        }
        self.file_tables.insert(process, snapshot.file_table);
        self.threads.insert(snapshot.thread.tid, snapshot.thread);
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
        let parent_process = child.process;
        if child_process != parent_process {
            let mut snapshot = self
                .file_tables
                .get(&parent_process)
                .cloned()
                .ok_or(CacheError::StaleFileTable { tid: parent_tid })?;
            snapshot.process = child_process;
            self.file_tables.insert(child_process, snapshot);
            let parent_epoch = self.process_mount_epoch(parent_process);
            self.process_mount_epochs
                .insert(child_process, parent_epoch);
        }
        child.process = child_process;
        child.tid = child_tid;
        child.mount_epoch = self.process_mount_epoch(child_process);
        self.threads.insert(child_tid, child);
        Ok(())
    }

    pub fn exec_thread(&mut self, tid: u32, abi: ProcessAbi) -> Result<(), CacheError> {
        let context = self
            .threads
            .get_mut(&tid)
            .ok_or(CacheError::MissingThread(tid))?;
        context.abi = abi;
        let table = self
            .file_tables
            .get_mut(&context.process)
            .ok_or(CacheError::StaleFileTable { tid })?;
        mark_stale(table, "exec_proc_refresh_failed");
        Ok(())
    }

    pub fn exit_thread(&mut self, tid: u32) {
        let Some(context) = self.threads.remove(&tid) else {
            return;
        };
        if !self
            .threads
            .values()
            .any(|thread| thread.process == context.process)
        {
            self.file_tables.remove(&context.process);
            self.process_mount_epochs.remove(&context.process);
        }
    }

    pub fn open_fd(
        &mut self,
        tid: u32,
        fd: i32,
        path: impl Into<PathBuf>,
    ) -> Result<(), CacheError> {
        let process = self.process_for_tid(tid)?;
        let mount_epoch = self.process_mount_epoch(process);
        associate_open(
            self.file_tables
                .get_mut(&process)
                .ok_or(CacheError::StaleFileTable { tid })?,
            fd,
            path.into(),
            mount_epoch,
            0,
        );
        Ok(())
    }

    pub fn duplicate_fd(&mut self, tid: u32, from: i32, to: i32) -> Result<(), CacheError> {
        let process = self.process_for_tid(tid)?;
        let table = self
            .file_tables
            .get_mut(&process)
            .ok_or(CacheError::StaleFileTable { tid })?;
        if table.state == FileTableState::Stale {
            return Err(CacheError::StaleFileTable { tid });
        }
        if !duplicate(table, from, to, 0) {
            return Err(CacheError::MissingFd { tid, fd: from });
        }
        Ok(())
    }

    pub fn close_fd(&mut self, tid: u32, fd: i32) -> Result<(), CacheError> {
        let process = self.process_for_tid(tid)?;
        close(
            self.file_tables
                .get_mut(&process)
                .ok_or(CacheError::StaleFileTable { tid })?,
            fd,
        );
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
        let path = self.fd_path(tid, fd)?.to_path_buf();
        self.change_cwd(tid, path)
    }

    pub fn resolve_path(
        &self,
        tid: u32,
        dirfd: Option<i32>,
        raw: &Path,
    ) -> Result<PathBuf, PathError> {
        let context = self.threads.get(&tid).ok_or(PathError::MissingThread)?;
        if !context.is_current(self.process_mount_epoch(context.process)) {
            return Err(PathError::StaleMountEpoch);
        }
        let root = context.root.as_deref().ok_or(PathError::MissingBase)?;
        let cwd = context.cwd.as_deref().ok_or(PathError::MissingBase)?;
        let dirfd_path = match dirfd {
            Some(fd) => Some(self.fd_path_for_context(context, fd)?),
            None => None,
        };
        normalize_in_boundary(root, cwd, dirfd_path, raw)
    }

    pub fn resolve_fd_path(&self, tid: u32, fd: i32) -> Result<PathBuf, PathError> {
        self.fd_path(tid, fd)
            .map(Path::to_path_buf)
            .map_err(|error| match error {
                CacheError::MissingThread(_) => PathError::MissingThread,
                CacheError::MissingFd { .. } => PathError::MissingFdAssociation,
                CacheError::StaleFileTable { .. } => PathError::StaleFdAssociation,
            })
    }

    /// 仅失效触发挂载边界变化的进程，避免其他进程执行 mount/setns 等操作时
    /// 清空全机 FD 路径关联。这里仍让同一线程组共享失效状态，因为 FD 表本来就是
    /// 按 `ProcessIdentity` 维护的；随后由触发线程的 `/proc` 快照恢复该进程。
    pub fn invalidate_process_mounts(&mut self, tid: u32) -> Result<(), CacheError> {
        let process = self.process_for_tid(tid)?;
        self.mount_epoch = self.mount_epoch.wrapping_add(1);
        self.process_mount_epochs.insert(process, self.mount_epoch);
        let table = self
            .file_tables
            .get_mut(&process)
            .ok_or(CacheError::StaleFileTable { tid })?;
        mark_stale(table, "mount_epoch_changed");
        Ok(())
    }

    #[must_use]
    pub fn is_thread_mount_current(&self, tid: u32) -> bool {
        self.threads
            .get(&tid)
            .is_some_and(|context| context.is_current(self.process_mount_epoch(context.process)))
    }

    #[must_use]
    pub fn thread(&self, tid: u32) -> Option<&ThreadPathContext> {
        self.threads.get(&tid)
    }

    #[must_use]
    pub fn file_table(&self, process: ProcessIdentity) -> Option<&ProcessFileTable> {
        self.file_tables.get(&process)
    }

    fn process_for_tid(&self, tid: u32) -> Result<ProcessIdentity, CacheError> {
        self.threads
            .get(&tid)
            .map(|context| context.process)
            .ok_or(CacheError::MissingThread(tid))
    }

    fn fd_path(&self, tid: u32, fd: i32) -> Result<&Path, CacheError> {
        let context = self
            .threads
            .get(&tid)
            .ok_or(CacheError::MissingThread(tid))?;
        self.fd_path_for_context(context, fd)
            .map_err(|error| match error {
                PathError::MissingFdAssociation => CacheError::MissingFd { tid, fd },
                _ => CacheError::StaleFileTable { tid },
            })
    }

    fn fd_path_for_context<'a>(
        &'a self,
        context: &ThreadPathContext,
        fd: i32,
    ) -> Result<&'a Path, PathError> {
        let table = self
            .file_tables
            .get(&context.process)
            .ok_or(PathError::MissingFdAssociation)?;
        if table.state == FileTableState::Stale {
            return Err(PathError::StaleFdAssociation);
        }
        let association = table.fds.get(&fd).ok_or(PathError::MissingFdAssociation)?;
        if association.confidence != AssociationConfidence::Reliable
            || association.mount_epoch != self.process_mount_epoch(context.process)
        {
            return Err(PathError::StaleFdAssociation);
        }
        Ok(&association.path)
    }

    fn remove_reused_process(&mut self, incoming: ProcessIdentity) {
        let reused: Vec<_> = self
            .file_tables
            .keys()
            .copied()
            .filter(|identity| identity.tgid == incoming.tgid && *identity != incoming)
            .collect();
        for identity in reused {
            self.file_tables.remove(&identity);
            self.process_mount_epochs.remove(&identity);
            self.threads.retain(|_, thread| thread.process != identity);
        }
    }

    fn process_mount_epoch(&self, process: ProcessIdentity) -> u64 {
        self.process_mount_epochs
            .get(&process)
            .copied()
            .unwrap_or(self.mount_epoch)
    }
}
