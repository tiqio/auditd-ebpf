use std::{fs, os::unix::fs::MetadataExt, path::PathBuf};

use super::model::{MountNamespaceId, ProcessIdentity, ThreadPathContext};

pub fn current_thread() -> anyhow::Result<ThreadPathContext> {
    let pid = std::process::id();
    let root = fs::read_link(format!("/proc/{pid}/root"))?;
    let cwd = fs::read_link(format!("/proc/{pid}/cwd"))?;
    let ns = fs::metadata(format!("/proc/{pid}/ns/mnt"))?;
    Ok(ThreadPathContext {
        process: ProcessIdentity {
            tgid: pid,
            start_time: 0,
        },
        tid: pid,
        root: Some(root),
        mount_namespace: Some(MountNamespaceId {
            device: ns.dev(),
            inode: ns.ino(),
        }),
        mount_epoch: 0,
        cwd: Some(cwd),
        fd_table: Default::default(),
    })
}

pub fn mountinfo(tid: u32) -> anyhow::Result<String> {
    Ok(fs::read_to_string(PathBuf::from(format!(
        "/proc/{tid}/mountinfo"
    )))?)
}
