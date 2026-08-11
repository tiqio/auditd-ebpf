use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};

use super::{
    ProcessCache,
    model::{MountNamespaceId, ProcessAbi, ProcessIdentity, ThreadPathContext},
};

/// 扫描所有可见 `/proc/<tgid>/task/<tid>`。进程可能在扫描期间退出，单个条目失败时跳过；
/// 调用方仍会通过后续 fork/exec/exit 事件收敛缓存。
pub fn scan_proc() -> anyhow::Result<ProcessCache> {
    let mut cache = ProcessCache::default();
    for process_entry in fs::read_dir("/proc").context("无法读取 /proc")? {
        let Ok(process_entry) = process_entry else {
            continue;
        };
        let Some(tgid) = parse_numeric_name(&process_entry.file_name()) else {
            continue;
        };
        let task_dir = process_entry.path().join("task");
        let Ok(tasks) = fs::read_dir(task_dir) else {
            continue;
        };
        for task_entry in tasks.flatten() {
            let Some(tid) = parse_numeric_name(&task_entry.file_name()) else {
                continue;
            };
            if let Ok(context) = read_thread(tgid, tid) {
                cache.insert_context(context);
            }
        }
    }
    Ok(cache)
}

pub fn current_thread() -> anyhow::Result<ThreadPathContext> {
    let tid = std::process::id();
    read_thread(tid, tid)
}

pub fn read_thread(tgid: u32, tid: u32) -> anyhow::Result<ThreadPathContext> {
    let proc_tid = PathBuf::from(format!("/proc/{tgid}/task/{tid}"));
    let root_host = fs::read_link(proc_tid.join("root"))?;
    let cwd_host = fs::read_link(proc_tid.join("cwd"))?;
    let root = PathBuf::from("/");
    let cwd = namespace_path(&root_host, &cwd_host);
    let ns = fs::metadata(proc_tid.join("ns/mnt"))?;
    let start_time = parse_start_time(&fs::read_to_string(proc_tid.join("stat"))?)?;
    let mountinfo = fs::read_to_string(proc_tid.join("mountinfo"))?;
    let abi = read_elf_abi(&proc_tid.join("exe")).unwrap_or(ProcessAbi::Unknown);
    let mut fd_table: BTreeMap<i32, PathBuf> = BTreeMap::new();
    if let Ok(entries) = fs::read_dir(proc_tid.join("fd")) {
        for entry in entries.flatten() {
            let Ok(fd) = entry.file_name().to_string_lossy().parse::<i32>() else {
                continue;
            };
            if let Ok(target) = fs::read_link(entry.path())
                && target.is_absolute()
            {
                fd_table.insert(fd, namespace_path(&root_host, &target));
            }
        }
    }
    Ok(ThreadPathContext {
        process: ProcessIdentity { tgid, start_time },
        tid,
        root: Some(root),
        mount_namespace: Some(MountNamespaceId {
            device: ns.dev(),
            inode: ns.ino(),
        }),
        mount_epoch: 0,
        cwd: Some(cwd),
        fd_table,
        abi,
        mountinfo,
    })
}

fn namespace_path(root: &Path, host_path: &Path) -> PathBuf {
    host_path
        .strip_prefix(root)
        .map(|relative| Path::new("/").join(relative))
        .unwrap_or_else(|_| host_path.to_path_buf())
}

fn parse_numeric_name(name: &std::ffi::OsStr) -> Option<u32> {
    name.to_string_lossy().parse().ok()
}

fn parse_start_time(stat: &str) -> anyhow::Result<u64> {
    let close = stat.rfind(')').context("/proc stat 缺少 comm 结束符")?;
    let fields: Vec<_> = stat[close + 1..].split_whitespace().collect();
    fields
        .get(19)
        .context("/proc stat 缺少 starttime")?
        .parse()
        .context("/proc stat starttime 非法")
}

fn read_elf_abi(exe_link: &Path) -> anyhow::Result<ProcessAbi> {
    let mut file = File::open(exe_link)?;
    let mut ident = [0_u8; 5];
    file.read_exact(&mut ident)?;
    if &ident[..4] != b"\x7fELF" {
        bail!("目标不是 ELF")
    }
    Ok(match ident[4] {
        1 => ProcessAbi::B32,
        2 => ProcessAbi::B64,
        _ => ProcessAbi::Unknown,
    })
}

pub fn mountinfo(tid: u32) -> anyhow::Result<String> {
    Ok(fs::read_to_string(format!("/proc/{tid}/mountinfo"))?)
}
