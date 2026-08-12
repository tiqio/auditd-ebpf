use std::{fs::File, os::fd::AsRawFd, path::Path};

use auditd_ebpf::process_cache::{
    ProcessCache, bootstrap,
    lifecycle::on_mount_boundary_change,
    model::{MountNamespaceId, ProcessIdentity},
    path::{PathError, normalize_in_boundary},
};

#[test]
fn 单fd_proc回读使用当前进程namespace路径() {
    let file = File::open("/dev/null").unwrap();
    let pid = std::process::id();
    assert_eq!(
        bootstrap::read_fd_path(pid, pid, file.as_raw_fd()).unwrap(),
        Path::new("/dev/null")
    );
}

#[test]
fn resolves_absolute_cwd_and_dirfd_without_inode_claims() {
    assert_eq!(
        normalize_in_boundary(
            Path::new("/root"),
            Path::new("/work"),
            None,
            Path::new("file")
        )
        .unwrap(),
        Path::new("/work/file")
    );
    assert_eq!(
        normalize_in_boundary(
            Path::new("/root"),
            Path::new("/work"),
            Some(Path::new("/base")),
            Path::new("child")
        )
        .unwrap(),
        Path::new("/base/child")
    );
    assert!(
        normalize_in_boundary(
            Path::new("/root"),
            Path::new("/work"),
            None,
            Path::new("../escape")
        )
        .is_err()
    );
}

#[test]
fn every_successful_namespace_boundary_change_invalidates_only_triggering_process() {
    for syscall in [
        "mount",
        "umount2",
        "move_mount",
        "mount_setattr",
        "chroot",
        "pivot_root",
        "setns",
        "unshare",
    ] {
        let mut cache = ProcessCache::default();
        let changed = ProcessIdentity {
            tgid: 7,
            start_time: 9,
        };
        let unrelated = ProcessIdentity {
            tgid: 17,
            start_time: 19,
        };
        let namespace = MountNamespaceId {
            device: 1,
            inode: 2,
        };
        cache.insert_thread(changed, 8, "/", "/work", namespace);
        cache.insert_thread(unrelated, 18, "/", "/other", namespace);
        cache.open_fd(8, 3, "/work/file").unwrap();
        cache.open_fd(18, 4, "/other/file").unwrap();

        on_mount_boundary_change(&mut cache, 8, syscall, false);
        assert!(
            cache.is_thread_mount_current(8),
            "失败的 {syscall} 不应失效"
        );
        on_mount_boundary_change(&mut cache, 8, syscall, true);
        assert!(
            !cache.is_thread_mount_current(8),
            "成功的 {syscall} 必须失效"
        );
        assert!(
            cache.is_thread_mount_current(18),
            "{syscall} 不应误伤其他进程"
        );
        assert_eq!(
            cache.resolve_fd_path(18, 4).unwrap(),
            Path::new("/other/file")
        );
    }
}

#[test]
fn stale_or_missing_context_produces_an_explicit_gap_reason() {
    let mut cache = ProcessCache::default();
    cache.insert_thread(
        ProcessIdentity {
            tgid: 7,
            start_time: 9,
        },
        8,
        "/",
        "/work",
        MountNamespaceId {
            device: 1,
            inode: 2,
        },
    );
    assert_eq!(
        cache.resolve_path(8, None, Path::new("file")).unwrap(),
        Path::new("/work/file")
    );
    cache.invalidate_process_mounts(8).unwrap();
    assert_eq!(
        cache.resolve_path(8, None, Path::new("file")),
        Err(PathError::StaleMountEpoch)
    );
    assert_eq!(
        cache.resolve_path(99, None, Path::new("file")),
        Err(PathError::MissingThread)
    );
}

#[test]
fn fd_only_resolution_uses_process_shared_table_and_rejects_stale_entries() {
    let mut cache = ProcessCache::default();
    let process = ProcessIdentity {
        tgid: 20,
        start_time: 30,
    };
    let namespace = MountNamespaceId {
        device: 1,
        inode: 2,
    };
    cache.insert_thread(process, 21, "/", "/work", namespace);
    cache.fork_thread(21, process, 22).unwrap();
    cache.open_fd(21, 7, "/work/fd-target").unwrap();

    assert_eq!(
        cache.resolve_fd_path(22, 7).unwrap(),
        Path::new("/work/fd-target")
    );
    cache.invalidate_process_mounts(21).unwrap();
    assert_eq!(
        cache.resolve_fd_path(22, 7),
        Err(PathError::StaleFdAssociation)
    );
}
