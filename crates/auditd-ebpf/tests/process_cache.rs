use auditd_ebpf::process_cache::{
    ProcessCache,
    model::{MountNamespaceId, ProcessAbi, ProcessIdentity},
};

#[test]
fn mount_epoch_only_invalidates_the_triggering_process() {
    let mut cache = ProcessCache::default();
    let changed = ProcessIdentity {
        tgid: 1,
        start_time: 10,
    };
    let unrelated = ProcessIdentity {
        tgid: 2,
        start_time: 20,
    };
    let namespace = MountNamespaceId {
        device: 4,
        inode: 5,
    };
    cache.insert_thread(changed, 1, "/", "/tmp", namespace);
    cache.insert_thread(
        unrelated,
        2,
        "/",
        "/var",
        MountNamespaceId {
            device: 6,
            inode: 7,
        },
    );
    cache.open_fd(1, 3, "/tmp/changed").unwrap();
    cache.open_fd(2, 4, "/var/unrelated").unwrap();

    assert!(cache.is_thread_mount_current(1));
    assert!(cache.is_thread_mount_current(2));
    cache.invalidate_process_mounts(1).unwrap();

    assert!(!cache.is_thread_mount_current(1));
    assert!(cache.is_thread_mount_current(2));
    assert!(cache.resolve_fd_path(1, 3).is_err());
    assert_eq!(
        cache.resolve_fd_path(2, 4).unwrap(),
        std::path::Path::new("/var/unrelated")
    );
    assert_eq!(
        cache
            .file_table(changed)
            .unwrap()
            .refresh_failure
            .as_deref(),
        Some("mount_epoch_changed")
    );
    assert!(
        cache
            .file_table(unrelated)
            .unwrap()
            .refresh_failure
            .is_none()
    );
}

#[test]
fn mount_invalidation_applies_to_the_shared_process_table() {
    let mut cache = ProcessCache::default();
    let process = ProcessIdentity {
        tgid: 10,
        start_time: 30,
    };
    cache.insert_thread(
        process,
        1,
        "/",
        "/tmp",
        MountNamespaceId {
            device: 4,
            inode: 5,
        },
    );
    cache.fork_thread(1, process, 2).unwrap();
    cache.invalidate_process_mounts(2).unwrap();
    assert!(!cache.is_thread_mount_current(1));
    assert!(!cache.is_thread_mount_current(2));
}

#[test]
fn same_tgid_threads_share_fd_updates_and_close() {
    let mut cache = ProcessCache::default();
    let process = ProcessIdentity {
        tgid: 10,
        start_time: 20,
    };
    cache.insert_thread_with_abi(
        process,
        11,
        "/",
        "/work/a",
        MountNamespaceId {
            device: 1,
            inode: 2,
        },
        ProcessAbi::B64,
        "",
    );
    cache.fork_thread(11, process, 12).unwrap();
    cache.open_fd(11, 3, "/work/a/file").unwrap();
    cache.duplicate_fd(11, 3, 4).unwrap();
    cache.change_cwd(12, "/work/b").unwrap();

    assert_eq!(
        cache.thread(11).unwrap().cwd.as_deref().unwrap(),
        std::path::Path::new("/work/a")
    );
    assert_eq!(
        cache.thread(12).unwrap().cwd.as_deref().unwrap(),
        std::path::Path::new("/work/b")
    );
    assert_eq!(
        cache.resolve_fd_path(12, 4).unwrap(),
        std::path::Path::new("/work/a/file")
    );

    cache.close_fd(12, 4).unwrap();
    assert!(cache.resolve_fd_path(11, 4).is_err());
    cache.exit_thread(12);
    assert!(cache.thread(12).is_none());
}

#[test]
fn forked_process_gets_snapshot_and_fd_reuse_overwrites_old_path() {
    let mut cache = ProcessCache::default();
    let parent = ProcessIdentity {
        tgid: 50,
        start_time: 100,
    };
    let child = ProcessIdentity {
        tgid: 60,
        start_time: 200,
    };
    let namespace = MountNamespaceId {
        device: 1,
        inode: 2,
    };
    cache.insert_thread(parent, 51, "/", "/work", namespace);
    cache.open_fd(51, 3, "/work/original").unwrap();
    cache.fork_thread(51, child, 61).unwrap();

    cache.open_fd(51, 3, "/work/reused").unwrap();
    assert_eq!(
        cache.resolve_fd_path(51, 3).unwrap(),
        std::path::Path::new("/work/reused")
    );
    assert_eq!(
        cache.resolve_fd_path(61, 3).unwrap(),
        std::path::Path::new("/work/original")
    );
}

#[test]
fn exec_refresh_failure_marks_shared_table_stale() {
    let mut cache = ProcessCache::default();
    let process = ProcessIdentity {
        tgid: 70,
        start_time: 300,
    };
    cache.insert_thread(
        process,
        71,
        "/",
        "/work",
        MountNamespaceId {
            device: 1,
            inode: 2,
        },
    );
    cache.open_fd(71, 4, "/work/file").unwrap();
    cache.exec_thread(71, ProcessAbi::B64).unwrap();

    assert!(cache.resolve_fd_path(71, 4).is_err());
    assert_eq!(
        cache
            .file_table(process)
            .unwrap()
            .refresh_failure
            .as_deref(),
        Some("exec_proc_refresh_failed")
    );

    cache.open_fd(71, 5, "/work/after-exec").unwrap();
    assert!(cache.resolve_fd_path(71, 4).is_err());
    assert_eq!(
        cache.resolve_fd_path(71, 5).unwrap(),
        std::path::Path::new("/work/after-exec")
    );
    assert!(cache.file_table(process).unwrap().refresh_failure.is_none());
}

#[test]
fn bootstrap_discovers_the_current_thread_without_argv_storage() {
    let cache = auditd_ebpf::process_cache::bootstrap::scan_proc().unwrap();
    let tid = std::process::id();
    let current = cache.thread(tid).expect("必须发现当前线程");
    assert_eq!(current.process.tgid, tid);
    assert!(current.process.start_time > 0);
    assert!(current.root.is_some());
    assert!(current.mount_namespace.is_some());
}

#[test]
fn clone_inherits_b32_but_pid_reuse_replaces_old_identity() {
    let mut cache = ProcessCache::default();
    let old_process = ProcessIdentity {
        tgid: 40,
        start_time: 100,
    };
    let namespace = MountNamespaceId {
        device: 7,
        inode: 8,
    };
    cache.insert_thread_with_abi(
        old_process,
        40,
        "/",
        "/old",
        namespace,
        ProcessAbi::B32,
        "old mountinfo",
    );
    cache
        .fork_thread(40, old_process, 41)
        .expect("clone 线程应继承上下文");
    assert_eq!(cache.thread(41).unwrap().abi, ProcessAbi::B32);
    assert_eq!(cache.thread(41).unwrap().process, old_process);

    cache.exit_thread(40);
    let reused_process = ProcessIdentity {
        tgid: 40,
        start_time: 200,
    };
    cache.insert_thread_with_abi(
        reused_process,
        40,
        "/",
        "/new",
        namespace,
        ProcessAbi::B64,
        "new mountinfo",
    );
    let reused = cache.thread(40).unwrap();
    assert_eq!(reused.process, reused_process);
    assert_eq!(reused.abi, ProcessAbi::B64);
    assert_eq!(reused.cwd.as_deref().unwrap(), std::path::Path::new("/new"));

    cache.exec_thread(40, ProcessAbi::B64).unwrap();
    cache.exit_thread(41);
    assert!(cache.thread(41).is_none());
}
