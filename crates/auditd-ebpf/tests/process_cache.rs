use auditd_ebpf::process_cache::{
    ProcessCache,
    model::{MountNamespaceId, ProcessAbi, ProcessIdentity},
};

#[test]
fn mount_epoch_invalidates_thread_contexts() {
    let mut cache = ProcessCache::default();
    cache.insert_thread(
        ProcessIdentity {
            tgid: 1,
            start_time: 10,
        },
        1,
        "/",
        "/tmp",
        MountNamespaceId {
            device: 4,
            inode: 5,
        },
    );
    assert!(cache.thread(1).unwrap().is_current(cache.mount_epoch()));
    cache.invalidate_mounts();
    assert!(!cache.thread(1).unwrap().is_current(cache.mount_epoch()));
}

#[test]
fn lifecycle_and_fd_updates_remain_thread_local() {
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
        cache.thread(11).unwrap().fd_table.get(&4).unwrap(),
        std::path::Path::new("/work/a/file")
    );
    assert!(!cache.thread(12).unwrap().fd_table.contains_key(&4));

    cache.close_fd(11, 4).unwrap();
    cache.exit_thread(12);
    assert!(cache.thread(12).is_none());
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
