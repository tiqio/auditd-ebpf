use auditd_ebpf::process_cache::{
    ProcessCache,
    model::{MountNamespaceId, ProcessIdentity},
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
