use std::path::Path;

use auditd_ebpf::process_cache::{
    ProcessCache,
    model::{MountNamespaceId, ProcessIdentity},
    path::{PathError, normalize_in_boundary},
};

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
    cache.invalidate_mounts();
    assert_eq!(
        cache.resolve_path(8, None, Path::new("file")),
        Err(PathError::StaleMountEpoch)
    );
    assert_eq!(
        cache.resolve_path(99, None, Path::new("file")),
        Err(PathError::MissingThread)
    );
}
