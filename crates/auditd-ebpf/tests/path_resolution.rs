use std::path::Path;

use auditd_ebpf::process_cache::path::normalize_in_boundary;

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
