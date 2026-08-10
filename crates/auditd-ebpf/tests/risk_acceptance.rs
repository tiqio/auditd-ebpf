use std::{fs, os::unix::fs::PermissionsExt};

use auditd_ebpf::policy::risk_acceptance::load_trusted;

#[test]
fn loads_root_owned_non_writable_record() {
    let path = std::env::temp_dir().join(format!("auditd-ebpf-risk-{}", std::process::id()));
    fs::write(
        &path,
        r#"
record_version = 1
approval_id = "A-1"
approver = "security"
owner = "audit"
approved_at = "2026-08-10T00:00:00Z"
purpose = "validation"
policy_digest_version = 1
policy_digest = "sha256:test"
"#,
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let record = load_trusted(&path).unwrap();
    assert_eq!(record.approval_id, "A-1");
    fs::remove_file(path).unwrap();
}
