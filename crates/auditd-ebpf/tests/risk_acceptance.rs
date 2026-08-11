use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

use auditd_ebpf::policy::{
    digest::{default_policy, policy_digest},
    risk_acceptance::load_trusted,
    validate::validate_record,
};

#[test]
fn 加载完整root可信记录且审批没有固定到期() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let path = path("valid");
    fs::write(&path, valid_record()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let record = load_trusted(&path).unwrap();
    assert_eq!(record.approval_id, "SEC-2026-0042");
    assert!(!fs::read_to_string(&path).unwrap().contains("expires_at"));
    validate_record(&record, &default_policy()).unwrap();
    fs::remove_file(path).unwrap();
}

#[test]
fn 拒绝摘要不匹配未知键和符号链接() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let target = path("target");
    fs::write(
        &target,
        valid_record().replace(
            &policy_digest(&default_policy()).unwrap(),
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ),
    )
    .unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    let record = load_trusted(&target).unwrap();
    assert!(validate_record(&record, &default_policy()).is_err());

    let unknown = path("unknown");
    fs::write(
        &unknown,
        format!(
            "{}\nexpires_at = \"2099-01-01T00:00:00Z\"\n",
            valid_record()
        ),
    )
    .unwrap();
    fs::set_permissions(&unknown, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(load_trusted(&unknown).is_err());

    let link = path("link");
    symlink(&target, &link).unwrap();
    assert!(load_trusted(&link).is_err());
    fs::remove_file(link).unwrap();
    fs::remove_file(unknown).unwrap();
    fs::remove_file(target).unwrap();
}

fn valid_record() -> String {
    let digest = policy_digest(&default_policy()).unwrap();
    format!(
        r#"record_version = 1
approval_id = "SEC-2026-0042"
approver = "security@example.invalid"
owner = "platform@example.invalid"
approved_at = "2026-08-10T09:00:00+08:00"
purpose = "记录完整 exec argv"
approved_readers = ["root", "auditd-ebpf-auditors"]
incident_response = "IR-AUDIT-ARGV-01"
policy_digest_version = 1
policy_digest = "{digest}"

[[destinations]]
id = "service-journal"
kind = "journal"
target = "auditd-ebpf.service"
retention_days = 90
transport_mode = "local-only"
peer_identity = ""
trust_fingerprint = ""
owner = "root"
group = "auditd-ebpf-auditors"
mode = "0640"
"#
    )
}

fn path(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("auditd-ebpf-risk-{label}-{}", std::process::id()))
}
