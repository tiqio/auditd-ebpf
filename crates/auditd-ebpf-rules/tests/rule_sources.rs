use std::{fs, os::unix::fs::PermissionsExt};

use auditd_ebpf_rules::source::sorted_rule_files;

#[test]
fn sorts_rules_and_rejects_writable_files() {
    let directory = std::env::temp_dir().join(format!("auditd-ebpf-rules-{}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    for name in ["20-b.rules", "10-a.rules"] {
        let path = directory.join(name);
        fs::write(&path, "-a always,exit -S execve -k x").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let paths = sorted_rule_files(&directory).unwrap();
    assert_eq!(paths[0].file_name().unwrap(), "10-a.rules");
    fs::set_permissions(&paths[0], fs::Permissions::from_mode(0o622)).unwrap();
    assert!(sorted_rule_files(&directory).is_err());
    fs::remove_dir_all(directory).unwrap();
}
