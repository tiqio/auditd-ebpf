use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
};

use auditd_ebpf::lifecycle::{
    model::LifecycleMarker,
    state_file::{LifecycleStateFile, StateFileError},
};

#[test]
fn root可信目录中原子写入0600普通文件() {
    let Some(directory) = root_directory("trusted") else {
        return;
    };
    let path = directory.join("lifecycle.toml");
    let marker = LifecycleMarker::dirty("boot", "invocation", 42, 100);

    LifecycleStateFile::new(&path).write(&marker).unwrap();
    let metadata = fs::metadata(&path).unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(LifecycleStateFile::new(&path).read().unwrap(), Some(marker));
    assert!(fs::read_dir(&directory).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp.")
    }));
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn 拒绝符号链接未知版本未知键和缺失字段() {
    let Some(directory) = root_directory("invalid") else {
        return;
    };
    let target = directory.join("target.toml");
    fs::write(&target, valid_toml()).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    let link = directory.join("lifecycle.toml");
    symlink(&target, &link).unwrap();
    assert!(LifecycleStateFile::new(&link).read().is_err());
    fs::remove_file(&link).unwrap();

    for invalid in [
        valid_toml().replace("version = 1", "version = 2"),
        format!("{}unknown = true\n", valid_toml()),
        valid_toml().replace("boot_id = \"boot\"\n", ""),
    ] {
        fs::write(&link, invalid).unwrap();
        fs::set_permissions(&link, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            LifecycleStateFile::new(&link).read(),
            Err(StateFileError::Decode(_)) | Err(StateFileError::InvalidSchema(_))
        ));
    }
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn 拒绝非可信父目录和过宽文件权限() {
    let Some(directory) = root_directory("permissions") else {
        return;
    };
    let path = directory.join("lifecycle.toml");
    fs::write(&path, valid_toml()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        LifecycleStateFile::new(&path).read(),
        Err(StateFileError::UntrustedFile)
    ));

    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        LifecycleStateFile::new(&path).read(),
        Err(StateFileError::UntrustedParent)
    ));
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_dir_all(directory).unwrap();
}

fn root_directory(label: &str) -> Option<PathBuf> {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("需要 root，跳过生命周期可信属性测试");
        return None;
    }
    let path = PathBuf::from(format!(
        "/tmp/auditd-ebpf-state-{label}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    Some(path)
}

fn valid_toml() -> &'static str {
    "version = 1\nstate = \"dirty\"\nboot_id = \"boot\"\ninvocation_id = \"invocation\"\npid = 42\nprocess_start_time = 100\nupdated_at = \"2026-08-11T00:00:00Z\"\n"
}
