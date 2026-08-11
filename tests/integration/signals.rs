use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use auditd_ebpf::{
    lifecycle::{model::LifecycleState, state_file::LifecycleStateFile},
    runtime::{DrainOutcome, SignalCoordinator},
};

#[test]
fn 同类信号重入被合并且停止优先于重载() {
    let mut signals = SignalCoordinator::default();
    signals.begin_reload();
    signals.request_reload();
    signals.request_reload();
    assert!(signals.finish_reload());
    assert!(!signals.finish_reload());

    signals.request_stop();
    signals.request_reload();
    assert!(signals.stopping());
    assert!(!signals.take_reload());
}

#[test]
fn 排空完成和超时分别映射退出码零与八() {
    assert_eq!(
        auditd_ebpf::runtime::drain_with_timeout(Duration::from_millis(20), || true),
        DrainOutcome::Drained
    );
    assert_eq!(
        auditd_ebpf::runtime::drain_with_timeout(Duration::from_millis(5), || false),
        DrainOutcome::TimedOut
    );
    assert_eq!(DrainOutcome::Drained.exit_code(), 0);
    assert_eq!(DrainOutcome::TimedOut.exit_code(), 8);
}

#[test]
fn root环境真实信号保持dirty并在优雅停止后写clean() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("需要 root，跳过真实生命周期进程测试");
        return;
    }
    let directory = test_directory("process");
    let state_path = directory.join("lifecycle.toml");

    let child = Command::new(env!("CARGO_BIN_EXE_auditd-ebpf"))
        .args([
            "run",
            "--lifecycle-state-file",
            state_path.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_state(&state_path, LifecycleState::Dirty);
    assert_eq!(fs::metadata(&state_path).unwrap().mode() & 0o777, 0o600);

    signal(child.id(), "USR1");
    thread::sleep(Duration::from_millis(100));
    signal(child.id(), "TERM");
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stderr).contains("AUDITD_EBPF_STATUS"));
    wait_for_state(&state_path, LifecycleState::Clean);

    fs::remove_dir_all(directory).unwrap();
}

fn test_directory(label: &str) -> PathBuf {
    let path = PathBuf::from(format!("/tmp/auditd-ebpf-{label}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn wait_for_state(path: &Path, expected: LifecycleState) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if LifecycleStateFile::new(path)
            .read()
            .is_ok_and(|marker| marker.is_some_and(|marker| marker.state == expected))
        {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("未在期限内观察到 {expected:?}: {}", path.display());
}

fn signal(pid: u32, name: &str) {
    assert!(
        Command::new("kill")
            .args([format!("-{name}"), pid.to_string()])
            .status()
            .unwrap()
            .success()
    );
}
