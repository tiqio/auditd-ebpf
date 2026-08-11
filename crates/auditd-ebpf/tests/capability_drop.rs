use std::{env, fs, process::Command};

use auditd_ebpf::capabilities::drop_runtime_capabilities;

const CHILD_ENV: &str = "AUDITD_EBPF_CAPABILITY_DROP_CHILD";

#[test]
fn 初始化后清空运行期capabilities并设置no_new_privs() {
    if env::var_os(CHILD_ENV).is_some() {
        drop_runtime_capabilities().expect("当前进程应允许主动删除自身 capabilities");
        // Linux capability 属于线程凭据；Rust 测试在线程池中执行，/proc/self/status 指向
        // 线程组 leader，必须读取 thread-self 才能验证实际调用 drop 的测试线程。
        let status = fs::read_to_string("/proc/thread-self/status").expect("应可读取当前线程状态");
        for field in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
            assert_eq!(status_hex(&status, field), Some(0), "{field} 必须清零");
        }
        assert_eq!(status_decimal(&status, "NoNewPrivs"), Some(1));
        return;
    }

    let result = Command::new(env::current_exe().unwrap())
        .args([
            "--exact",
            "初始化后清空运行期capabilities并设置no_new_privs",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .status()
        .unwrap();
    assert!(result.success());
}

fn status_hex(status: &str, key: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{key}:")))
        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
}

fn status_decimal(status: &str, key: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{key}:")))
        .and_then(|value| value.trim().parse().ok())
}
