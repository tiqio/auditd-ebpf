use std::{
    env,
    io::{self, BufRead, BufReader, Read, Write},
    process::{Command, Stdio},
};

use auditd_ebpf::output::writer::{OutputPipeline, WriterError};

const HELPER_ENV: &str = "AUDITD_EBPF_OUTPUT_HELPER";

#[test]
fn audit走stdout而status和diag走stderr() {
    if env::var_os(HELPER_ENV).is_some() {
        helper_main(false);
        std::process::exit(0);
    }
    let output = Command::new(env::current_exe().unwrap())
        .args([
            "--exact",
            "audit走stdout而status和diag走stderr",
            "--nocapture",
        ])
        .env(HELPER_ENV, "streams")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("type=AUDITD_EBPF "));
    assert!(stdout.contains("key=\"ddtest\" operation=openat"));
    assert!(stdout.contains("path=\"/tmp/ddtest\" perm=rw"));
    assert!(!stdout.contains("AUDITD_EBPF_STATUS"));
    assert!(!stdout.contains("AUDITD_EBPF_DIAG"));
    assert!(stderr.contains("AUDITD_EBPF_STATUS"));
    assert!(stderr.contains("AUDITD_EBPF_DIAG"));
}

#[test]
fn 永久epipe映射为退出码七() {
    if env::var_os(HELPER_ENV).is_some() {
        helper_main(true);
        std::process::exit(0);
    }
    let mut child = Command::new(env::current_exe().unwrap())
        .args(["--exact", "永久epipe映射为退出码七", "--nocapture"])
        .env(HELPER_ENV, "epipe")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let mut ready = String::new();
    stderr.read_line(&mut ready).unwrap();
    assert!(ready.contains("writer-ready"));
    drop(child.stdout.take());
    child.stdin.take().unwrap().write_all(b"1").unwrap();

    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(7));
}

fn helper_main(force_epipe: bool) {
    let stdout = io::stdout();
    let stderr = io::stderr();
    let mut pipeline = OutputPipeline::new(stdout.lock(), stderr.lock(), 1024, 4096).unwrap();
    if force_epipe {
        pipeline
            .write_operational(b"writer-ready\n")
            .and_then(|_| pipeline.flush())
            .unwrap();
        let mut release = [0_u8; 1];
        io::stdin().read_exact(&mut release).unwrap();
        pipeline.enqueue_audit(&vec![b'x'; 4096]).unwrap();
        if let Err(error) = pipeline.drain_all() {
            std::process::exit(writer_exit_code(&error));
        }
        std::process::exit(1);
    }

    pipeline
        .enqueue_audit(
            b"type=AUDITD_EBPF key=\"ddtest\" operation=openat path=\"/tmp/ddtest\" perm=rw\n",
        )
        .unwrap();
    pipeline
        .write_operational(b"type=AUDITD_EBPF_STATUS state=healthy\n")
        .unwrap();
    pipeline
        .write_operational(b"type=AUDITD_EBPF_DIAG code=test\n")
        .unwrap();
    if let Err(error) = pipeline.drain_all().and_then(|_| pipeline.flush()) {
        std::process::exit(writer_exit_code(&error));
    }
}

fn writer_exit_code(error: &WriterError) -> i32 {
    assert!(error.is_permanent_stdout_failure());
    7
}
