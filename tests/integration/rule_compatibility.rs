use std::{path::PathBuf, process::Command};

use auditd_ebpf_rules::{RuleCompiler, normalize::normalized_line, parse_rules};

const SUPPORTED: &str = include_str!("../fixtures/rules/supported.rules");
const REJECTED: &str = include_str!("../fixtures/rules/rejected.rules");

#[test]
fn complete_supported_corpus_is_accepted_and_stably_normalized() {
    let rules = parse_rules("supported.rules", SUPPORTED).expect("完整兼容 corpus 应通过");
    assert_eq!(rules.len(), 4);
    let normalized: Vec<_> = rules.iter().map(normalized_line).collect();
    assert!(normalized[0].contains("arch=Some(B64)"));
    assert!(normalized[0].contains("uid=0 gid=0 success=true"));
    assert!(normalized[1].contains("path=/tmp/auditd-ebpf-validation/file"));
    assert!(normalized[2].contains("arch=Some(B32)"));
    assert!(normalized[2].contains("dir=/tmp/auditd-ebpf-validation"));
    assert!(normalized[3].contains("kind=Watch"));
}

#[test]
fn every_rejected_corpus_line_has_its_own_diagnostic() {
    for (index, line) in REJECTED.lines().enumerate() {
        let errors = parse_rules("rejected.rules", line)
            .unwrap_err_or_else(|| panic!("第 {} 行不应被接受: {line}", index + 1));
        assert_eq!(errors.0.len(), 1, "第 {} 行诊断数量", index + 1);
        assert!(!errors.0[0].code.is_empty());
    }
}

#[test]
fn check_rules_print_normalized_matches_library_contract() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/rules/supported.rules");
    let output = Command::new(env!("CARGO_BIN_EXE_auditd-ebpf"))
        .args([
            "check-rules",
            "--rules-file",
            fixture.to_str().unwrap(),
            "--print-normalized",
        ])
        .output()
        .expect("应能启动 check-rules");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 4);
    assert!(stdout.contains("key=exec-root"));
    assert!(stdout.contains("key=legacy-watch"));
    let watch = stdout
        .lines()
        .find(|line| line.contains("key=legacy-watch"))
        .unwrap();
    assert!(!watch.contains("syscalls= path="));
    assert!(watch.contains(" coverage_version=1 "));
    assert!(watch.contains(" coverage_b64="));
    assert!(watch.contains(" coverage_b32="));
    assert!(watch.contains("r:"));
    assert!(watch.contains("w:"));
}

#[test]
fn watch_coverage_output_is_stable_and_changes_rule_digest() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/rules/watch-supported.rules");
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_auditd-ebpf"))
            .args([
                "check-rules",
                "--rules-file",
                fixture.to_str().unwrap(),
                "--print-normalized",
            ])
            .output()
            .unwrap()
    };
    let first = run();
    let second = run();
    assert!(first.status.success());
    assert_eq!(first.stdout, second.stdout);
    let stdout = String::from_utf8(first.stdout).unwrap();
    for line in stdout.lines() {
        assert!(line.contains("syscalls="));
        assert!(line.contains("coverage_version=1"));
        assert!(line.contains("coverage_b64="));
        assert!(line.contains("coverage_b32="));
    }

    let r = RuleCompiler::compile(
        parse_rules("r.rules", "-w /tmp/ddtest -p r -k ddtest").unwrap(),
        0,
        Default::default(),
    )
    .unwrap();
    let rw = RuleCompiler::compile(
        parse_rules("rw.rules", "-w /tmp/ddtest -p rw -k ddtest").unwrap(),
        0,
        Default::default(),
    )
    .unwrap();
    assert_ne!(r.version_hash, rw.version_hash);
}

#[test]
fn invalid_watch_returns_three_with_location_and_error_code() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/rules/watch-rejected.rules");
    for (line_number, line) in std::fs::read_to_string(fixture)
        .unwrap()
        .lines()
        .enumerate()
    {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let temp = std::env::temp_dir().join(format!(
            "auditd-ebpf-invalid-watch-{}-{line_number}.rules",
            std::process::id()
        ));
        std::fs::write(&temp, format!("{line}\n")).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_auditd-ebpf"))
            .args(["check-rules", "--rules-file", temp.to_str().unwrap()])
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&temp);
        assert_eq!(output.status.code(), Some(3), "line={line}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(".rules"), "stderr={stderr}");
        assert!(stderr.contains("E_"), "stderr={stderr}");
    }
}

trait UnwrapErrOrElse<T, E> {
    fn unwrap_err_or_else(self, fallback: impl FnOnce() -> E) -> E;
}

impl<T, E> UnwrapErrOrElse<T, E> for Result<T, E> {
    fn unwrap_err_or_else(self, fallback: impl FnOnce() -> E) -> E {
        match self {
            Ok(_) => fallback(),
            Err(error) => error,
        }
    }
}
