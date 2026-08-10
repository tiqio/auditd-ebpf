use auditd_ebpf::policy::digest::policy_digest;

#[test]
fn digest_is_stable_across_input_order() {
    let first = policy_digest(["b=2".to_string(), "a=1".to_string()]);
    let second = policy_digest(["a=1".to_string(), "b=2".to_string()]);
    assert_eq!(first, second);
    assert!(first.starts_with("sha256:"));
}
