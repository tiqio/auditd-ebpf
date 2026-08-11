use auditd_ebpf_rules::parse_rules;

#[test]
fn supported_fixture_is_accepted_and_rejected_fixture_is_not() {
    let supported = include_str!("../fixtures/rules/supported.rules");
    let rejected = include_str!("../fixtures/rules/rejected.rules");
    assert_eq!(parse_rules("supported.rules", supported).unwrap().len(), 2);
    assert!(parse_rules("rejected.rules", rejected).is_err());
}

