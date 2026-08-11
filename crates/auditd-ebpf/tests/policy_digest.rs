use auditd_ebpf::policy::{
    digest::{PolicyInput, canonical_policy, policy_digest},
    model::DestinationPolicy,
};

#[test]
fn version1摘要使用固定顺序并对集合去重排序() {
    let input = PolicyInput {
        argv_default_emitted: true,
        argv_rules: vec![(b"z key".to_vec(), false), (b"a\xff".to_vec(), true)],
        readers: vec![" root ".into(), "audit".into(), "root".into()],
        destinations: vec![destination("file", "/var/log/events", "local-only")],
    };

    let canonical = canonical_policy(&input).unwrap();
    assert_eq!(
        canonical,
        concat!(
            "argv.default=emitted\n",
            "argv.rule.a\\xFF=emitted\n",
            "argv.rule.z\\x20key=suppressed\n",
            "reader=audit\n",
            "reader=root\n",
            "destination=file:/var/log/events\n",
            "transport=local-only::\n",
            "access=root:audit:0640\n",
            "retention_days=90\n",
        )
    );
    let first = policy_digest(&input).unwrap();
    let mut reordered = input.clone();
    reordered.readers.reverse();
    reordered.argv_rules.reverse();
    assert_eq!(first, policy_digest(&reordered).unwrap());
    assert_eq!(first.len(), "sha256:".len() + 64);
}

fn destination(kind: &str, target: &str, transport_mode: &str) -> DestinationPolicy {
    DestinationPolicy {
        id: "destination".into(),
        kind: kind.into(),
        target: target.into(),
        retention_days: 90,
        transport_mode: transport_mode.into(),
        peer_identity: String::new(),
        trust_fingerprint: String::new(),
        owner: "root".into(),
        group: "audit".into(),
        mode: "0640".into(),
    }
}
