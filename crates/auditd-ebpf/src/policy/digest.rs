use std::collections::BTreeSet;

use sha2::{Digest, Sha256};
use thiserror::Error;

use super::model::DestinationPolicy;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PolicyInput {
    pub argv_default_emitted: bool,
    pub argv_rules: Vec<(Vec<u8>, bool)>,
    pub readers: Vec<String>,
    pub destinations: Vec<DestinationPolicy>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PolicyDigestError {
    #[error("策略字段规范化后不能为空")]
    EmptyField,
    #[error("同一 argv key 存在冲突覆盖")]
    DuplicateArgvKey,
    #[error("目的地 id 重复")]
    DuplicateDestination,
}

#[must_use]
pub fn default_policy() -> PolicyInput {
    PolicyInput {
        argv_default_emitted: true,
        argv_rules: Vec::new(),
        readers: vec!["root".into(), "auditd-ebpf-auditors".into()],
        destinations: vec![DestinationPolicy {
            id: "service-journal".into(),
            kind: "journal".into(),
            target: "auditd-ebpf.service".into(),
            retention_days: 90,
            transport_mode: "local-only".into(),
            peer_identity: String::new(),
            trust_fingerprint: String::new(),
            owner: "root".into(),
            group: "auditd-ebpf-auditors".into(),
            mode: "0640".into(),
        }],
    }
}

pub fn canonical_policy(input: &PolicyInput) -> Result<String, PolicyDigestError> {
    let mut output = String::new();
    output.push_str(if input.argv_default_emitted {
        "argv.default=emitted\n"
    } else {
        "argv.default=suppressed\n"
    });

    let mut argv_rules = input.argv_rules.clone();
    argv_rules.sort_by(|left, right| left.0.cmp(&right.0));
    for pair in argv_rules.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(PolicyDigestError::DuplicateArgvKey);
        }
    }
    for (key, emitted) in argv_rules {
        output.push_str("argv.rule.");
        output.push_str(&escape_key(&key));
        output.push('=');
        output.push_str(if emitted { "emitted\n" } else { "suppressed\n" });
    }

    let readers = input
        .readers
        .iter()
        .map(|value| normalized(value))
        .collect::<Result<BTreeSet<_>, _>>()?;
    for reader in readers {
        output.push_str("reader=");
        output.push_str(&reader);
        output.push('\n');
    }

    let mut destinations = input.destinations.clone();
    destinations.sort_by(|left, right| {
        (left.kind.trim(), left.target.trim()).cmp(&(right.kind.trim(), right.target.trim()))
    });
    let mut ids = BTreeSet::new();
    for destination in destinations {
        if !ids.insert(normalized(&destination.id)?) {
            return Err(PolicyDigestError::DuplicateDestination);
        }
        let kind = normalized(&destination.kind)?;
        let target = normalized(&destination.target)?;
        let transport = normalized(&destination.transport_mode)?;
        let owner = normalized(&destination.owner)?;
        let group = normalized(&destination.group)?;
        let mode = normalized(&destination.mode)?;
        output.push_str(&format!("destination={kind}:{target}\n"));
        output.push_str(&format!(
            "transport={transport}:{}:{}\n",
            destination.peer_identity.trim(),
            destination.trust_fingerprint.trim()
        ));
        output.push_str(&format!("access={owner}:{group}:{mode}\n"));
        output.push_str(&format!("retention_days={}\n", destination.retention_days));
    }
    Ok(output)
}

pub fn policy_digest(input: &PolicyInput) -> Result<String, PolicyDigestError> {
    let canonical = canonical_policy(input)?;
    let mut digest = Sha256::new();
    digest.update(canonical.as_bytes());
    Ok(format!("sha256:{}", hex::encode(digest.finalize())))
}

fn normalized(value: &str) -> Result<String, PolicyDigestError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(PolicyDigestError::EmptyField);
    }
    Ok(value.to_owned())
}

fn escape_key(bytes: &[u8]) -> String {
    let mut output = String::new();
    for byte in bytes {
        if matches!(*byte, 0x21..=0x7e) && !matches!(*byte, b'\\' | b'=') {
            output.push(char::from(*byte));
        } else {
            output.push_str(&format!("\\x{byte:02X}"));
        }
    }
    output
}
