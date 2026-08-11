use std::collections::BTreeSet;

use thiserror::Error;

use super::{
    digest::{PolicyDigestError, PolicyInput, policy_digest},
    model::{DestinationPolicy, RiskAcceptance},
};

#[derive(Debug, Error)]
pub enum PolicyValidationError {
    #[error("风险接受记录版本不受支持")]
    Version,
    #[error("风险接受记录缺少必填字段")]
    MissingField,
    #[error("approved_at 必须是带时区 RFC 3339 时间")]
    InvalidApprovalTime,
    #[error("策略摘要格式或内容不匹配")]
    DigestMismatch,
    #[error("记录的读取者或目的地与有效策略不一致")]
    EffectivePolicyMismatch,
    #[error("目的地安全策略无效: {0}")]
    Destination(String),
    #[error(transparent)]
    Digest(#[from] PolicyDigestError),
}

pub fn validate_record(
    record: &RiskAcceptance,
    effective: &PolicyInput,
) -> Result<(), PolicyValidationError> {
    if record.record_version != 1 || record.policy_digest_version != 1 {
        return Err(PolicyValidationError::Version);
    }
    for value in [
        &record.approval_id,
        &record.approver,
        &record.owner,
        &record.approved_at,
        &record.purpose,
        &record.incident_response,
    ] {
        if value.trim().is_empty() {
            return Err(PolicyValidationError::MissingField);
        }
    }
    if !is_rfc3339_with_zone(&record.approved_at) {
        return Err(PolicyValidationError::InvalidApprovalTime);
    }
    let expected_digest = policy_digest(effective)?;
    if record.policy_digest != expected_digest {
        return Err(PolicyValidationError::DigestMismatch);
    }
    let readers = normalized_set(&record.approved_readers)?;
    let effective_readers = normalized_set(&effective.readers)?;
    if readers != effective_readers || record.destinations != effective.destinations {
        return Err(PolicyValidationError::EffectivePolicyMismatch);
    }
    for destination in &record.destinations {
        validate_destination(destination)?;
    }
    Ok(())
}

fn normalized_set(values: &[String]) -> Result<BTreeSet<String>, PolicyValidationError> {
    values
        .iter()
        .map(|value| {
            let value = value.trim();
            if value.is_empty() {
                Err(PolicyValidationError::MissingField)
            } else {
                Ok(value.to_owned())
            }
        })
        .collect()
}

fn validate_destination(destination: &DestinationPolicy) -> Result<(), PolicyValidationError> {
    if destination.id.trim().is_empty()
        || destination.kind.trim().is_empty()
        || destination.target.trim().is_empty()
        || destination.owner.trim().is_empty()
        || destination.group.trim().is_empty()
        || destination.mode.trim().is_empty()
        || !(1..=3650).contains(&destination.retention_days)
    {
        return Err(PolicyValidationError::Destination(destination.id.clone()));
    }
    let mode = u32::from_str_radix(destination.mode.trim(), 8)
        .map_err(|_| PolicyValidationError::Destination(destination.id.clone()))?;
    if destination.kind == "export" && mode & 0o077 != 0
        || destination.kind != "export" && mode & 0o027 != 0
    {
        return Err(PolicyValidationError::Destination(destination.id.clone()));
    }
    if destination.transport_mode == "local-only" {
        if !destination.peer_identity.is_empty() || !destination.trust_fingerprint.is_empty() {
            return Err(PolicyValidationError::Destination(destination.id.clone()));
        }
    } else if destination.peer_identity.trim().is_empty()
        || destination.trust_fingerprint.trim().is_empty()
    {
        return Err(PolicyValidationError::Destination(destination.id.clone()));
    }
    Ok(())
}

fn is_rfc3339_with_zone(value: &str) -> bool {
    let Some(time_index) = value.find('T') else {
        return false;
    };
    let zone = &value[time_index + 1..];
    value.len() >= 20
        && (value.ends_with('Z')
            || zone.rfind('+').is_some_and(|index| index >= 8)
            || zone.rfind('-').is_some_and(|index| index >= 8))
}
