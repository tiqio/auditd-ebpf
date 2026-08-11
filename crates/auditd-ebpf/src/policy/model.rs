use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RiskAcceptance {
    pub record_version: u16,
    pub approval_id: String,
    pub approver: String,
    pub owner: String,
    pub approved_at: String,
    pub purpose: String,
    pub approved_readers: Vec<String>,
    pub incident_response: String,
    pub policy_digest_version: u16,
    pub policy_digest: String,
    pub destinations: Vec<DestinationPolicy>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationPolicy {
    pub id: String,
    pub kind: String,
    pub target: String,
    pub retention_days: u32,
    pub transport_mode: String,
    pub peer_identity: String,
    pub trust_fingerprint: String,
    pub owner: String,
    pub group: String,
    pub mode: String,
}
