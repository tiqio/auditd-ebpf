use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RiskAcceptance {
    pub record_version: u16,
    pub approval_id: String,
    pub approver: String,
    pub owner: String,
    pub approved_at: String,
    pub purpose: String,
    pub policy_digest_version: u16,
    pub policy_digest: String,
}
