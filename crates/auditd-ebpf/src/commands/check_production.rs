use std::path::Path;

use crate::policy::{
    digest::default_policy,
    risk_acceptance::load_trusted,
    validate::{PolicyValidationError, validate_record},
};

pub fn run(path: &Path) -> Result<(), ProductionError> {
    let record = load_trusted(path).map_err(|error| ProductionError {
        code: "risk_acceptance_untrusted",
        message: error.to_string(),
    })?;
    validate_record(&record, &default_policy()).map_err(|error| ProductionError {
        code: validation_code(&error),
        message: error.to_string(),
    })?;
    println!(
        "production_policy=passed policy_digest_version=1 approval_id={} readers={} destinations={}",
        record.approval_id,
        record.approved_readers.len(),
        record.destinations.len()
    );
    Ok(())
}

pub struct ProductionError {
    pub code: &'static str,
    pub message: String,
}

fn validation_code(error: &PolicyValidationError) -> &'static str {
    match error {
        PolicyValidationError::DigestMismatch => "policy_digest_mismatch",
        PolicyValidationError::EffectivePolicyMismatch => "effective_policy_mismatch",
        PolicyValidationError::Version => "risk_acceptance_version",
        PolicyValidationError::InvalidApprovalTime => "approved_at_invalid",
        PolicyValidationError::Destination(_) => "destination_policy_invalid",
        PolicyValidationError::MissingField | PolicyValidationError::Digest(_) => {
            "risk_acceptance_invalid"
        }
    }
}
