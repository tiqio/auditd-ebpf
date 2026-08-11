//! auditd 多记录与 auditd-ebpf 单行记录的正确性门禁。

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use crate::model::NormalizedEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizationResult {
    pub events: BTreeSet<NormalizedEvent>,
    pub duplicates: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CorrectnessResult {
    pub valid: bool,
    pub coverage: f64,
    pub missing: usize,
    pub false_positives: usize,
    pub duplicates: u64,
    pub disclosed_loss: u64,
    pub reasons: Vec<String>,
}

#[derive(Debug, Error)]
pub enum NormalizationError {
    #[error("记录缺少必填字段: {0}")]
    MissingField(&'static str),
    #[error("字段值无效: {0}")]
    InvalidField(&'static str),
    #[error("auditd 记录缺少有效 msg=audit(...:serial)")]
    MissingSerial,
}

pub fn normalize_ebpf<I, S>(lines: I) -> Result<NormalizationResult, NormalizationError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut event_ids = BTreeSet::new();
    let mut events = BTreeSet::new();
    let mut duplicates = 0;
    for line in lines {
        let fields = parse_fields(line.as_ref());
        let event_id = required(&fields, "event_id")?;
        if !event_ids.insert(event_id.to_owned()) {
            duplicates += 1;
            continue;
        }
        events.insert(event_from_fields(&fields, fields.get("path").cloned())?);
    }
    Ok(NormalizationResult { events, duplicates })
}

pub fn normalize_auditd<I, S>(lines: I) -> Result<NormalizationResult, NormalizationError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut groups: BTreeMap<String, Vec<BTreeMap<String, String>>> = BTreeMap::new();
    for line in lines {
        let fields = parse_fields(line.as_ref());
        let serial = fields
            .get("msg")
            .and_then(|value| audit_serial(value))
            .ok_or(NormalizationError::MissingSerial)?;
        groups.entry(serial).or_default().push(fields);
    }
    let mut events = BTreeSet::new();
    for records in groups.into_values() {
        let syscall = records
            .iter()
            .find(|record| record.get("type").is_some_and(|value| value == "SYSCALL"))
            .ok_or(NormalizationError::MissingField("type=SYSCALL"))?;
        let path = records
            .iter()
            .find_map(|record| record.get("name"))
            .cloned();
        let mut combined = syscall.clone();
        for record in &records {
            for (name, value) in record {
                combined
                    .entry(name.clone())
                    .or_insert_with(|| value.clone());
            }
        }
        events.insert(event_from_fields(&combined, path)?);
    }
    Ok(NormalizationResult {
        events,
        duplicates: 0,
    })
}

pub fn evaluate(
    expected: &BTreeSet<NormalizedEvent>,
    observed: &BTreeSet<NormalizedEvent>,
    duplicates: u64,
    disclosed_loss: u64,
) -> CorrectnessResult {
    let missing = expected.difference(observed).count();
    let false_positives = observed.difference(expected).count();
    let coverage = if expected.is_empty() {
        if observed.is_empty() { 1.0 } else { 0.0 }
    } else {
        (expected.len() - missing) as f64 / expected.len() as f64
    };
    let mut reasons = Vec::new();
    if coverage != 1.0 {
        reasons.push(format!("coverage={coverage:.6}"));
    }
    if false_positives != 0 {
        reasons.push(format!("false_positives={false_positives}"));
    }
    if duplicates != 0 {
        reasons.push(format!("duplicates={duplicates}"));
    }
    if disclosed_loss != 0 {
        reasons.push(format!("disclosed_loss={disclosed_loss}"));
    }
    CorrectnessResult {
        valid: reasons.is_empty(),
        coverage,
        missing,
        false_positives,
        duplicates,
        disclosed_loss,
        reasons,
    }
}

fn event_from_fields(
    fields: &BTreeMap<String, String>,
    path: Option<String>,
) -> Result<NormalizedEvent, NormalizationError> {
    Ok(NormalizedEvent {
        operation_id: fields
            .get("operation_id")
            .cloned()
            .or_else(|| derive_operation_id(fields, path.as_deref()))
            .ok_or(NormalizationError::MissingField("operation_id"))?,
        rule_key: required(fields, "key")?.to_owned(),
        syscall: required(fields, "syscall")?.to_owned(),
        success: match required(fields, "success")? {
            "yes" | "true" | "1" => true,
            "no" | "false" | "0" => false,
            _ => return Err(NormalizationError::InvalidField("success")),
        },
        identity: required(fields, "identity")?.to_owned(),
        path,
    })
}

fn derive_operation_id(fields: &BTreeMap<String, String>, path: Option<&str>) -> Option<String> {
    fields
        .values()
        .find_map(|value| operation_marker(value))
        .or_else(|| path.and_then(operation_marker))
}

fn operation_marker(value: &str) -> Option<String> {
    value
        .split(|character: char| !character.is_ascii_alphanumeric())
        .find(|part| {
            part.len() == 15
                && part.starts_with("op")
                && part.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
        .map(str::to_owned)
}

fn required<'a>(
    fields: &'a BTreeMap<String, String>,
    name: &'static str,
) -> Result<&'a str, NormalizationError> {
    fields
        .get(name)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(NormalizationError::MissingField(name))
}

fn parse_fields(line: &str) -> BTreeMap<String, String> {
    line.split_whitespace()
        .filter_map(|token| token.split_once('='))
        .map(|(name, value)| (name.to_owned(), value.trim_matches('"').to_owned()))
        .collect()
}

fn audit_serial(value: &str) -> Option<String> {
    let value = value.strip_prefix("audit(")?.strip_suffix(')')?;
    value.rsplit_once(':').map(|(_, serial)| serial.to_owned())
}
