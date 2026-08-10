use auditd_ebpf_common::SCHEMA_VERSION;
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedRecord<'a> {
    pub schema: u16,
    pub record_type: u16,
    pub bytes: &'a [u8],
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DecodeError {
    #[error("记录头不足 8 字节")]
    TruncatedHeader,
    #[error("未知 schema {found}，当前仅支持 {supported}")]
    UnknownSchema { found: u16, supported: u16 },
    #[error("非法记录长度 {declared}，实际 {actual}")]
    InvalidLength { declared: usize, actual: usize },
}

pub fn decode_record(bytes: &[u8]) -> Result<DecodedRecord<'_>, DecodeError> {
    let prefix = bytes.get(..8).ok_or(DecodeError::TruncatedHeader)?;
    let schema = u16::from_le_bytes([prefix[0], prefix[1]]);
    if schema != SCHEMA_VERSION {
        return Err(DecodeError::UnknownSchema {
            found: schema,
            supported: SCHEMA_VERSION,
        });
    }
    let record_type = u16::from_le_bytes([prefix[2], prefix[3]]);
    let declared = u32::from_le_bytes([prefix[4], prefix[5], prefix[6], prefix[7]]) as usize;
    if !(56..=64 * 1024).contains(&declared) || declared != bytes.len() {
        return Err(DecodeError::InvalidLength {
            declared,
            actual: bytes.len(),
        });
    }
    Ok(DecodedRecord {
        schema,
        record_type,
        bytes,
    })
}
