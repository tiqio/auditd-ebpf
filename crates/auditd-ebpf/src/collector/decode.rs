use std::mem::size_of;

use auditd_ebpf_common::{
    SCHEMA_VERSION,
    event::{ExecAttempt, ExecResult, ProcessEvent, RecordType, SyscallEvent},
};
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
    #[error("未知记录类型 {0}")]
    UnknownRecordType(u16),
}

#[derive(Clone)]
pub enum KernelRecord {
    Syscall(Box<SyscallEvent>),
    ExecAttempt(Box<ExecAttempt>),
    ExecResult(Box<ExecResult>),
    Process(Box<ProcessEvent>),
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

pub fn decode_owned(bytes: &[u8]) -> Result<KernelRecord, DecodeError> {
    let decoded = decode_record(bytes)?;
    match decoded.record_type {
        value if value == RecordType::Syscall as u16 => {
            copy_record(bytes).map(Box::new).map(KernelRecord::Syscall)
        }
        value if value == RecordType::ExecAttempt as u16 => copy_record(bytes)
            .map(Box::new)
            .map(KernelRecord::ExecAttempt),
        value if value == RecordType::ExecResult as u16 => copy_record(bytes)
            .map(Box::new)
            .map(KernelRecord::ExecResult),
        value
            if value == RecordType::Fork as u16
                || value == RecordType::Exit as u16
                || value == RecordType::ProcessExec as u16 =>
        {
            copy_record(bytes).map(Box::new).map(KernelRecord::Process)
        }
        value => Err(DecodeError::UnknownRecordType(value)),
    }
}

fn copy_record<T: Copy>(bytes: &[u8]) -> Result<T, DecodeError> {
    if bytes.len() != size_of::<T>() {
        return Err(DecodeError::InvalidLength {
            declared: bytes.len(),
            actual: size_of::<T>(),
        });
    }
    // SAFETY: 长度已严格等于固定宽度 repr(C) ABI 类型；read_unaligned 不要求 RingBuf
    // 字节切片满足 Rust 对齐。所有字段均为整数或固定数组，不含引用和无效枚举位型。
    Ok(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) })
}
