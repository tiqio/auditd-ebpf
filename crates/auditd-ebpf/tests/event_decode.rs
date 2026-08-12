use auditd_ebpf::collector::decode::{DecodeError, decode_owned, decode_record};
use auditd_ebpf_common::{
    SCHEMA_VERSION,
    event::{RecordType, SyscallEvent},
};

fn header(schema: u16, kind: u16, len: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&schema.to_le_bytes());
    bytes.extend_from_slice(&kind.to_le_bytes());
    bytes.extend_from_slice(&len.to_le_bytes());
    bytes.resize(len as usize, 0);
    bytes
}

#[test]
fn rejects_unknown_schema() {
    let error = decode_record(&header(SCHEMA_VERSION + 1, 1, 56)).unwrap_err();
    assert!(matches!(error, DecodeError::UnknownSchema { .. }));
}

#[test]
fn rejects_invalid_or_truncated_length() {
    assert!(matches!(
        decode_record(&[0; 7]),
        Err(DecodeError::TruncatedHeader)
    ));
    assert!(matches!(
        decode_record(&header(SCHEMA_VERSION, 1, 8)),
        Err(DecodeError::InvalidLength { .. })
    ));
}

#[test]
fn syscall_decoder_accepts_old_zero_flags_and_rejects_unknown_abi_bits() {
    let mut old = header(
        SCHEMA_VERSION,
        RecordType::Syscall as u16,
        size_of::<SyscallEvent>() as u32,
    );
    assert!(decode_owned(&old).is_ok());

    // KernelEventHeader.flags 位于固定 repr(C) 头偏移 12；只修改保留 bit，验证旧对象
    // flags=0 兼容而未知 ABI 扩展不会被静默接受。
    old[12..16].copy_from_slice(&(1_u32 << 31).to_le_bytes());
    assert!(matches!(
        decode_owned(&old),
        Err(DecodeError::InvalidPermissionFlags(_))
    ));
}
