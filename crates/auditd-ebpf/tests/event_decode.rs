use auditd_ebpf::collector::decode::{DecodeError, decode_record};
use auditd_ebpf_common::SCHEMA_VERSION;

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
