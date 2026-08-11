use crate::collector::decode::{DecodeError, DecodedRecord, decode_record};

#[derive(Default)]
pub struct MemorySink {
    records: Vec<Vec<u8>>,
}

impl MemorySink {
    pub fn accept<'a>(&mut self, bytes: &'a [u8]) -> Result<DecodedRecord<'a>, DecodeError> {
        let decoded = decode_record(bytes)?;
        self.records.push(bytes.to_vec());
        Ok(decoded)
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}
