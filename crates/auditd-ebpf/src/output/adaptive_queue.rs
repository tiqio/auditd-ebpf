use std::collections::VecDeque;

use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum QueueError {
    #[error("队列容量配置无效")]
    InvalidCapacity,
    #[error("队列达到硬上限")]
    AtHardLimit,
}

pub struct AdaptiveQueue {
    entries: VecDeque<Vec<u8>>,
    used_bytes: usize,
    limit_bytes: usize,
    max_bytes: usize,
}

impl AdaptiveQueue {
    pub fn new(initial_bytes: usize, max_bytes: usize) -> Result<Self, QueueError> {
        if initial_bytes == 0 || initial_bytes > max_bytes {
            return Err(QueueError::InvalidCapacity);
        }
        Ok(Self {
            entries: VecDeque::new(),
            used_bytes: 0,
            limit_bytes: initial_bytes,
            max_bytes,
        })
    }

    pub fn try_push(&mut self, record: Vec<u8>) -> Result<(), QueueError> {
        let required = self.used_bytes.saturating_add(record.len());
        while required > self.limit_bytes && self.limit_bytes < self.max_bytes {
            self.limit_bytes = self.limit_bytes.saturating_mul(2).min(self.max_bytes);
        }
        if required > self.limit_bytes {
            return Err(QueueError::AtHardLimit);
        }
        self.used_bytes = required;
        self.entries.push_back(record);
        Ok(())
    }

    pub fn pop(&mut self) -> Option<Vec<u8>> {
        let record = self.entries.pop_front()?;
        self.used_bytes -= record.len();
        Some(record)
    }

    #[must_use]
    pub const fn limit_bytes(&self) -> usize {
        self.limit_bytes
    }
}
