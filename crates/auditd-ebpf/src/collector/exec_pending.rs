use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use thiserror::Error;

#[derive(Clone, Debug)]
pub struct PendingExec {
    pub argv: Vec<Vec<u8>>,
    pub observed_argc: u32,
    pub argv_flags: u16,
    inserted_at: Instant,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PendingError {
    #[error("pending exec 达到上限")]
    AtCapacity,
}

pub struct ExecPending {
    entries: BTreeMap<(u64, u64), PendingExec>,
    capacity: usize,
    timeout: Duration,
}

impl ExecPending {
    pub fn new(capacity: usize, timeout: Duration) -> Self {
        Self {
            entries: BTreeMap::new(),
            capacity,
            timeout,
        }
    }
    pub fn insert(
        &mut self,
        process: u64,
        attempt: u64,
        argv: Vec<Vec<u8>>,
        observed_argc: u32,
        argv_flags: u16,
    ) -> Result<(), PendingError> {
        self.insert_at(
            process,
            attempt,
            argv,
            observed_argc,
            argv_flags,
            Instant::now(),
        )
    }
    pub fn insert_at(
        &mut self,
        process: u64,
        attempt: u64,
        argv: Vec<Vec<u8>>,
        observed_argc: u32,
        argv_flags: u16,
        inserted_at: Instant,
    ) -> Result<(), PendingError> {
        if self.entries.len() >= self.capacity {
            return Err(PendingError::AtCapacity);
        }
        self.entries.insert(
            (process, attempt),
            PendingExec {
                argv,
                observed_argc,
                argv_flags,
                inserted_at,
            },
        );
        Ok(())
    }
    pub fn complete(&mut self, process: u64, attempt: u64) -> Option<PendingExec> {
        self.entries.remove(&(process, attempt))
    }
    pub fn expire(&mut self, now: Instant) -> Vec<(u64, u64)> {
        let mut expired = Vec::new();
        self.entries.retain(|key, entry| {
            let keep = now.duration_since(entry.inserted_at) < self.timeout;
            if !keep {
                expired.push(*key);
            }
            keep
        });
        expired
    }
}
