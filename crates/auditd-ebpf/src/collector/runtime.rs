use std::{
    borrow::Borrow,
    time::{Duration, Instant},
};

use auditd_ebpf_common::event::{ExecAttempt, ExecResult, MAX_EXEC_ARGS};
use aya::maps::{MapData, RingBuf};

use crate::collector::{
    decode::{DecodeError, KernelRecord, decode_owned, decode_record},
    exec_pending::{ExecPending, PendingError, PendingExec},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CollectorGap {
    MissingExecAttempt { process: u64, attempt: u64 },
    ExecAttemptTimeout { process: u64, attempt: u64 },
    PendingCapacity,
}

#[derive(Clone, Debug)]
pub struct CorrelatedExec {
    pub process: u64,
    pub attempt: u64,
    pub result: i64,
    pub argv: Vec<Vec<u8>>,
    pub observed_argc: u32,
    pub argv_flags: u16,
}

pub enum CollectedRecord {
    Kernel(KernelRecord),
    Exec(CorrelatedExec),
    Gap(CollectorGap),
}

pub struct CollectorRuntime {
    pending: ExecPending,
    output: Vec<CollectedRecord>,
}

impl CollectorRuntime {
    pub fn new(capacity: usize, timeout: Duration) -> Self {
        Self {
            pending: ExecPending::new(capacity, timeout),
            output: Vec::new(),
        }
    }

    pub fn accept(&mut self, bytes: &[u8]) -> Result<(), DecodeError> {
        match decode_owned(bytes)? {
            KernelRecord::ExecAttempt(attempt) => self.accept_attempt(&attempt),
            KernelRecord::ExecResult(result) => self.accept_result(&result),
            record => self.output.push(CollectedRecord::Kernel(record)),
        }
        Ok(())
    }

    pub fn expire(&mut self, now: Instant) {
        self.output.extend(
            self.pending
                .expire(now)
                .into_iter()
                .map(|(process, attempt)| {
                    CollectedRecord::Gap(CollectorGap::ExecAttemptTimeout { process, attempt })
                }),
        );
    }

    pub fn take_output(&mut self) -> Vec<CollectedRecord> {
        std::mem::take(&mut self.output)
    }

    fn accept_attempt(&mut self, attempt: &ExecAttempt) {
        let process = attempt.header.pid_tgid;
        let argv = decode_argv(attempt);
        if self.pending.insert(
            process,
            attempt.attempt_id,
            argv,
            attempt.argc_observed,
            attempt.argv_flags,
        ) == Err(PendingError::AtCapacity)
        {
            self.output
                .push(CollectedRecord::Gap(CollectorGap::PendingCapacity));
        }
    }

    fn accept_result(&mut self, result: &ExecResult) {
        let process = result.header.pid_tgid;
        if let Some(PendingExec {
            argv,
            observed_argc,
            argv_flags,
            ..
        }) = self.pending.complete(process, result.attempt_id)
        {
            self.output.push(CollectedRecord::Exec(CorrelatedExec {
                process,
                attempt: result.attempt_id,
                result: result.result,
                argv,
                observed_argc,
                argv_flags,
            }));
        } else {
            self.output
                .push(CollectedRecord::Gap(CollectorGap::MissingExecAttempt {
                    process,
                    attempt: result.attempt_id,
                }));
        }
    }
}

pub fn drain_ring<T: Borrow<MapData>>(
    ring: &mut RingBuf<T>,
    runtime: &mut CollectorRuntime,
) -> Result<usize, DecodeError> {
    let mut drained = 0;
    while let Some(item) = ring.next() {
        runtime.accept(&item)?;
        drained += 1;
    }
    Ok(drained)
}

fn decode_argv(attempt: &ExecAttempt) -> Vec<Vec<u8>> {
    let count = usize::from(attempt.argc_captured).min(MAX_EXEC_ARGS);
    let mut argv = Vec::with_capacity(count);
    for index in 0..count {
        let start = usize::from(attempt.argv_offsets[index]);
        let end = usize::from(attempt.argv_offsets[index + 1]);
        if start <= end && end <= attempt.argv_bytes.len() {
            let slot = &attempt.argv_bytes[start..end];
            let length = slot
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(slot.len());
            argv.push(slot[..length].to_vec());
        }
    }
    argv
}

#[derive(Default)]
pub struct MemorySink {
    records: Vec<Vec<u8>>,
}

impl MemorySink {
    pub fn accept<'a>(
        &mut self,
        bytes: &'a [u8],
    ) -> Result<crate::collector::decode::DecodedRecord<'a>, DecodeError> {
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
