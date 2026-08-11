use std::io::{self, Cursor, Write};

use thiserror::Error;

use crate::rules::argv_policy::EffectiveArgvOutput;

use super::{
    adaptive_queue::{AdaptiveQueue, QueueError},
    event_formatter::{AuditEvent, format_event},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputRecordKind {
    Audit,
    Gap,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueuedRecord {
    pub kind: OutputRecordKind,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum WriterError {
    #[error(transparent)]
    Queue(#[from] QueueError),
    #[error("stdout 写入失败: {0}")]
    Stdout(#[source] io::Error),
    #[error("stderr 写入失败: {0}")]
    Stderr(#[source] io::Error),
}

impl WriterError {
    #[must_use]
    pub fn is_permanent_stdout_failure(&self) -> bool {
        matches!(self, Self::Stdout(_))
    }
}

pub struct OutputPipeline<StdoutWriter, StderrWriter> {
    stdout: StdoutWriter,
    stderr: StderrWriter,
    queue: AdaptiveQueue,
}

impl<StdoutWriter: Write, StderrWriter: Write> OutputPipeline<StdoutWriter, StderrWriter> {
    pub fn new(
        stdout: StdoutWriter,
        stderr: StderrWriter,
        initial_bytes: usize,
        max_bytes: usize,
    ) -> Result<Self, QueueError> {
        Ok(Self {
            stdout,
            stderr,
            queue: AdaptiveQueue::new(initial_bytes, max_bytes)?,
        })
    }

    pub fn enqueue_event(&mut self, event: &AuditEvent<'_>) -> Result<(), WriterError> {
        if event.argv_output == EffectiveArgvOutput::Suppressed {
            // 内核仍完整捕获 argv 以保证 emitted/suppressed 使用相同审计事实，但敏感参数不得
            // 穿过用户态规则决策边界。构造不持有 argv 的临时视图后再格式化，队列中只会出现
            // `argv_output=suppressed` 与 argc，不会保留可被转储或误写出的原始参数字节。
            let sanitized = AuditEvent {
                argv: &[],
                ..*event
            };
            self.enqueue_audit(format_event(&sanitized).as_bytes())
        } else {
            self.enqueue_audit(format_event(event).as_bytes())
        }
    }

    pub fn enqueue_audit(&mut self, record: &[u8]) -> Result<(), WriterError> {
        self.queue.try_push(record.to_vec()).map_err(Into::into)
    }

    pub fn enqueue_gap(&mut self, record: &[u8]) -> Result<(), WriterError> {
        self.queue.try_push(record.to_vec()).map_err(Into::into)
    }

    pub fn write_operational(&mut self, record: &[u8]) -> Result<(), WriterError> {
        self.stderr.write_all(record).map_err(WriterError::Stderr)
    }

    pub fn drain_one(&mut self) -> Result<bool, WriterError> {
        let Some(record) = self.queue.pop() else {
            return Ok(false);
        };
        self.stdout
            .write_all(&record)
            .map_err(WriterError::Stdout)?;
        Ok(true)
    }

    pub fn drain_all(&mut self) -> Result<(), WriterError> {
        while self.drain_one()? {}
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), WriterError> {
        self.stdout.flush().map_err(WriterError::Stdout)?;
        self.stderr.flush().map_err(WriterError::Stderr)
    }

    #[must_use]
    pub fn queued_records(&self) -> Vec<QueuedRecord> {
        self.queue
            .records()
            .map(|bytes| QueuedRecord {
                kind: if bytes.starts_with(b"type=AUDITD_EBPF_GAP") {
                    OutputRecordKind::Gap
                } else {
                    OutputRecordKind::Audit
                },
                bytes: bytes.to_vec(),
            })
            .collect()
    }
}

impl OutputPipeline<Cursor<Vec<u8>>, Cursor<Vec<u8>>> {
    pub fn memory(initial_bytes: usize, max_bytes: usize) -> Result<Self, QueueError> {
        Self::new(
            Cursor::new(Vec::new()),
            Cursor::new(Vec::new()),
            initial_bytes,
            max_bytes,
        )
    }

    #[must_use]
    pub fn stdout_bytes(&self) -> &[u8] {
        self.stdout.get_ref()
    }

    #[must_use]
    pub fn stderr_bytes(&self) -> &[u8] {
        self.stderr.get_ref()
    }
}
