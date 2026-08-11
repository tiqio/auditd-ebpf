use std::{collections::VecDeque, time::Duration};

use thiserror::Error;

pub const DEFAULT_INITIAL_BYTES: usize = 64 * 1024 * 1024;
pub const DEFAULT_MAX_BYTES: usize = 512 * 1024 * 1024;
const HIGH_WATERMARK_PERCENT: usize = 80;
const LOW_WATERMARK_PERCENT: usize = 25;
const HIGH_WINDOWS_TO_GROW: u8 = 3;
const LOW_WATERMARK_DURATION: Duration = Duration::from_secs(10 * 60);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueState {
    Normal,
    Growing,
    AtMax,
    Dropping,
}

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
    initial_bytes: usize,
    limit_bytes: usize,
    max_bytes: usize,
    state: QueueState,
    consecutive_high_windows: u8,
    low_watermark_elapsed: Duration,
    dropped_total: u64,
}

impl AdaptiveQueue {
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_INITIAL_BYTES, DEFAULT_MAX_BYTES).expect("编译期默认队列容量必须保持有效")
    }

    pub fn new(initial_bytes: usize, max_bytes: usize) -> Result<Self, QueueError> {
        if initial_bytes == 0 || initial_bytes > max_bytes {
            return Err(QueueError::InvalidCapacity);
        }
        Ok(Self {
            entries: VecDeque::new(),
            used_bytes: 0,
            initial_bytes,
            limit_bytes: initial_bytes,
            max_bytes,
            state: QueueState::Normal,
            consecutive_high_windows: 0,
            low_watermark_elapsed: Duration::ZERO,
            dropped_total: 0,
        })
    }

    pub fn try_push(&mut self, record: Vec<u8>) -> Result<(), QueueError> {
        let required = self.used_bytes.saturating_add(record.len());

        // 单条记录不能因为监控窗口尚未推进而被过早丢弃。这里仅增长到容纳当前记录所需的
        // 最小二倍容量；常规的提前扩容仍由连续三个 80% 高水位窗口驱动。
        while required > self.limit_bytes && self.limit_bytes < self.max_bytes {
            self.grow_once();
        }
        if required > self.limit_bytes {
            self.dropped_total = self.dropped_total.saturating_add(1);
            self.state = QueueState::Dropping;
            return Err(QueueError::AtHardLimit);
        }
        self.used_bytes = required;
        self.entries.push_back(record);
        if self.limit_bytes == self.max_bytes {
            self.state = QueueState::AtMax;
        }
        Ok(())
    }

    pub fn pop(&mut self) -> Option<Vec<u8>> {
        let record = self.entries.pop_front()?;
        self.used_bytes -= record.len();
        Some(record)
    }

    pub fn observe_window(&mut self, elapsed: Duration) {
        let usage_percent = self.used_bytes.saturating_mul(100) / self.limit_bytes;
        if usage_percent >= HIGH_WATERMARK_PERCENT {
            self.low_watermark_elapsed = Duration::ZERO;
            self.consecutive_high_windows = self.consecutive_high_windows.saturating_add(1);
            if self.consecutive_high_windows >= HIGH_WINDOWS_TO_GROW {
                self.grow_once();
                self.consecutive_high_windows = 0;
            }
            return;
        }

        self.consecutive_high_windows = 0;
        if usage_percent <= LOW_WATERMARK_PERCENT {
            self.low_watermark_elapsed = self.low_watermark_elapsed.saturating_add(elapsed);
            if self.low_watermark_elapsed >= LOW_WATERMARK_DURATION {
                self.shrink_once();
                self.low_watermark_elapsed = Duration::ZERO;
            }
        } else {
            self.low_watermark_elapsed = Duration::ZERO;
            self.state = if self.limit_bytes == self.max_bytes {
                QueueState::AtMax
            } else {
                QueueState::Normal
            };
        }
    }

    fn grow_once(&mut self) {
        if self.limit_bytes == self.max_bytes {
            self.state = QueueState::AtMax;
            return;
        }
        self.limit_bytes = self.limit_bytes.saturating_mul(2).min(self.max_bytes);
        self.state = if self.limit_bytes == self.max_bytes {
            QueueState::AtMax
        } else {
            QueueState::Growing
        };
    }

    fn shrink_once(&mut self) {
        let candidate = (self.limit_bytes / 2).max(self.initial_bytes);
        if candidate >= self.used_bytes {
            self.limit_bytes = candidate;
        }
        self.state = if self.limit_bytes == self.max_bytes {
            QueueState::AtMax
        } else {
            QueueState::Normal
        };
    }

    #[must_use]
    pub const fn used_bytes(&self) -> usize {
        self.used_bytes
    }

    #[must_use]
    pub const fn limit_bytes(&self) -> usize {
        self.limit_bytes
    }

    #[must_use]
    pub const fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    #[must_use]
    pub const fn dropped_total(&self) -> u64 {
        self.dropped_total
    }

    #[must_use]
    pub const fn state(&self) -> QueueState {
        self.state
    }

    pub(crate) fn records(&self) -> impl Iterator<Item = &[u8]> {
        self.entries.iter().map(Vec::as_slice)
    }
}
