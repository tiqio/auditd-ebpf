//! 固定 seed 的确定性工作负载描述。

pub mod mixed;
pub mod path;
pub mod syscall;

/// 小型确定性 PRNG，避免基准序列受第三方随机库升级影响。
#[derive(Debug, Clone)]
pub(crate) struct StableRng(u64);

impl StableRng {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed ^ 0x9e37_79b9_7f4a_7c15)
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value >> 12;
        value ^= value << 25;
        value ^= value >> 27;
        self.0 = value;
        value.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub(crate) fn index(&mut self, len: usize) -> usize {
        (self.next_u64() as usize) % len
    }
}
