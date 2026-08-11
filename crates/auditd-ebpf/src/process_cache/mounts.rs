#[derive(Clone, Copy, Debug, Default)]
pub struct MountEpoch(u64);

impl MountEpoch {
    pub fn invalidate(&mut self) {
        self.0 = self.0.wrapping_add(1);
    }
    #[must_use]
    pub const fn current(self) -> u64 {
        self.0
    }
}
