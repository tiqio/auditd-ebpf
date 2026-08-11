use core::{
    fmt,
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign},
};

/// 与 Linux audit permission bits 数值一致的固定宽度权限集合。
///
/// 该类型跨用户态与 eBPF 共用，因此禁止包含平台宽度整数、动态容器或默认布局枚举。
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct PermissionMask(u8);

impl PermissionMask {
    pub const EMPTY: Self = Self(0);
    pub const EXEC: Self = Self(1);
    pub const WRITE: Self = Self(2);
    pub const READ: Self = Self(4);
    pub const ATTR: Self = Self(8);
    pub const ALL: Self = Self(15);

    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits & !Self::ALL.0 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}

impl BitOr for PermissionMask {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for PermissionMask {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitAnd for PermissionMask {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl BitAndAssign for PermissionMask {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl fmt::Display for PermissionMask {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (permission, symbol) in [
            (Self::READ, 'r'),
            (Self::WRITE, 'w'),
            (Self::EXEC, 'x'),
            (Self::ATTR, 'a'),
        ] {
            if self.intersects(permission) {
                formatter.write_fmt(format_args!("{symbol}"))?;
            }
        }
        Ok(())
    }
}
