#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Permission {
    Read,
    Write,
    Execute,
    Attribute,
}
