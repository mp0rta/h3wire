//! Header field types.

/// A header field; `never_index` sets the QPACK 'N' bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldRef<'a> {
    pub name: &'a [u8],
    pub value: &'a [u8],
    pub never_index: bool,
}

impl<'a> FieldRef<'a> {
    pub fn new(name: &'a [u8], value: &'a [u8]) -> Self {
        Self {
            name,
            value,
            never_index: false,
        }
    }
}
