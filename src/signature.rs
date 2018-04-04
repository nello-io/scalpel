use errors::*;

use bytes::{Bytes, BytesMut};

use ring::{rand, signature};


#[derive(Debug, Eq, PartialEq)]
pub struct Signature {
    bytes: BytesMut,
    // TODO use ed25519 elliptic curve signature
}

impl Default for Signature {
    fn default() -> Self {
        Self { bytes: BytesMut::with_capacity(64) }
    }
}

use std::fmt::Debug;

// TODO impl equal operation
impl Signature {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn from_slice<'a, T>(slice: T) -> Result<Self>
    where
        T: Into<&'a [u8]>,
    {
        let x = BytesMut::from(slice.into());
        if x.len() == Self::size() {
            Ok(Self { bytes: x })
        } else {
            Err(
                ParsingError::ParsePacket {
                    reason: format!("Failed to parse {:?} into signature", x),
                }.into(),
)
        }
    }

    pub fn size() -> usize {
        64
    }
}

use std::convert::AsRef;

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..]
    }
}
