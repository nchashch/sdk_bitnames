pub use sdk_types::hash;
use serde::{Deserialize, Serialize};

type Hash = [u8; 32];

#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Key(Hash);

impl std::fmt::Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl From<Hash> for Key {
    fn from(other: Hash) -> Self {
        Self(other)
    }
}

impl From<Key> for Hash {
    fn from(other: Key) -> Self {
        other.0
    }
}

impl<'a> From<&'a Key> for &'a Hash {
    fn from(other: &'a Key) -> Self {
        &other.0
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Value(Hash);

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl std::fmt::Debug for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl From<Hash> for Value {
    fn from(other: Hash) -> Self {
        Self(other)
    }
}

impl From<Value> for Hash {
    fn from(other: Value) -> Self {
        other.0
    }
}

impl<'a> From<&'a Value> for &'a Hash {
    fn from(other: &'a Value) -> Self {
        &other.0
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Commitment(Hash);

impl std::fmt::Display for Commitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl std::fmt::Debug for Commitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl From<Hash> for Commitment {
    fn from(other: Hash) -> Self {
        Self(other)
    }
}

impl From<Commitment> for Hash {
    fn from(other: Commitment) -> Self {
        other.0
    }
}

impl<'a> From<&'a Commitment> for &'a Hash {
    fn from(other: &'a Commitment) -> Self {
        &other.0
    }
}

use digest::FixedOutput;

pub fn blake2b_hmac(key: &Key, salt: u64) -> Commitment {
    let salt = salt.to_be_bytes();
    let key: &[u8; 32] = key.into();
    let commitment: [u8; 32] =
        blake2::Blake2bMac::<digest::consts::U32>::new_with_salt_and_personal(key, &salt, &[])
            .unwrap()
            .finalize_fixed()
            .into();
    commitment.into()
}
