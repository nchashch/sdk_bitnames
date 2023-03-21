use crate::hashes::*;
use sdk_authorization_ed25519_dalek::Authorization;
use sdk_types::*;
pub use sdk_types::{Address, Content, OutPoint};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BitNamesOutput {
    Commitment(Commitment),
    Reveal { salt: u64, key: Key, value: Value },
}

pub type Output = sdk_types::Output<BitNamesOutput>;
pub type Transaction = sdk_types::Transaction<BitNamesOutput>;
pub type AuthorizedTransaction = sdk_types::AuthorizedTransaction<Authorization, BitNamesOutput>;
pub type Body = sdk_types::Body<Authorization, BitNamesOutput>;

impl GetValue for BitNamesOutput {
    #[inline(always)]
    fn get_value(&self) -> u64 {
        0
    }
}
