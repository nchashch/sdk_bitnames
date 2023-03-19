use crate::hashes::*;
use sdk_types::*;
pub use sdk_types::{Address, Authorization, OutPoint};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BitNamesOutput {
    Commitment { salt: u32, commitment: Commitment },
    Name { key: Key, value: Value },
}

pub type Output = sdk_types::Output<BitNamesOutput>;
pub type Transaction = sdk_types::Transaction<BitNamesOutput>;
pub type Body = sdk_types::Body<BitNamesOutput>;

impl GetValue for BitNamesOutput {
    #[inline(always)]
    fn get_value(&self) -> u64 {
        0
    }
}
