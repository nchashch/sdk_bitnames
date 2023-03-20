use crate::hashes::*;
use crate::types::*;
use sdk_authorization_ed25519_dalek::{verify_authorizations, Authorization};
use sdk_types::{validate_transaction, GetAddress, GetValue, MerkleRoot, OutPoint, State};
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug)]
pub struct BitNamesState {
    pub key_to_value: HashMap<Key, Value>,
    pub utxos: HashMap<OutPoint, Output>,
}

impl State<Authorization, BitNamesOutput> for BitNamesState {
    type Error = BitNamesError;

    fn validate_transaction(
        &self,
        spent_utxos: &[Output],
        transaction: &Transaction,
    ) -> Result<(), Self::Error> {
        let spent_commitments: Vec<(u64, Commitment)> = spent_utxos
            .iter()
            .filter_map(|utxo| match utxo.content {
                Content::Custom(BitNamesOutput::Commitment { salt, commitment }) => {
                    Some((salt, commitment))
                }
                _ => None,
            })
            .collect();
        let name_outputs = transaction
            .outputs
            .iter()
            .filter_map(|output| match output.content {
                Content::Custom(BitNamesOutput::Name { key, value }) => Some((key, value)),
                _ => None,
            });
        if spent_commitments.len() > 1 {
            return Err(BitNamesError::MoreThanOneCommitment);
        }
        for (key, _) in name_outputs {
            let (salt, commitment) = spent_commitments[0];
            if blake2b_hmac(&key, salt) != commitment {
                return Err(BitNamesError::InvalidNameCommitment {
                    key,
                    salt,
                    commitment,
                });
            }
            if self.key_to_value.contains_key(&key) {
                return Err(BitNamesError::KeyAlreadyRegistered { key });
            }
        }
        Ok(())
    }
    fn connect_outputs(&mut self, outputs: &[Output]) -> Result<(), Self::Error> {
        for output in outputs {
            match &output.content {
                Content::Custom(BitNamesOutput::Name { key, value }) => {
                    self.key_to_value.insert(*key, *value);
                    println!("key {key} was registered successfuly");
                }
                _ => {}
            }
        }
        Ok(())
    }
}

impl BitNamesState {
    fn validate_tx(&self, transaction: &Transaction) -> Result<u64, Error> {
        let spent_utxos: Vec<Output> = transaction
            .inputs
            .iter()
            .map(|input| self.utxos[input].clone())
            .collect();
        verify_authorizations(&[transaction.clone()])?;
        self.validate_transaction(&spent_utxos, transaction)?;
        Ok(validate_transaction(&spent_utxos, transaction)?)
    }

    pub fn execute_transaction(&mut self, transaction: &Transaction) -> Result<(), Error> {
        self.validate_tx(transaction)?;
        println!();
        println!("--- EXECUTING TRANSACTION {} ---", transaction.txid());
        println!();
        for input in &transaction.inputs {
            self.utxos.remove(input);
        }
        let txid = transaction.txid();
        self.connect_outputs(&transaction.outputs)?;
        for vout in 0..transaction.outputs.len() {
            let outpoint = OutPoint::Regular {
                txid,
                vout: vout as u32,
            };
            let output = transaction.outputs[vout].clone();
            self.utxos.insert(outpoint, output);
        }
        Ok(())
    }
}

pub struct Utxos<C, A, S, E> {
    pub utxos: HashMap<OutPoint, sdk_types::Output<C>>,
    phantom: std::marker::PhantomData<(A, S, E)>,
}

impl<
        C: GetValue + Clone + Serialize,
        A: GetAddress + Clone + Serialize,
        S: State<A, C>,
        E: From<S::Error> + From<sdk_types::Error>,
    > Utxos<C, A, S, E>
{
    fn validate_transaction(
        &self,
        state: &S,
        transaction: &sdk_types::Transaction<A, C>,
    ) -> Result<u64, E> {
        let spent_utxos: Vec<sdk_types::Output<C>> = transaction
            .inputs
            .iter()
            .map(|input| self.utxos[input].clone())
            .collect();
        Ok(validate_transaction(&spent_utxos, &transaction)?)
    }

    pub fn connect_transaction(
        &mut self,
        state: &mut S,
        transaction: &sdk_types::Transaction<A, C>,
    ) -> Result<(), E> {
        self.validate_transaction(state, transaction)?;
        println!();
        println!("--- CONNECTING TRANSACTION {} ---", transaction.txid());
        println!();
        state.connect_outputs(&transaction.outputs)?;
        for input in &transaction.inputs {
            self.utxos.remove(input);
        }
        let txid = transaction.txid();
        for vout in 0..transaction.outputs.len() {
            let outpoint = OutPoint::Regular {
                txid,
                vout: vout as u32,
            };
            let output = transaction.outputs[vout].clone();
            self.utxos.insert(outpoint, output);
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("authorization error")]
    AuthorizationError(#[from] sdk_authorization_ed25519_dalek::Error),
    #[error("sdk error")]
    SdkError(#[from] sdk_types::Error),
    #[error("bitnames error")]
    BitNamesError(#[from] BitNamesError),
}

#[derive(Debug, thiserror::Error)]
pub enum BitNamesError {
    #[error("can not spend more than 1 commitment per transaction")]
    MoreThanOneCommitment,
    #[error("invalid name commitment")]
    InvalidNameCommitment {
        key: Key,
        salt: u64,
        commitment: Commitment,
    },
    #[error("key {key} was already registered")]
    KeyAlreadyRegistered { key: Key },
}
