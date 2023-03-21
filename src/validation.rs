use crate::hashes::*;
use crate::types::*;
use sdk_authorization_ed25519_dalek::{verify_authorizations, Authorization};
use sdk_types::{
    validate_body, validate_transaction, GetAddress, GetValue, MerkleRoot, OutPoint, State,
};
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct BitNamesState {
    pub key_to_value: HashMap<Key, Value>,
}

impl State<BitNamesOutput> for BitNamesState {
    type Error = BitNamesError;

    fn validate_transaction(
        &self,
        spent_utxos: &[Output],
        transaction: &Transaction,
    ) -> Result<(), Self::Error> {
        let spent_commitments: Vec<Commitment> = spent_utxos
            .iter()
            .filter_map(|utxo| match utxo.content {
                Content::Custom(BitNamesOutput::Commitment(commitment)) => Some(commitment),
                _ => None,
            })
            .collect();
        let name_outputs = transaction
            .outputs
            .iter()
            .filter_map(|output| match output.content {
                Content::Custom(BitNamesOutput::Reveal { salt, key, value }) => {
                    Some((salt, key, value))
                }
                _ => None,
            });
        if spent_commitments.len() > 1 {
            return Err(BitNamesError::MoreThanOneCommitment);
        }
        for (salt, key, _) in name_outputs {
            let commitment = spent_commitments[0];
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
                Content::Custom(BitNamesOutput::Reveal { key, value, .. }) => {
                    self.key_to_value.insert(*key, *value);
                    println!("key {key} was registered successfuly");
                }
                _ => {}
            }
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct Utxos<C, S, E> {
    pub utxos: HashMap<OutPoint, sdk_types::Output<C>>,
    phantom: std::marker::PhantomData<(S, E)>,
}

impl<C: GetValue + Clone + Serialize, S: State<C>, E: From<S::Error> + From<sdk_types::Error>>
    Utxos<C, S, E>
{
    pub fn new(utxos: HashMap<OutPoint, sdk_types::Output<C>>) -> Self {
        Self {
            utxos,
            phantom: Default::default(),
        }
    }

    pub fn validate_transaction(
        &self,
        state: &S,
        transaction: &sdk_types::Transaction<C>,
    ) -> Result<u64, E> {
        let spent_utxos: Vec<sdk_types::Output<C>> = transaction
            .inputs
            .iter()
            .map(|input| self.utxos[input].clone())
            .collect();
        state.validate_transaction(&spent_utxos, transaction)?;
        Ok(validate_transaction(&spent_utxos, transaction)?)
    }

    pub fn validate_body<A: GetAddress>(&self, body: &sdk_types::Body<A, C>) -> Result<u64, E> {
        let spent_utxos: Vec<Vec<sdk_types::Output<C>>> = body
            .transactions
            .iter()
            .map(|transaction| {
                transaction
                    .inputs
                    .iter()
                    .map(|input| self.utxos[input].clone())
                    .collect()
            })
            .collect();
        Ok(validate_body(&spent_utxos, body)?)
    }

    pub fn connect_transaction(
        &mut self,
        state: &mut S,
        transaction: &sdk_types::Transaction<C>,
    ) -> Result<(), E> {
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

    pub fn connect_body<A>(
        &mut self,
        state: &mut S,
        body: &sdk_types::Body<A, C>,
    ) -> Result<(), E> {
        for transaction in &body.transactions {
            self.connect_transaction(state, transaction)?;
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

#[derive(Debug)]
pub struct BitNamesNode {
    pub utxos: Utxos<BitNamesOutput, BitNamesState, Error>,
    pub state: BitNamesState,
}

impl BitNamesNode {
    pub fn new(utxos: HashMap<OutPoint, Output>) -> Self {
        let utxos = Utxos::new(utxos);
        Self {
            utxos,
            state: Default::default(),
        }
    }

    pub fn validate_body(&self, body: &Body) -> Result<u64, Error> {
        verify_authorizations(body)?;
        self.utxos.validate_body(body)
    }

    pub fn validate_transaction(&self, transaction: &Transaction) -> Result<u64, Error> {
        self.utxos.validate_transaction(&self.state, transaction)
    }

    pub fn connect_transaction(&mut self, transaction: &Transaction) -> Result<(), Error> {
        println!();
        println!("--- CONNECTING TRANSACTION {} ---", transaction.txid());
        println!();
        self.validate_transaction(transaction)?;
        self.utxos.connect_transaction(&mut self.state, transaction)
    }

    pub fn connect_body(&mut self, body: &Body) -> Result<(), Error> {
        self.validate_body(body)?;
        self.utxos.connect_body(&mut self.state, body)
    }
}
