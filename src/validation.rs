use crate::hashes::*;
use crate::types::*;
use sdk_authorization_ed25519_dalek::verify_authorizations;
use sdk_types::{validate_body, validate_transaction, OutPoint};
use std::collections::{HashMap, HashSet};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("authorization error")]
    Authorization(#[from] sdk_authorization_ed25519_dalek::Error),
    #[error("sdk error")]
    Sdk(#[from] sdk_types::Error),
    #[error("bitnames error")]
    BitNames(#[from] BitNamesError),
}

const COMMITMENT_MAX_AGE: u32 = 10;
#[derive(Debug, thiserror::Error)]
pub enum BitNamesError {
    #[error("invalid name commitment")]
    InvalidNameCommitment {
        key: Key,
        salt: u64,
        commitment: Commitment,
    },
    #[error("key {key} was already registered with an older commitment: prev commitment height {prev_commitment_height} < commitment height {commitment_height}")]
    KeyAlreadyRegistered {
        key: Key,
        prev_commitment_height: u32,
        commitment_height: u32,
    },
    #[error("commitment {commitment} not found")]
    CommitmentNotFound { commitment: Commitment },
    #[error("key {key} not found")]
    KeyNotFound { key: Key },
    #[error("commitment {commitment} is late by {late_by}")]
    RevealTooLate {
        commitment: Commitment,
        late_by: u32,
    },
}

#[derive(Debug, Default)]
pub struct BitNamesState {
    pub key_to_value: HashMap<Key, Value>,
    pub commitment_height: HashMap<Commitment, u32>,
    // Height of the oldest commitment used to claim this key.
    pub key_height: HashMap<Key, u32>,
    pub utxos: HashMap<OutPoint, Output>,
    pub best_block_height: u32,
}

impl BitNamesState {
    pub fn new(utxos: HashMap<OutPoint, Output>) -> Self {
        Self {
            utxos,
            ..Default::default()
        }
    }

    pub fn validate_body(&self, block_height: u32, body: &Body) -> Result<u64, Error> {
        verify_authorizations(body)?;
        let spent_utxos: Vec<Output> = body
            .transactions
            .iter()
            .flat_map(|transaction| {
                transaction
                    .inputs
                    .iter()
                    .map(|input| self.utxos[input].clone())
            })
            .collect();
        {
            let mut index = 0;
            for transaction in &body.transactions {
                let spent_utxos = &spent_utxos[index..transaction.inputs.len()];
                self.validate_transaction_pure(spent_utxos, block_height, transaction)?;
                index += transaction.inputs.len();
            }
        }
        Ok(validate_body(spent_utxos.as_slice(), body)?)
    }

    fn validate_transaction_pure(
        &self,
        spent_utxos: &[Output],
        block_height: u32,
        transaction: &Transaction,
    ) -> Result<(), BitNamesError> {
        let spent_commitments: HashSet<Commitment> = spent_utxos
            .iter()
            .filter_map(|utxo| match utxo.content {
                Content::Custom(BitNamesOutput::Commitment(commitment)) => Some(commitment),
                _ => None,
            })
            .collect();
        for commitment in &spent_commitments {
            let height = self.get_commitment_height(commitment)?;
            if block_height - height > COMMITMENT_MAX_AGE {
                return Err(BitNamesError::RevealTooLate {
                    commitment: *commitment,
                    late_by: block_height - height - COMMITMENT_MAX_AGE,
                });
            }
        }
        let name_outputs = transaction
            .outputs
            .iter()
            .filter_map(|output| match output.content {
                Content::Custom(BitNamesOutput::Reveal { salt, key, value }) => {
                    Some((salt, key, value))
                }
                _ => None,
            });
        for (salt, key, _) in name_outputs {
            let commitment = blake2b_hmac(&key, salt);
            if !spent_commitments.contains(&commitment) {
                return Err(BitNamesError::InvalidNameCommitment {
                    key,
                    salt,
                    commitment,
                });
            }
            if self.key_to_value.contains_key(&key) {
                let commitment_height = self.get_commitment_height(&commitment)?;
                let prev_commitment_height = self.get_key_height(&key)?;
                if prev_commitment_height < commitment_height {
                    return Err(BitNamesError::KeyAlreadyRegistered {
                        key,
                        prev_commitment_height,
                        commitment_height,
                    });
                }
            }
        }
        Ok(())
    }

    fn get_commitment_height(&self, commitment: &Commitment) -> Result<u32, BitNamesError> {
        self.commitment_height
            .get(commitment)
            .copied()
            .ok_or(BitNamesError::CommitmentNotFound {
                commitment: *commitment,
            })
    }

    fn get_key_height(&self, key: &Key) -> Result<u32, BitNamesError> {
        self.key_height
            .get(key)
            .copied()
            .ok_or(BitNamesError::KeyNotFound { key: *key })
    }
    pub fn validate_transaction(&self, transaction: &Transaction) -> Result<u64, Error> {
        // Will this transaction be valid, if included in next block?
        let spent_utxos: Vec<Output> = transaction
            .inputs
            .iter()
            .map(|input| self.utxos[input].clone())
            .collect();
        self.validate_transaction_pure(&spent_utxos, self.best_block_height + 1, transaction)?;
        Ok(validate_transaction(&spent_utxos, transaction)?)
    }

    pub fn connect_body(&mut self, body: &Body) -> Result<(), Error> {
        println!();
        println!(
            "--- CONNECTING BODY merkle_root = {} ---",
            body.compute_merkle_root()
        );
        println!();
        self.validate_body(self.best_block_height + 1, body)?;
        self.best_block_height += 1;

        let spent_utxos: Vec<Output> = body
            .transactions
            .iter()
            .flat_map(|transaction| {
                transaction
                    .inputs
                    .iter()
                    .map(|input| self.utxos[input].clone())
            })
            .collect();
        for transaction in &body.transactions {
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
                match &output.content {
                    Content::Custom(BitNamesOutput::Reveal { key, value, salt }) => {
                        let commitment = blake2b_hmac(key, *salt);
                        let commitment_height = self.get_commitment_height(&commitment)?;
                        self.key_height.insert(*key, commitment_height);
                        self.key_to_value.insert(*key, *value);
                        println!("key {key} was registered successfuly");
                    }
                    Content::Custom(BitNamesOutput::Commitment(commitment)) => {
                        self.commitment_height
                            .insert(*commitment, self.best_block_height);
                    }
                    _ => {}
                }
                self.utxos.insert(outpoint, output);
            }
        }
        for spent_utxo in &spent_utxos {
            match &spent_utxo.content {
                Content::Custom(BitNamesOutput::Commitment(commitment)) => {
                    self.commitment_height.remove(commitment);
                }
                Content::Custom(BitNamesOutput::Reveal { key, .. }) => {
                    self.key_to_value.remove(key);
                }
                _ => {}
            }
        }

        Ok(())
    }
}
