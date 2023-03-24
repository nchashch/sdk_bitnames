use crate::hashes::*;
use crate::types::*;
use sdk_authorization_ed25519_dalek::verify_authorizations;
use sdk_types::{validate_body, validate_transaction, OutPoint};
use std::collections::{HashMap, HashSet};

use heed::types::*;
use heed::{Database, RoTxn};

pub struct BitNamesState {
    pub env: heed::Env,

    pub key_to_value: Database<SerdeBincode<Key>, SerdeBincode<Option<Value>>>,
    pub commitment_to_height: Database<SerdeBincode<Commitment>, OwnedType<u32>>,
    pub commitment_to_outpoint: Database<SerdeBincode<Commitment>, SerdeBincode<OutPoint>>,
    pub key_to_commitment: Database<SerdeBincode<Key>, SerdeBincode<Commitment>>,
    pub commitment_to_key: Database<SerdeBincode<Commitment>, SerdeBincode<Key>>,

    pub utxos: Database<SerdeBincode<OutPoint>, SerdeBincode<Output>>,
    pub best_block_height: u32,
}

impl BitNamesState {
    pub fn new(env: &heed::Env) -> Result<Self, Error> {
        let key_to_value = env.create_database(Some("key_to_value"))?;
        let commitment_to_height = env.create_database(Some("commitment_to_height"))?;
        let commitment_to_outpoint = env.create_database(Some("commitment_to_outpoint"))?;
        let key_to_commitment = env.create_database(Some("key_to_commitment"))?;
        let commitment_to_key = env.create_database(Some("commitment_to_key"))?;
        let utxos = env.create_database(Some("utxos"))?;

        Ok(Self {
            env: env.clone(),
            key_to_value,
            commitment_to_height,
            commitment_to_outpoint,
            key_to_commitment,
            commitment_to_key,
            utxos,
            best_block_height: 0,
        })
    }

    pub fn connect_deposits(&self, deposits: &HashMap<OutPoint, Output>) -> Result<(), Error> {
        let mut wtxn = self.env.write_txn()?;
        for (outpoint, deposit) in deposits {
            self.utxos.put(&mut wtxn, outpoint, deposit)?;
        }
        wtxn.commit()?;
        Ok(())
    }

    pub fn get_value(&self, key: &Key) -> Result<Option<Option<Value>>, Error> {
        let rtxn = self.env.read_txn()?;
        Ok(self.key_to_value.get(&rtxn, key)?)
    }

    pub fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<Output>, Error> {
        let rtxn = self.env.read_txn()?;
        Ok(self.utxos.get(&rtxn, outpoint)?)
    }

    fn get_utxos(
        &self,
        txn: &RoTxn,
        inputs: &[OutPoint],
    ) -> (Vec<Option<Output>>, Vec<heed::Error>) {
        let (spent_utxos, errors): (Vec<_>, Vec<_>) = inputs
            .iter()
            .map(|outpoint| self.utxos.get(txn, outpoint))
            .partition(Result::is_ok);
        let spent_utxos: Vec<_> = spent_utxos.into_iter().map(Result::unwrap).collect();
        let errors: Vec<_> = errors.into_iter().map(Result::unwrap_err).collect();
        (spent_utxos, errors)
    }

    pub fn validate_body(&self, block_height: u32, body: &Body) -> Result<u64, Error> {
        verify_authorizations(body)?;
        let rtxn = self.env.read_txn()?;
        let inputs: Vec<OutPoint> = body
            .transactions
            .iter()
            .flat_map(|transaction| transaction.inputs.iter())
            .copied()
            .collect();
        let (spent_utxos, _) = self.get_utxos(&rtxn, &inputs);
        let spent_utxos: Vec<Output> = spent_utxos
            .into_iter()
            .collect::<Option<Vec<Output>>>()
            .unwrap();
        {
            let mut index = 0;
            for transaction in &body.transactions {
                let spent_utxos = &spent_utxos[index..transaction.inputs.len()];
                self.validate_transaction_pure(&rtxn, spent_utxos, block_height, transaction)?;
                index += transaction.inputs.len();
            }
        }
        Ok(validate_body(spent_utxos.as_slice(), body)?)
    }

    fn validate_transaction_pure(
        &self,
        txn: &RoTxn,
        spent_utxos: &[Output],
        block_height: u32,
        transaction: &Transaction,
    ) -> Result<(), Error> {
        let spent_commitments: HashSet<Commitment> = spent_utxos
            .iter()
            .filter_map(|utxo| match utxo.content {
                Content::Custom(BitNamesOutput::Commitment(commitment)) => Some(commitment),
                _ => None,
            })
            .collect();
        let spent_keys: HashSet<Key> = spent_utxos
            .iter()
            .filter_map(|utxo| match utxo.content {
                Content::Custom(BitNamesOutput::Reveal { key, .. }) => Some(key),
                Content::Custom(BitNamesOutput::KeyValue { key, .. }) => Some(key),
                _ => None,
            })
            .collect();
        for commitment in &spent_commitments {
            let height = self.get_commitment_height(txn, commitment)?;
            if block_height - height > COMMITMENT_MAX_AGE {
                Err(BitNamesError::RevealTooLate {
                    commitment: *commitment,
                    late_by: block_height - height - COMMITMENT_MAX_AGE,
                })?;
            }
        }
        for output in &transaction.outputs {
            match output.content {
                Content::Custom(BitNamesOutput::Reveal { salt, key }) => {
                    let commitment = blake2b_hmac(&key, salt);
                    if !spent_commitments.contains(&commitment) {
                        Err(BitNamesError::InvalidNameCommitment {
                            key,
                            salt,
                            commitment,
                        })?;
                    }
                    if self.key_to_value.get(txn, &key)?.is_some() {
                        let commitment_height = self.get_commitment_height(txn, &commitment)?;
                        let prev_commitment_height = self.get_key_height(txn, &key)?;
                        if prev_commitment_height < commitment_height {
                            Err(BitNamesError::KeyAlreadyRegistered {
                                key,
                                prev_commitment_height,
                                commitment_height,
                            })?;
                        }
                    }
                }
                Content::Custom(BitNamesOutput::KeyValue { key, .. }) => {
                    if !spent_keys.contains(&key) {
                        Err(BitNamesError::InvalidKey { key })?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn get_commitment_height(&self, txn: &RoTxn, commitment: &Commitment) -> Result<u32, Error> {
        Ok(self.commitment_to_height.get(txn, commitment)?.ok_or(
            BitNamesError::CommitmentNotFound {
                commitment: *commitment,
            },
        )?)
    }

    fn get_key_height(&self, txn: &RoTxn, key: &Key) -> Result<u32, Error> {
        let commitment = self
            .key_to_commitment
            .get(txn, key)?
            .ok_or(BitNamesError::KeyNotFound { key: *key })?;
        Ok(self
            .commitment_to_height
            .get(txn, &commitment)?
            .ok_or(BitNamesError::CommitmentNotFound { commitment })?)
    }

    pub fn validate_transaction(&self, transaction: &Transaction) -> Result<u64, Error> {
        let rtxn = self.env.read_txn()?;
        let (spent_utxos, _) = self.get_utxos(&rtxn, &transaction.inputs);
        let spent_utxos: Vec<Output> = spent_utxos.into_iter().collect::<Option<Vec<_>>>().unwrap();
        // Will this transaction be valid, if included in next block?
        self.validate_transaction_pure(
            &rtxn,
            &spent_utxos,
            self.best_block_height + 1,
            transaction,
        )?;
        Ok(validate_transaction(&spent_utxos, transaction)?)
    }

    pub fn connect_body(&mut self, body: &Body) -> Result<(), Error> {
        let mut wtxn = self.env.write_txn()?;
        println!(
            "--- connecting body with merkle_root = {} ---",
            body.compute_merkle_root()
        );
        self.validate_body(self.best_block_height + 1, body)?;
        self.best_block_height += 1;

        for transaction in &body.transactions {
            for input in &transaction.inputs {
                self.utxos.delete(&mut wtxn, input)?;
            }
            let txid = transaction.txid();
            for vout in 0..transaction.outputs.len() {
                let outpoint = OutPoint::Regular {
                    txid,
                    vout: vout as u32,
                };
                let output = transaction.outputs[vout].clone();
                match &output.content {
                    Content::Custom(BitNamesOutput::KeyValue { key, value }) => {
                        self.key_to_value.put(&mut wtxn, key, value)?;
                    }
                    Content::Custom(BitNamesOutput::Reveal { key, salt }) => {
                        let commitment = blake2b_hmac(key, *salt);
                        self.key_to_commitment.put(&mut wtxn, key, &commitment)?;
                        self.commitment_to_key.put(&mut wtxn, &commitment, key)?;
                        self.key_to_value.put(&mut wtxn, key, &None)?;
                        println!("key {key} was registered successfuly");
                    }
                    Content::Custom(BitNamesOutput::Commitment(commitment)) => {
                        self.commitment_to_height.put(
                            &mut wtxn,
                            commitment,
                            &self.best_block_height,
                        )?;
                        self.commitment_to_outpoint
                            .put(&mut wtxn, commitment, &outpoint)?;
                    }
                    _ => {}
                }
                self.utxos.put(&mut wtxn, &outpoint, &output)?;
            }
        }
        let mut expired_commitments: Vec<Commitment> = vec![];
        for item in self.commitment_to_height.iter(&wtxn)? {
            let (commitment, height) = item?;
            if self.best_block_height - height > COMMITMENT_MAX_AGE {
                expired_commitments.push(commitment);
            }
        }
        for commitment in &expired_commitments {
            if let Some(key) = self.commitment_to_key.get(&wtxn, commitment)? {
                self.key_to_commitment.delete(&mut wtxn, &key)?;
                self.commitment_to_key.delete(&mut wtxn, commitment)?;
            }
            let outpoint = self.commitment_to_outpoint.get(&wtxn, commitment)?.ok_or(
                BitNamesError::CommitmentNotFound {
                    commitment: *commitment,
                },
            )?;
            self.utxos.delete(&mut wtxn, &outpoint)?;
            self.commitment_to_height.delete(&mut wtxn, commitment)?;
            self.commitment_to_outpoint.delete(&mut wtxn, commitment)?;
        }
        wtxn.commit()?;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("authorization error")]
    Authorization(#[from] sdk_authorization_ed25519_dalek::Error),
    #[error("sdk error")]
    Sdk(#[from] sdk_types::Error),
    #[error("bitnames error")]
    BitNames(#[from] BitNamesError),
    #[error("heed error")]
    Heed(#[from] heed::Error),
}

const COMMITMENT_MAX_AGE: u32 = 1;
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
    #[error("invalid key {key}")]
    InvalidKey { key: Key },
}
