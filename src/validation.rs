use crate::types::*;
use crate::hashes::*;
use std::collections::HashMap;
use sdk_types::{OutPoint, Validator, CustomValidator};

#[derive(Debug)]
pub struct BitNamesValidator {
    pub key_to_value: HashMap<Key, Value>,
    pub utxos: HashMap<OutPoint, Output>,
}

impl BitNamesValidator {
    fn validate_tx(&self, transaction: &Transaction) -> Result<u64, String> {
        let spent_utxos: Vec<Output> = transaction
            .inputs
            .iter()
            .map(|input| self.utxos[input].clone())
            .collect();
        self.validate_transaction(&spent_utxos, transaction)
    }

    pub fn execute_transaction(&mut self, transaction: &Transaction) -> Result<(), String> {
        self.validate_tx(transaction)?;
        println!();
        println!("--- EXECUTING TRANSACTION {} ---", transaction.txid());
        println!();
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
            match &output {
                Output::Custom {
                    custom: BitNamesOutput::Name { key, value },
                    ..
                } => {
                    self.key_to_value.insert(*key, *value);
                    println!("key {key} was registered successfuly");
                }
                _ => {}
            }
            self.utxos.insert(outpoint, output);
        }
        Ok(())
    }
}

impl CustomValidator<BitNamesOutput> for BitNamesValidator {
    fn custom_validate_transaction(
        &self,
        spent_utxos: &[Output],
        transaction: &Transaction,
    ) -> Result<(), String> {
        let spent_commitments: Vec<(u32, Commitment)> = spent_utxos
            .iter()
            .filter_map(|utxo| match utxo {
                Output::Custom {
                    custom: BitNamesOutput::Commitment { salt, commitment },
                    ..
                } => Some((*salt, *commitment)),
                _ => None,
            })
            .collect();
        let name_outputs = transaction
            .outputs
            .iter()
            .filter_map(|output| match output {
                Output::Custom {
                    custom: BitNamesOutput::Name { key, value },
                    ..
                } => Some((key, value)),
                _ => None,
            });
        if spent_commitments.len() > 1 {
            return Err("can not spend more than 1 commitment per transaction".into());
        }
        for (key, _) in name_outputs {
            let (salt, commitment) = spent_commitments[0];
            if blake2b_hmac(key, salt) != commitment {
                return Err("invalid name commitment".into());
            }
            if self.key_to_value.contains_key(key) {
                return Err(format!("key {key} was already registered"));
            }
        }
        Ok(())
    }
}

impl Validator<BitNamesOutput> for BitNamesValidator {}
