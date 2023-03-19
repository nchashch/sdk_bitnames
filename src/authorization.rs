use crate::hashes::hash;
use crate::types::*;
use ed25519_dalek::{Keypair, Signer};
use std::collections::HashMap;

pub fn authorize_transaction(
    keypairs: &HashMap<Address, Keypair>,
    spent_utxos: &[Output],
    transaction: Transaction,
) -> Transaction {
    let authorizations: Vec<Authorization> = {
        let transaction_hash_without_authorizations = hash(&transaction);
        spent_utxos
            .iter()
            .map(|utxo| {
                let address = utxo.get_address();
                Authorization {
                    public_key: keypairs[&address].public,
                    signature: keypairs[&address].sign(&transaction_hash_without_authorizations),
                }
            })
            .collect()
    };
    Transaction {
        authorizations,
        ..transaction
    }
}
