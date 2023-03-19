mod authorization;
mod hashes;
mod nameserver;
mod random;
mod types;
mod validation;

use authorization::*;
use fake::{Fake, Faker};
use hashes::*;
use nameserver::*;
use random::*;
use std::collections::HashMap;
use types::*;
use validation::*;

fn main() {
    const NUM_KEYPAIRS: usize = 10;
    const NUM_DEPOSITS: usize = 2;
    const DEPOSIT_VALUE: u64 = 100;

    const NUM_INPUTS: usize = 1;

    let keypairs = random_keypairs(NUM_KEYPAIRS);
    let addresses: Vec<Address> = keypairs.keys().copied().collect();
    let utxos = random_deposits(&addresses, DEPOSIT_VALUE, NUM_DEPOSITS);
    let (inputs, spent_utxos, value_in) = random_inputs(&utxos, NUM_INPUTS);

    let key: Key = hash(&"nytimes.com").into();
    let value: Value = hash(&"151.101.193.164").into();

    let mut validator = BitNamesValidator {
        utxos,
        key_to_value: HashMap::new(),
        //key_to_value: HashMap::from([(key, [0; 32].into())]),
    };
    let commitment_transaction = {
        let salt: u32 = Faker.fake();
        let commitment = blake2b_hmac(&key, salt);
        let outputs = vec![
            Output::Regular {
                value: value_in - 10,
                address: addresses[0],
            },
            Output::Custom {
                address: addresses[1],
                custom: BitNamesOutput::Commitment { salt, commitment },
            },
        ];
        let unsigned_transaction = Transaction {
            inputs,
            outputs,
            authorizations: vec![],
        };
        authorize_transaction(&keypairs, &spent_utxos, unsigned_transaction)
    };

    dbg!(&validator);
    validator
        .execute_transaction(&commitment_transaction)
        .unwrap();

    let name_transaction = {
        let commitment_outpoint = OutPoint::Regular {
            txid: commitment_transaction.txid(),
            vout: 1,
        };
        let spent_utxos = vec![validator.utxos[&commitment_outpoint].clone()];
        let inputs = vec![commitment_outpoint];
        let outputs = vec![Output::Custom {
            address: addresses[2],
            custom: BitNamesOutput::Name { key, value },
        }];
        let unsigned_transaction = Transaction {
            inputs,
            outputs,
            authorizations: vec![],
        };
        authorize_transaction(&keypairs, &spent_utxos, unsigned_transaction)
    };
    dbg!(&validator);
    validator.execute_transaction(&name_transaction).unwrap();
    dbg!(&validator);

    let mut nameserver = NameServer::default();
    nameserver
        .store(&validator, "nytimes.com", "151.101.193.164")
        .unwrap();
    let value = nameserver.lookup(&validator, "nytimes.com").unwrap();
    dbg!(value);
}
