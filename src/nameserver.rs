use crate::hashes::*;
use crate::validation::BitNamesValidator;
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct NameServer {
    data: HashMap<Key, String>,
}

impl NameServer {
    pub fn store(
        &mut self,
        validator: &BitNamesValidator,
        name: &str,
        value: &str,
    ) -> Result<(), String> {
        let key: Key = hash(&name).into();
        if let Some(value_hash) = validator.key_to_value.get(&key) {
            if Value::from(hash(&value)) != *value_hash {
                return Err(format!("attempting to store invalid value: {value}"));
            }
            self.data.insert(key, value.into());
            Ok(())
        } else {
            Err(format!("{name} is not registered"))
        }
    }

    pub fn lookup(&self, validator: &BitNamesValidator, name: &str) -> Result<String, String> {
        let key: Key = hash(&name).into();
        if let Some(value_hash) = validator.key_to_value.get(&key) {
            let value = self.data[&key].clone();
            if Value::from(hash(&value)) != *value_hash {
                return Err(format!("store has invalid value for {key}"));
            }
            Ok(value)
        } else {
            Err(format!("{name} is not registered"))
        }
    }
}
