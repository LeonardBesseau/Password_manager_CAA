use crate::crypto::Salt;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicData {
    // SaltString is not serializable, so we use an array instead
    pub salt: Salt,
    pub hash: String,
}

impl PublicData {
    pub fn new(salt: Salt, hash: String) -> Self {
        PublicData { salt, hash }
    }
}
