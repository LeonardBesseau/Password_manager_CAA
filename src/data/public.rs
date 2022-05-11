use ecies_ed25519::PublicKey;
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use crate::ca::sign_public_key;
use crate::crypto::{Nonce, Salt};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicData {
    pub nonce: Nonce,
    // SaltString is not serializable, so we use an array instead
    pub salt: Salt,
    pub hash: String,
    pub username: String,
    pub public_key: PublicKey,
    pub signature: Signature,
}

impl PublicData {
    pub fn new(salt: Salt, hash: String, username: &String, public_key: PublicKey) -> Self {
        PublicData {
            nonce: [0; 24], // We set the nonce to 0 as it will be overwritten when locking the file
            salt,
            hash,
            username: username.clone(),
            public_key,
            signature: sign_public_key(username.as_str(), &public_key),
        }
    }
}
