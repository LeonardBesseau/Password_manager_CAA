use crate::crypto::{sign_message, verify_message};
use crate::error::PasswordManagerError;
use ed25519_dalek::Signature;
use serde::{ Deserialize, Serialize};
use crate::data::password::{PasswordEntryUnlocked};


#[derive(Serialize, Deserialize)]
pub struct SharedPassword {
    pub(crate) password: PasswordEntryUnlocked,
    pub(crate) signature: Signature,
}

impl SharedPassword {
    pub fn new(
        password: PasswordEntryUnlocked,
        username: &str,
        private_key: &ed25519_dalek::SecretKey,
        public_key: &ed25519_dalek::PublicKey,
    ) -> Result<Self, PasswordManagerError> {
        Ok(SharedPassword {
            password,
            signature: sign_message(username, private_key, public_key)?,
        })
    }

    pub fn verify(&self, username: &str, public_key: &ed25519_dalek::PublicKey) -> Result<bool, PasswordManagerError> {
        verify_message(username, &self.signature, public_key)
    }
}
