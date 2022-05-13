use std::str::FromStr;
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use crate::ca::{sign_public_key, verify_public_key};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Identity{
    pub username: String,
    pub sharing_public_key: ecies_ed25519::PublicKey,
    pub signing_public_key: ed25519_dalek::PublicKey,
    pub signature: Signature,
}

impl Identity{
    pub fn new(username: &String, sharing_public_key: ecies_ed25519::PublicKey, signature_public_key: ed25519_dalek::PublicKey) -> Self{
        Identity {
            username: username.clone(),
            sharing_public_key,
            signing_public_key: signature_public_key,
            signature: sign_public_key(username,  &sharing_public_key, &signature_public_key)
        }
    }

    pub fn fake() -> Self{
        Identity{
            username: "".parse().unwrap(),
            sharing_public_key: Default::default(),
            signing_public_key: Default::default(),
            signature: Signature::from_str("AFDF902050EB00E80DC6C0B2C0F6F548055F9AF7AD7FFAF0C00CE2F3B7D342344248B80DF8C49D5B8EC84448D0EC0E749834037D9DDC3BABCA4D6EECE2F62301").unwrap(),

        }
    }

    pub fn verify_identity(&self) -> bool{
        verify_public_key(
            self.username.as_str(),
            &self.sharing_public_key,
            &self.signing_public_key,
            &self.signature,
        )
    }
}