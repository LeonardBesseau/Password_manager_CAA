use crate::identity_autority::{sign_identity, verify_identity};
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Identity {
    pub username: String,
    pub sharing_public_key: ecies_ed25519::PublicKey,
    pub signing_public_key: ed25519_dalek::PublicKey,
    pub signature: Signature,
}

impl Identity {
    pub fn new(
        username: &str,
        sharing_public_key: ecies_ed25519::PublicKey,
        signature_public_key: ed25519_dalek::PublicKey,
    ) -> Self {
        Identity {
            username: username.to_string(),
            sharing_public_key,
            signing_public_key: signature_public_key,
            signature: sign_identity(username, &sharing_public_key, &signature_public_key),
        }
    }

    pub fn fake() -> Self {
        Identity{
            username: "".parse().unwrap(),
            sharing_public_key: Default::default(),
            signing_public_key: Default::default(),
            signature: Signature::from_str("AFDF902050EB00E80DC6C0B2C0F6F548055F9AF7AD7FFAF0C00CE2F3B7D342344248B80DF8C49D5B8EC84448D0EC0E749834037D9DDC3BABCA4D6EECE2F62301").unwrap(),

        }
    }

    ///
    ///
    ///
    pub fn verify_identity(&self, expected_username: &str) -> bool {
        expected_username == self.username
            && verify_identity(
                self.username.as_str(),
                &self.sharing_public_key,
                &self.signing_public_key,
                &self.signature,
            )
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::generate_keys;
    use crate::data::identity::Identity;
    use ed25519_dalek::{Keypair, Signer};

    fn generate_identity(username: &str) -> Identity {
        let username = username.to_string();
        let (_, share, sign) = generate_keys();
        Identity::new(&username, share.1, sign.1)
    }

    #[test]
    fn unmodified_identity_is_ok() {
        let identity = generate_identity("test");
        assert_eq!(identity.verify_identity("test"), true);
    }

    #[test]
    fn fake_identity_is_invalid() {
        let identity = Identity::fake();
        assert_eq!(identity.verify_identity("test"), false);
    }

    #[test]
    fn modified_username_is_detected() {
        let mut identity = generate_identity("test");
        identity.username = "FAKE".parse().unwrap();
        assert_eq!(identity.verify_identity("test"), false);
    }

    #[test]
    fn modified_sharing_keys_is_detected() {
        let mut identity = generate_identity("test");
        let (_, keys, _) = generate_keys();
        identity.sharing_public_key = keys.1;
        assert_eq!(identity.verify_identity("test"), false);
    }

    #[test]
    fn modified_signing_keys_is_detected() {
        let mut identity = generate_identity("test");
        let (_, _, keys) = generate_keys();
        identity.signing_public_key = keys.1;
        assert_eq!(identity.verify_identity("test"), false);
    }

    #[test]
    fn crafted_signature_is_detected() {
        let mut identity = generate_identity("test");
        let keypair = Keypair::generate(&mut rand_7::thread_rng());
        let mut data = Vec::from(identity.sharing_public_key.to_bytes());
        data.extend_from_slice(identity.signing_public_key.as_bytes());
        data.extend_from_slice(identity.username.as_bytes());
        identity.signature = keypair.sign(data.as_slice());
        assert_eq!(identity.verify_identity("test"), false);
    }
}
