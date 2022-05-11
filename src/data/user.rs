use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use chacha20poly1305::aead::{Aead, NewAead, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

use crate::ca::verify_public_key;
use crate::crypto::{
    compute_hash, EncryptedData, generate_asymmetric_key, generate_master_key,
    generate_nonce, generate_password_key, generate_salt, SecretKey,
};
use crate::data::password::{PasswordEntryLocked, PasswordEntryUnlocked};
use crate::error::PasswordManagerError;
use constant_time_eq::constant_time_eq;
use ed25519_dalek::Signature;
use crate::data::private::PrivateData;
use crate::data::public::PublicData;

pub trait Lockable<T: Unlockable<Self>>: Sized {
    fn lock(&self, key: &SecretKey) -> Result<T, PasswordManagerError>;
}

pub trait Unlockable<T: Lockable<Self>>: Sized {
    fn unlock(&self, key: &SecretKey) -> Result<T, PasswordManagerError>;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserDataLocked {
    pub public: PublicData,
    private: EncryptedData,
}

#[derive(Clone)]
pub struct UserDataUnlocked {
    pub public: PublicData,
    private: PrivateData,
}

impl Unlockable<UserDataUnlocked> for UserDataLocked {
    fn unlock(&self, key: &SecretKey) -> Result<UserDataUnlocked, PasswordManagerError> {
        let key = Key::from_slice(key.expose_secret().as_slice());
        let nonce = XNonce::from_slice(self.public.nonce.as_slice());
        let aead = XChaCha20Poly1305::new(&key);

        let public_data = bincode::serialize(&self.public)?;

        let plaintext = aead.decrypt(
            nonce,
            Payload {
                msg: self.private.as_slice(),
                aad: public_data.as_slice(),
            },
        )?;

        let passwords: PrivateData = bincode::deserialize(&plaintext)?;

        Ok(UserDataUnlocked {
            public: self.public.clone(),
            private: passwords,
        })
    }
}

impl UserDataLocked {
    pub fn fake() -> Self {
        UserDataLocked {
            public: PublicData {
                nonce: [0; 24],
                salt: [0; 16],
                hash: "".to_string(),
                username: "".to_string(),
                public_key: Default::default(),
                signature: Signature::from_str("AFDF902050EB00E80DC6C0B2C0F6F548055F9AF7AD7FFAF0C00CE2F3B7D342344248B80DF8C49D5B8EC84448D0EC0E749834037D9DDC3BABCA4D6EECE2F62301").unwrap(),
            },
            private: vec![],
        }
    }

    pub fn verify_master_key(&self, master_key: &SecretKey) -> bool {
        constant_time_eq(
            compute_hash(self.public.username.as_str(), master_key).as_bytes(),
            self.public.hash.as_bytes(),
        )
    }

    pub fn verify_public_key(&self) -> bool {
        verify_public_key(
            self.public.username.as_str(),
            &self.public.public_key,
            &self.public.signature,
        )
    }
}

impl Lockable<UserDataLocked> for UserDataUnlocked {
    fn lock(&self, key: &SecretKey) -> Result<UserDataLocked, PasswordManagerError> {
        let key = Key::from_slice(key.expose_secret().as_slice());
        let nonce = generate_nonce();
        let aead = XChaCha20Poly1305::new(&key);
        let mut public = self.public.clone();
        public.nonce = nonce.clone();
        let private_data = bincode::serialize(&self.private)?;
        let public_data = bincode::serialize(&public)?;

        let ciphertext = aead.encrypt(
            XNonce::from_slice(nonce.as_slice()),
            Payload {
                msg: private_data.as_slice(),
                aad: public_data.as_slice(),
            },
        )?;
        Ok(UserDataLocked {
            public,
            private: ciphertext,
        })
    }
}

impl UserDataUnlocked {
    pub fn new(public_data: PublicData, private_data: PrivateData) -> Self {
        UserDataUnlocked {
            public: public_data,
            private: private_data,
        }
    }

    pub fn get_password_list(&self) -> &Vec<PasswordEntryLocked> {
        &self.private.passwords
    }

    pub fn add_password(
        &mut self,
        site: &str,
        username: &str,
        password: SecretString,
        shared_by: Option<String>,
    ) -> Result<(), PasswordManagerError> {
        let entry = PasswordEntryUnlocked::new(site, username, password, shared_by)
            .lock(&self.private.password_key)?;
        self.private.passwords.push(entry);
        Ok(())
    }

    pub fn get_password(
        &self,
        index: usize,
    ) -> Result<PasswordEntryUnlocked, PasswordManagerError> {
        self.private
            .passwords
            .get(index)
            .unwrap()
            .clone()
            .unlock(&self.private.password_key)
    }

    pub fn get_private_key(&self) -> &ecies_ed25519::SecretKey {
        &self.private.private_key
    }

    pub fn change_key(
        self,
        new_password: SecretString,
    ) -> Result<(Self, SecretKey), PasswordManagerError> {
        let (salt, salt_buf) = generate_salt();
        let master_key = generate_master_key(new_password, &salt)?;
        let password_key = generate_password_key();
        let (private_key, public_key) = generate_asymmetric_key();
        let private_data = self.private.change_key(password_key, private_key)?;
        let public_data = PublicData::new(
            salt_buf,
            compute_hash(self.public.username.as_str(), &master_key),
            &self.public.username,
            public_key,
        );

        Ok((UserDataUnlocked::new(public_data, private_data), master_key))
    }
}
