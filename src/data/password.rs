use crate::crypto::{generate_nonce, EncryptedData, Nonce, SecretKey};
use crate::data::user::{Lockable, Unlockable};
use crate::error::PasswordManagerError;
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use secrecy::{ExposeSecret, SecretString, Zeroize};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct Password {
    size: usize,
    // we have to use a Vec because serde does not manage array > 32
    payload: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PasswordEntryLocked {
    pub site: String,
    nonce: Nonce,
    username: String,
    password: EncryptedData,
    pub shared_by: Option<String>,
}

pub struct PasswordEntryUnlocked {
    pub site: String,
    pub username: String,
    pub password: SecretString,
    pub shared_by: Option<String>,
}

impl Zeroize for Password {
    fn zeroize(&mut self) {
        self.payload.zeroize();
        self.size.zeroize();
    }
}

impl Drop for Password {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Password {
    pub const MAX_LEN: usize = 64;

    fn new(password: SecretString) -> Self {
        let mut payload = password.expose_secret().clone().into_bytes();
        let size = payload.len();
        payload.reserve(Password::MAX_LEN - size);
        for _ in size..Password::MAX_LEN {
            payload.push(0);
        }
        Password { size, payload }
    }

    fn encrypt(
        password: &SecretString,
        aead: XChaCha20Poly1305,
        nonce: Nonce,
    ) -> Result<Vec<u8>, PasswordManagerError> {
        if password.expose_secret().len() > Password::MAX_LEN {
            return Err(PasswordManagerError::InvalidParameter);
        }
        let mut password = bincode::serialize(&Password::new(password.clone()))?;
        let ciphertext = aead.encrypt(XNonce::from_slice(nonce.as_slice()), password.as_slice())?;
        password.zeroize();
        Ok(ciphertext)
    }

    fn decrypt(
        password: &Vec<u8>,
        aead: XChaCha20Poly1305,
        nonce: Nonce,
    ) -> Result<SecretString, PasswordManagerError> {
        let plaintext = aead.decrypt(XNonce::from_slice(nonce.as_slice()), password.as_slice())?;
        let mut password: Password = bincode::deserialize(&plaintext)?;
        password.payload.resize((&password).size, 0);
        Ok(SecretString::from(
            String::from_utf8(password.payload.clone()).unwrap(),
        ))
    }
}

impl Unlockable<PasswordEntryUnlocked> for PasswordEntryLocked {
    fn unlock(&self, key: &SecretKey) -> Result<PasswordEntryUnlocked, PasswordManagerError> {
        let key = Key::from_slice(key.expose_secret().as_slice());
        let aead = XChaCha20Poly1305::new(&key);

        let secret = Password::decrypt(&self.password, aead, self.nonce)?;

        Ok(PasswordEntryUnlocked {
            site: self.site.clone(),
            username: self.username.clone(),
            password: secret,
            shared_by: self.shared_by.clone(),
        })
    }
}

impl Lockable<PasswordEntryLocked> for PasswordEntryUnlocked {
    fn lock(&self, key: &SecretKey) -> Result<PasswordEntryLocked, PasswordManagerError> {
        let key = Key::from_slice(key.expose_secret().as_slice());
        let nonce = generate_nonce();
        let aead = XChaCha20Poly1305::new(&key);

        let ciphertext = Password::encrypt(&self.password, aead, nonce)?;

        Ok(PasswordEntryLocked {
            site: self.site.clone(),
            nonce,
            username: self.username.clone(),
            password: ciphertext,
            shared_by: self.shared_by.clone(),
        })
    }
}

impl PasswordEntryUnlocked {
    pub(crate) fn new(
        site: &str,
        username: &str,
        password: SecretString,
        shared_by: Option<String>,
    ) -> Self {
        PasswordEntryUnlocked {
            site: String::from(site),
            username: String::from(username),
            password,
            shared_by,
        }
    }
}

impl Zeroize for PasswordEntryLocked {
    fn zeroize(&mut self) {
        self.password.zeroize();
        self.site.zeroize();
        self.username.zeroize();
    }
}
