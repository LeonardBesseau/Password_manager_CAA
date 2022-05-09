use std::error::Error;
use std::fmt::{Display, Formatter};
use secrecy::{ExposeSecret, SecretString, Zeroize};
use serde::{Serialize, Deserialize};

use chacha20poly1305::{XChaCha20Poly1305, Key, XNonce};
use chacha20poly1305::aead::{Aead, NewAead, Payload};

use constant_time_eq::constant_time_eq;
use crate::password::{compute_hash, EncryptedData, generate_nonce, Nonce, Salt, SecretKey};


#[derive(Debug)]
pub enum UserFileError {
    Encryption(chacha20poly1305::aead::Error),
    Serialisation(bincode::Error),
}

pub trait Lockable<T: Unlockable<Self>>: Sized {
    fn lock(&self, key: &SecretKey) -> Result<T, UserFileError>;
}

pub trait Unlockable<T: Lockable<Self>>: Sized {
    fn unlock(&self, key: &SecretKey) -> Result<T, UserFileError>;
}


#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicData {
    pub nonce: Nonce,
    pub salt: Salt,
    pub hash: String,
    pub username: String,
}


#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PasswordEntryLocked {
    pub site: String,
    nonce: Nonce,
    username: String,
    password: EncryptedData,
}

pub struct PasswordEntryUnlocked {
    pub site: String,
    pub username: String,
    pub password: SecretString,
}

pub struct PrivateData {
    password_key: SecretKey,
    passwords: Vec<PasswordEntryLocked>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PrivateDataSerialize {
    password_key: [u8; 32],
    passwords: Vec<PasswordEntryLocked>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserFileLocked {
    pub public: PublicData,
    private: EncryptedData,
}

pub struct UserFileUnlocked {
    pub public: PublicData,
    private: PrivateData,
}


impl Error for UserFileError {}

impl Display for UserFileError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match *self {
            UserFileError::Encryption(ref err) => write!(f, "Encryption/Decryption error {}", err),
            UserFileError::Serialisation(ref err) => write!(f, "Serialisation error: {}", err)
        }
    }
}

impl From<chacha20poly1305::aead::Error> for UserFileError {
    fn from(err: chacha20poly1305::aead::Error) -> UserFileError {
        UserFileError::Encryption(err)
    }
}

impl From<bincode::Error> for UserFileError {
    fn from(err: bincode::Error) -> UserFileError {
        UserFileError::Serialisation(err)
    }
}

impl PrivateDataSerialize {
    fn convert(self) -> PrivateData {
        let output = PrivateData {
            password_key: SecretKey::new(Vec::from(self.password_key)),
            passwords: self.passwords,
        };
        output
    }
}

impl Zeroize for PrivateDataSerialize {
    fn zeroize(&mut self) {
        self.password_key.zeroize();
        self.passwords.zeroize();
    }
}


impl PrivateData {
    fn convert(&self) -> PrivateDataSerialize {
        PrivateDataSerialize {
            password_key: <[u8; 32]>::try_from(self.password_key.expose_secret().as_slice()).unwrap(),
            passwords: self.passwords.clone(),
        }
    }

    pub fn new(password_key: SecretKey, passwords: Vec<PasswordEntryLocked>) -> Self {
        PrivateData { password_key, passwords }
    }
}

impl Unlockable<PasswordEntryUnlocked> for PasswordEntryLocked {
    fn unlock(&self, key: &SecretKey) -> Result<PasswordEntryUnlocked, UserFileError> {
        let key = Key::from_slice(key.expose_secret().as_slice());
        let nonce = XNonce::from_slice(self.nonce.as_slice());
        let aead = XChaCha20Poly1305::new(&key);

        let plaintext = aead.decrypt(nonce, self.password.as_slice())?;
        // TODO manage unwrap
        let secret = SecretString::from(String::from_utf8(plaintext).unwrap());

        Ok(PasswordEntryUnlocked {
            site: self.site.clone(),
            username: self.username.clone(),
            password: secret,
        })
    }
}

impl Lockable<PasswordEntryLocked> for PasswordEntryUnlocked {
    fn lock(&self, key: &SecretKey) -> Result<PasswordEntryLocked, UserFileError> {
        let key = Key::from_slice(key.expose_secret().as_slice());
        let nonce = generate_nonce();
        let aead = XChaCha20Poly1305::new(&key);
        // TODO ask if padding for password is necessary (Assuming that adversary knows site name and username then password length is known)
        let ciphertext = aead.encrypt(XNonce::from_slice(nonce.as_slice()), self.password.expose_secret().as_bytes())?;
        Ok(PasswordEntryLocked {
            site: self.site.clone(),
            nonce,
            username: self.username.clone(),
            password: ciphertext,
        })
    }
}


impl PasswordEntryUnlocked {
    fn new(site: &str, username: &str, password: SecretString) -> Self {
        PasswordEntryUnlocked {
            site: String::from(site),
            username: String::from(username),
            password,
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

impl Unlockable<UserFileUnlocked> for UserFileLocked {
    fn unlock(&self, key: &SecretKey) -> Result<UserFileUnlocked, UserFileError> {
        let key = Key::from_slice(key.expose_secret().as_slice());
        let nonce = XNonce::from_slice(self.public.nonce.as_slice());
        let aead = XChaCha20Poly1305::new(&key);

        let public_data = bincode::serialize(&self.public)?;

        let plaintext = aead.decrypt(nonce, Payload { msg: self.private.as_slice(), aad: public_data.as_slice() })?;

        let passwords: PrivateDataSerialize = bincode::deserialize(&plaintext)?;

        Ok(UserFileUnlocked { public: self.public.clone(), private: passwords.convert() })
    }
}


impl UserFileLocked {
    pub fn verify(&self, master_key: &SecretKey) -> bool {
        constant_time_eq(compute_hash(self.public.username.as_str(), master_key).as_bytes(), self.public.hash.as_bytes())
    }

    pub fn unlock(self, master_key: &SecretKey) -> Result<UserFileUnlocked, UserFileError> {
        let key = Key::from_slice(master_key.expose_secret().as_slice());
        let nonce = XNonce::from_slice(self.public.nonce.as_slice());
        let aead = XChaCha20Poly1305::new(&key);

        let public_data = bincode::serialize(&self.public)?;

        let plaintext = aead.decrypt(nonce, Payload { msg: self.private.as_slice(), aad: public_data.as_slice() })?;

        let passwords: PrivateDataSerialize = bincode::deserialize(&plaintext)?;

        Ok(UserFileUnlocked { public: self.public, private: passwords.convert() })
    }
}


impl Lockable<UserFileLocked> for UserFileUnlocked {
    fn lock(&self, key: &SecretKey) -> Result<UserFileLocked, UserFileError> {
        let key = Key::from_slice(key.expose_secret().as_slice());
        let nonce = XNonce::from_slice(self.public.nonce.as_slice());
        let aead = XChaCha20Poly1305::new(&key);

        let private_data = bincode::serialize(&(self.private.convert()))?;
        let public_data = bincode::serialize(&self.public)?;

        let ciphertext = aead.encrypt(nonce, Payload { msg: private_data.as_slice(), aad: public_data.as_slice() })?;

        Ok(UserFileLocked { public: self.public.clone(), private: ciphertext })
    }
}

impl UserFileUnlocked {
    pub fn new(public_data: PublicData, private_data: PrivateData) -> Self {
        UserFileUnlocked { public: public_data, private: private_data }
    }

    pub fn get_password_list(&self) -> &Vec<PasswordEntryLocked> {
        &self.private.passwords
    }

    pub fn add_password(&mut self, site: &str, username: &str, password: SecretString) -> Result<(), UserFileError> {
        let entry = PasswordEntryUnlocked::new(site, username, password).lock(&self.private.password_key)?;
        self.private.passwords.push(entry);
        Ok(())
    }

    pub fn get_password(&self, index: usize) -> Result<PasswordEntryUnlocked, UserFileError> {
        self.private.passwords.get(index).unwrap().clone().unlock(&self.private.password_key)
    }
}

impl PublicData {
    pub fn new(nonce: [u8; 24], salt: [u8; 16], hash: String, username: &String) -> Self {
        PublicData {
            nonce,
            salt,
            hash,
            username: username.clone(),
        }
    }
}