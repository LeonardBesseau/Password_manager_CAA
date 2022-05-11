use secrecy::{ExposeSecret, SecretString, Zeroize};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

use chacha20poly1305::aead::{Aead, NewAead, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

use crate::crypto::{
    compute_hash, generate_asymmetric_key, generate_master_key, generate_nonce,
    generate_password_key, generate_salt, EncryptedData, Nonce, Salt, SecretKey,
};
use crate::error::PasswordManagerError;
use constant_time_eq::constant_time_eq;
use ecies_ed25519::PublicKey;
use ed25519_dalek::Signature;
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeStruct;
use crate::ca::{sign_public_key, verify_public_key};

pub trait Lockable<T: Unlockable<Self>>: Sized {
    fn lock(&self, key: &SecretKey) -> Result<T, PasswordManagerError>;
}

pub trait Unlockable<T: Lockable<Self>>: Sized {
    fn unlock(&self, key: &SecretKey) -> Result<T, PasswordManagerError>;
}

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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PasswordEntryLocked {
    pub site: String,
    nonce: Nonce,
    username: String,
    password: EncryptedData,
    pub shared_by: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Password {
    size: usize,
    // we have to use a Vec because serde does not manage array > 32
    payload: Vec<u8>,
}

pub struct PasswordEntryUnlocked {
    pub site: String,
    pub username: String,
    pub password: SecretString,
    pub shared_by: Option<String>,
}

pub struct PrivateData {
    password_key: SecretKey,
    private_key: ecies_ed25519::SecretKey,
    passwords: Vec<PasswordEntryLocked>,
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

impl Clone for PrivateData {
    fn clone(&self) -> Self {
        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(self.private_key.as_bytes());
        PrivateData {
            password_key: SecretKey::new(self.password_key.expose_secret().clone()),
            private_key: ecies_ed25519::SecretKey::from_bytes(bits.as_slice()).unwrap(),
            passwords: self.passwords.clone(),
        }
    }
}

impl Serialize for PrivateData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        let mut state = serializer.serialize_struct("PrivateData", 3)?;
        state.serialize_field("password_key", &self.password_key.expose_secret())?;
        state.serialize_field("private_key", &self.private_key)?;
        state.serialize_field("passwords", &self.passwords)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for PrivateData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
    {
        enum Field {
            PasswordKey,
            PrivateKey,
            Passwords,
        }

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
                where
                    D: Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str("`password_key` or `private_key` or `passwords`")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                        where
                            E: de::Error,
                    {
                        match value {
                            "password_key" => Ok(Field::PasswordKey),
                            "private_key" => Ok(Field::PrivateKey),
                            "passwords" => Ok(Field::Passwords),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct PrivateDataVisitor;

        impl<'de> Visitor<'de> for PrivateDataVisitor {
            type Value = PrivateData;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct PrivateData")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<PrivateData, V::Error>
                where
                    V: SeqAccess<'de>,
            {
                let password_key: Vec<u8> = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let password_key = SecretKey::new(password_key);
                let private_key = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let passwords = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                Ok(PrivateData {
                    password_key,
                    private_key,
                    passwords,
                })
            }

            fn visit_map<V>(self, mut map: V) -> Result<PrivateData, V::Error>
                where
                    V: MapAccess<'de>,
            {
                let mut password_key = None;
                let mut private_key = None;
                let mut passwords = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::PasswordKey => {
                            if password_key.is_some() {
                                return Err(de::Error::duplicate_field("password_key"));
                            }
                            let p: Vec<u8> = map.next_value()?;
                            password_key = Some(SecretKey::new(p));
                        }
                        Field::PrivateKey => {
                            if private_key.is_some() {
                                return Err(de::Error::duplicate_field("private_key"));
                            }
                            private_key = Some(map.next_value()?);
                        }
                        Field::Passwords => {
                            if passwords.is_some() {
                                return Err(de::Error::duplicate_field("passwords"));
                            }
                            passwords = Some(map.next_value()?);
                        }
                    }
                }
                let password_key =
                    password_key.ok_or_else(|| de::Error::missing_field("password_key"))?;
                let private_key =
                    private_key.ok_or_else(|| de::Error::missing_field("private_key"))?;
                let passwords = passwords.ok_or_else(|| de::Error::missing_field("passwords"))?;
                Ok(PrivateData {
                    password_key,
                    private_key,
                    passwords,
                })
            }
        }
        const FIELDS: &'static [&'static str] = &["password_key", "private_key", "passwords"];
        deserializer.deserialize_struct("PrivateData", FIELDS, PrivateDataVisitor)
    }
}

impl PrivateData {
    pub fn new(
        password_key: SecretKey,
        private_key: ecies_ed25519::SecretKey,
        passwords: Vec<PasswordEntryLocked>,
    ) -> Self {
        PrivateData {
            password_key,
            private_key,
            passwords,
        }
    }

    pub fn change_key(
        self,
        new_key: SecretKey,
        new_private_key: ecies_ed25519::SecretKey,
    ) -> Result<Self, PasswordManagerError> {
        let mut new_entries: Vec<PasswordEntryLocked> = Vec::with_capacity(self.passwords.len());
        for entry in self.passwords {
            new_entries.push(entry.unlock(&self.password_key)?.lock(&new_key)?);
        }
        Ok(PrivateData {
            password_key: new_key,
            private_key: new_private_key,
            passwords: new_entries,
        })
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
    fn new(site: &str, username: &str, password: SecretString, shared_by: Option<String>) -> Self {
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
        verify_public_key(self.public.username.as_str(), &self.public.public_key, &self.public.signature)
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
