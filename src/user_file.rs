use secrecy::{ExposeSecret, SecretString, Zeroize};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

use chacha20poly1305::aead::{Aead, NewAead, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

use crate::crypto::{
    compute_hash, generate_asymmetric_key, generate_master_key, generate_nonce,
    generate_password_key, generate_salt, EncryptedData, Nonce, Salt, SecretKey,
};
use crate::error::PasswordManagerError;
use constant_time_eq::constant_time_eq;
use ecies_ed25519::PublicKey;
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeStruct;

pub trait Lockable<T: Unlockable<Self>>: Sized {
    fn lock(&self, key: &SecretKey) -> Result<T, PasswordManagerError>;
}

pub trait Unlockable<T: Lockable<Self>>: Sized {
    fn unlock(&self, key: &SecretKey) -> Result<T, PasswordManagerError>;
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicData {
    pub nonce: Nonce,
    pub salt: Salt, // Salt string is not serializable, so we use an array
    pub hash: String,
    pub username: String,
    pub public_key: PublicKey,
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

pub struct PrivateData {
    password_key: SecretKey,
    private_key: ecies_ed25519::SecretKey,
    passwords: Vec<PasswordEntryLocked>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserFileLocked {
    pub public: PublicData,
    private: EncryptedData,
}

#[derive(Clone)]
pub struct UserFileUnlocked {
    pub public: PublicData,
    private: PrivateData,
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
        let nonce = XNonce::from_slice(self.nonce.as_slice());
        let aead = XChaCha20Poly1305::new(&key);

        let plaintext = aead.decrypt(nonce, self.password.as_slice())?;
        // TODO manage unwrap
        let secret = SecretString::from(String::from_utf8(plaintext).unwrap());

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
        // TODO ask if padding for password is necessary (Assuming that adversary knows site name and username then password length is known)
        let ciphertext = aead.encrypt(
            XNonce::from_slice(nonce.as_slice()),
            self.password.expose_secret().as_bytes(),
        )?;
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

impl Unlockable<UserFileUnlocked> for UserFileLocked {
    fn unlock(&self, key: &SecretKey) -> Result<UserFileUnlocked, PasswordManagerError> {
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

        Ok(UserFileUnlocked {
            public: self.public.clone(),
            private: passwords,
        })
    }
}

impl UserFileLocked {
    pub fn verify(&self, master_key: &SecretKey) -> bool {
        constant_time_eq(
            compute_hash(self.public.username.as_str(), master_key).as_bytes(),
            self.public.hash.as_bytes(),
        )
    }
}

impl Lockable<UserFileLocked> for UserFileUnlocked {
    fn lock(&self, key: &SecretKey) -> Result<UserFileLocked, PasswordManagerError> {
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
        Ok(UserFileLocked {
            public,
            private: ciphertext,
        })
    }
}

impl UserFileUnlocked {
    pub fn new(public_data: PublicData, private_data: PrivateData) -> Self {
        UserFileUnlocked {
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

        Ok((UserFileUnlocked::new(public_data, private_data), master_key))
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
        }
    }
}
