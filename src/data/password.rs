use std::fmt;
use crate::crypto::{generate_nonce, EncryptedData, Nonce, SecretKey};
use crate::data::user::{Lockable, Unlockable};
use crate::error::PasswordManagerError;
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use secrecy::{ExposeSecret, SecretString, Zeroize};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeStruct;

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

impl Serialize for PasswordEntryUnlocked {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        let mut state = serializer.serialize_struct("PasswordEntryUnlocked", 4)?;
        state.serialize_field("site", &self.site)?;
        state.serialize_field("username", &self.username)?;
        state.serialize_field("password", &self.password.expose_secret())?;
        state.serialize_field("shared_by", &self.shared_by)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for PasswordEntryUnlocked {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
    {
        enum Field {
            Site,
            Username,
            Password,
            SharedBy,
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
                        formatter.write_str("`site` or `username` or `password` or `shared_by`")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                        where
                            E: de::Error,
                    {
                        match value {
                            "site" => Ok(Field::Site),
                            "username" => Ok(Field::Username),
                            "password" => Ok(Field::Password),
                            "shared_by" => Ok(Field::SharedBy),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct PrivateDataVisitor;

        impl<'de> Visitor<'de> for PrivateDataVisitor {
            type Value = PasswordEntryUnlocked;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct PasswordEntryUnlocked")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<PasswordEntryUnlocked, V::Error>
                where
                    V: SeqAccess<'de>,
            {
                let site = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let username = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let password: String = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let password = SecretString::new(password);
                let shared_by = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                Ok(PasswordEntryUnlocked {
                    site,
                    username,
                    password,
                    shared_by,
                })
            }

            fn visit_map<V>(self, mut map: V) -> Result<PasswordEntryUnlocked, V::Error>
                where
                    V: MapAccess<'de>,
            {
                let mut site = None;
                let mut username = None;
                let mut password = None;
                let mut shared_by = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Site => {
                            if site.is_some() {
                                return Err(de::Error::duplicate_field("site"));
                            }
                            site = Some(map.next_value()?);
                        }
                        Field::Username => {
                            if username.is_some() {
                                return Err(de::Error::duplicate_field("username"));
                            }
                            username = Some(map.next_value()?);
                        }
                        Field::Password => {
                            if password.is_some() {
                                return Err(de::Error::duplicate_field("password"));
                            }
                            let p: String = map.next_value()?;
                            password = Some(SecretString::new(p));
                        }
                        Field::SharedBy => {
                            if shared_by.is_some() {
                                return Err(de::Error::duplicate_field("shared_by"));
                            }
                            shared_by = Some(map.next_value()?);
                        }
                    }
                }
                let site =
                    site.ok_or_else(|| de::Error::missing_field("site"))?;
                let username =
                    username.ok_or_else(|| de::Error::missing_field("username"))?;
                let password =
                    password.ok_or_else(|| de::Error::missing_field("password"))?;
                let shared_by = shared_by.ok_or_else(|| de::Error::missing_field("shared_by"))?;
                Ok(PasswordEntryUnlocked {
                    site,
                    username,
                    password,
                    shared_by,
                })
            }
        }
        const FIELDS: &'static [&'static str] = &["site", "username", "password", "shared_by"];
        deserializer.deserialize_struct("PasswordEntryUnlocked", FIELDS, PrivateDataVisitor)
    }
}