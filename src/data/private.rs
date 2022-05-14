use crate::crypto::SecretKey;
use crate::data::password::PasswordEntryLocked;
use crate::error::PasswordManagerError;
use secrecy::ExposeSecret;
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use crate::data::traits::{Lockable, Unlockable};

pub struct PrivateData {
    pub(crate) password_key: SecretKey,
    pub(crate) sharing_private_key: ecies_ed25519::SecretKey,
    pub(crate) signing_private_key: ed25519_dalek::SecretKey,
    pub(crate) passwords: Vec<PasswordEntryLocked>,
}

impl Clone for PrivateData {
    fn clone(&self) -> Self {
        let mut bits_1: [u8; 32] = [0u8; 32];
        let mut bits_2: [u8; 32] = [0u8; 32];
        bits_1.copy_from_slice(self.sharing_private_key.as_bytes());
        bits_2.copy_from_slice(self.signing_private_key.as_bytes());
        PrivateData {
            password_key: SecretKey::new(self.password_key.expose_secret().clone()),
            sharing_private_key: ecies_ed25519::SecretKey::from_bytes(bits_1.as_slice()).unwrap(),
            signing_private_key: ed25519_dalek::SecretKey::from_bytes(bits_2.as_slice()).unwrap(),
            passwords: self.passwords.clone(),
        }
    }
}

impl Serialize for PrivateData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("PrivateData", 4)?;
        state.serialize_field("password_key", &self.password_key.expose_secret())?;
        state.serialize_field("sharing_private_key", &self.sharing_private_key)?;
        state.serialize_field("signature_private_key", &self.signing_private_key)?;
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
            SharingPrivateKey,
            SignaturePrivateKey,
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
                        formatter.write_str("`password_key` or `sharing_private_key` or `signature_private_key` or `passwords`")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "password_key" => Ok(Field::PasswordKey),
                            "sharing_private_key" => Ok(Field::SharingPrivateKey),
                            "signature_private_key" => Ok(Field::SignaturePrivateKey),
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
                let sharing_private_key = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let signature_private_key = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let passwords = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                Ok(PrivateData {
                    password_key,
                    sharing_private_key,
                    signing_private_key: signature_private_key,
                    passwords,
                })
            }

            fn visit_map<V>(self, mut map: V) -> Result<PrivateData, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut password_key = None;
                let mut sharing_private_key = None;
                let mut signature_private_key = None;
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
                        Field::SharingPrivateKey => {
                            if sharing_private_key.is_some() {
                                return Err(de::Error::duplicate_field("sharing_private_key"));
                            }
                            sharing_private_key = Some(map.next_value()?);
                        }
                        Field::SignaturePrivateKey => {
                            if signature_private_key.is_some() {
                                return Err(de::Error::duplicate_field("signature_private_key"));
                            }
                            signature_private_key = Some(map.next_value()?);
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
                let sharing_private_key = sharing_private_key
                    .ok_or_else(|| de::Error::missing_field("sharing_private_key"))?;
                let signature_private_key = signature_private_key
                    .ok_or_else(|| de::Error::missing_field("signature_private_key"))?;
                let passwords = passwords.ok_or_else(|| de::Error::missing_field("passwords"))?;
                Ok(PrivateData {
                    password_key,
                    sharing_private_key,
                    signing_private_key: signature_private_key,
                    passwords,
                })
            }
        }
        const FIELDS: &'static [&'static str] = &[
            "password_key",
            "sharing_private_key",
            "signature_private_key",
            "passwords",
        ];
        deserializer.deserialize_struct("PrivateData", FIELDS, PrivateDataVisitor)
    }
}

impl PrivateData {
    pub fn new(
        password_key: SecretKey,
        sharing_private_key: ecies_ed25519::SecretKey,
        signature_private_key: ed25519_dalek::SecretKey,
        passwords: Vec<PasswordEntryLocked>,
    ) -> Self {
        PrivateData {
            password_key,
            sharing_private_key,
            signing_private_key: signature_private_key,
            passwords,
        }
    }

    pub fn change_key(
        self,
        new_key: SecretKey,
        new_sharing_private_key: ecies_ed25519::SecretKey,
        new_signature_private_key: ed25519_dalek::SecretKey,
    ) -> Result<Self, PasswordManagerError> {
        let mut new_entries: Vec<PasswordEntryLocked> = Vec::with_capacity(self.passwords.len());
        for entry in self.passwords {
            new_entries.push(entry.unlock(&self.password_key)?.lock(&new_key)?);
        }
        Ok(PrivateData {
            password_key: new_key,
            sharing_private_key: new_sharing_private_key,
            signing_private_key: new_signature_private_key,
            passwords: new_entries,
        })
    }
}
