use std::error::Error;
use std::fmt;
use secrecy::ExposeSecret;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeStruct;
use crate::password::{generate_password_key, SecretKey};
use crate::user_file::{Lockable, PasswordEntryLocked, PasswordEntryUnlocked, Unlockable};

pub struct SharedPassword {
    password: PasswordEntryLocked,
    password_key: SecretKey,
}

impl SharedPassword {
    pub fn new(password: PasswordEntryUnlocked) -> Result<Self, Box<dyn Error>> {
        let password_key = generate_password_key();
        let password = password.lock(&password_key)?;
        Ok(SharedPassword {password, password_key })
    }

    pub fn get_password(&self) -> Result<PasswordEntryUnlocked, Box<dyn Error>> {
        Ok(self.password.unlock(&self.password_key)?)
    }
}

impl Serialize for SharedPassword {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer {
        let mut state = serializer.serialize_struct("SharedPassword", 3)?;
        state.serialize_field("password", &self.password)?;
        state.serialize_field("password_key", &self.password_key.expose_secret())?;
        state.end()
    }
}


impl<'de> Deserialize<'de> for SharedPassword {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>, {
        enum Field {
            PasswordKey,
            Password,
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
                        formatter.write_str("`password_key` or `password`")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                        where
                            E: de::Error,
                    {
                        match value {
                            "password_key" => Ok(Field::PasswordKey),
                            "password" => Ok(Field::Password),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct PrivateDataVisitor;

        impl<'de> Visitor<'de> for PrivateDataVisitor {
            type Value = SharedPassword;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct SharedPassword")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<SharedPassword, V::Error>
                where
                    V: SeqAccess<'de>,
            {
                let password = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let password_key: Vec<u8> = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let password_key = SecretKey::new(password_key);
                Ok(SharedPassword {password, password_key })
            }

            fn visit_map<V>(self, mut map: V) -> Result<SharedPassword, V::Error>
                where
                    V: MapAccess<'de>,
            {
                let mut password_key = None;
                let mut password = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::PasswordKey => {
                            if password_key.is_some() {
                                return Err(de::Error::duplicate_field("password_key"));
                            }
                            let p: Vec<u8> = map.next_value()?;
                            password_key = Some(SecretKey::new(p));
                        }
                        Field::Password => {
                            if password.is_some() {
                                return Err(de::Error::duplicate_field("password"));
                            }
                            password = Some(map.next_value()?);
                        }
                    }
                }
                let password_key = password_key.ok_or_else(|| de::Error::missing_field("password_key"))?;
                let password = password.ok_or_else(|| de::Error::missing_field("password"))?;
                Ok(SharedPassword { password_key, password })
            }
        }
        const FIELDS: &'static [&'static str] = &["shared_by", "password_key", "password"];
        deserializer.deserialize_struct("SharedPassword", FIELDS, PrivateDataVisitor)
    }
}