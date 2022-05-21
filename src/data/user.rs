use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::crypto::{
    compute_hash, generate_keys, generate_master_key, generate_nonce, generate_salt, EncryptedData,
    Nonce, SecretKey,
};
use crate::data::identity::Identity;
use crate::data::password::{PasswordEntryLocked, PasswordEntryUnlocked};
use crate::data::private::PrivateData;
use crate::data::public::PublicData;
use crate::data::traits::{Lockable, Unlockable};
use crate::error::PasswordManagerError;
use chacha20poly1305::aead::{Aead, NewAead, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use constant_time_eq::constant_time_eq;

#[derive(Serialize, Deserialize, Debug)]
pub struct UserDataLocked {
    pub public: PublicData,
    pub identity: Identity,
    pub nonce: Nonce,
    private: EncryptedData,
}

#[derive(Clone)]
pub struct UserDataUnlocked {
    pub public: PublicData,
    pub identity: Identity,
    private: PrivateData,
}

impl Unlockable<UserDataUnlocked> for UserDataLocked {
    fn unlock(&self, key: &SecretKey) -> Result<UserDataUnlocked, PasswordManagerError> {
        let key = Key::from_slice(key.expose_secret().as_slice());
        let nonce = XNonce::from_slice(self.nonce.as_slice());
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
            identity: self.identity.clone(),
            private: passwords,
        })
    }
}

impl UserDataLocked {
    pub fn fake() -> Self {
        UserDataLocked {
            public: PublicData {
                salt: [0; 16],
                hash: "".to_string(),
            },
            identity: Identity::fake(),
            nonce: [0; 24],
            private: vec![],
        }
    }

    pub fn verify_master_key(&self, master_key: &SecretKey) -> bool {
        constant_time_eq(
            compute_hash(master_key).as_bytes(),
            self.public.hash.as_bytes(),
        )
    }

    pub fn verify_identity(&self, expected_username: &str) -> bool {
        self.identity.verify_identity(expected_username)
    }
}

impl Lockable<UserDataLocked> for UserDataUnlocked {
    fn lock(&self, key: &SecretKey) -> Result<UserDataLocked, PasswordManagerError> {
        let key = Key::from_slice(key.expose_secret().as_slice());
        let nonce = generate_nonce();
        let aead = XChaCha20Poly1305::new(&key);
        let public = self.public.clone();
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
            identity: self.identity.clone(),
            nonce,
            private: ciphertext,
        })
    }
}

impl UserDataUnlocked {
    pub fn new(username: &String, salt_buf: [u8; 16], hash: String) -> UserDataUnlocked {
        let (
            password_key,
            (sharing_private_key, sharing_public_key),
            (signing_private_key, signing_public_key),
        ) = generate_keys();

        let public_data = PublicData::new(salt_buf, hash);
        let identity = Identity::new(&username, sharing_public_key, signing_public_key);

        let private_data = PrivateData::new(
            password_key,
            sharing_private_key,
            signing_private_key,
            vec![],
        );

        // encrypt password key
        let user_data = UserDataUnlocked::create(public_data, private_data, identity);
        user_data
    }

    fn create(public_data: PublicData, private_data: PrivateData, identity: Identity) -> Self {
        UserDataUnlocked {
            public: public_data,
            identity,
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

    pub fn get_private_sharing_key(&self) -> &ecies_ed25519::SecretKey {
        &self.private.sharing_private_key
    }

    pub fn get_private_signing_key(&self) -> &ed25519_dalek::SecretKey {
        &self.private.signing_private_key
    }

    pub fn change_key(
        self,
        new_password: SecretString,
    ) -> Result<(Self, SecretKey), PasswordManagerError> {
        let (salt, salt_buf) = generate_salt();
        let master_key = generate_master_key(new_password, &salt)?;

        let (
            password_key,
            (sharing_private_key, sharing_public_key),
            (signing_private_key, signing_public_key),
        ) = generate_keys();

        let public_data = PublicData::new(salt_buf, compute_hash(&master_key));
        let identity = Identity::new(
            &self.identity.username,
            sharing_public_key,
            signing_public_key,
        );

        let private_data =
            self.private
                .change_key(password_key, sharing_private_key, signing_private_key)?;

        Ok((
            UserDataUnlocked::create(public_data, private_data, identity),
            master_key,
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::{compute_hash, SecretKey};
    use crate::data::traits::{Lockable, Unlockable};
    use crate::data::user::UserDataUnlocked;
    use crate::error::PasswordManagerError;

    fn generate_user_file(name: &str) -> (UserDataUnlocked, SecretKey) {
        let username = name.to_string();
        let salt_buf = [0u8; 16];
        // Password is test
        let master_key = SecretKey::from(vec![
            26, 113, 79, 169, 98, 182, 100, 22, 84, 227, 193, 60, 141, 123, 234, 191, 94, 86, 182,
            249, 138, 120, 222, 240, 160, 197, 40, 217, 123, 39, 155, 27,
        ]);
        let hash = compute_hash(&master_key);
        (UserDataUnlocked::new(&username, salt_buf, hash), master_key)
    }

    #[test]
    fn no_tampering_works() {
        let (user1, master_key_1) = generate_user_file("A");
        let user1 = user1.lock(&master_key_1).unwrap();
        let res = user1.unlock(&master_key_1);
        assert!(res.is_ok());
    }

    #[test]
    fn swapping_identity_is_detected() {
        let (mut user1, master_key_1) = generate_user_file("A");
        let (user2, _) = generate_user_file("B");

        user1.identity = user2.identity;
        let user1 = user1.lock(&master_key_1).unwrap();
        assert_eq!(user1.verify_identity("A"), false);
    }

    #[test]
    fn tampering_with_encrypted_data_is_detected() {
        let (user1, master_key_1) = generate_user_file("A");

        let mut user1 = user1.lock(&master_key_1).unwrap();
        user1.private[10] ^= 0xFF;
        user1.private[20] ^= 0xFF;
        user1.private[30] ^= 0xFF;
        let res = user1.unlock(&master_key_1);
        assert!(res.is_err());
        let res = res.err().unwrap();
        assert!(match res {
            PasswordManagerError::Security => true,
            _ => false,
        });
    }

    #[test]
    fn tampering_with_nonce_is_detected() {
        let (user1, master_key_1) = generate_user_file("A");

        let mut user1 = user1.lock(&master_key_1).unwrap();
        user1.nonce[1] ^= 0xFF;
        user1.nonce[10] ^= 0xFF;
        let res = user1.unlock(&master_key_1);
        assert!(res.is_err());
        let res = res.err().unwrap();
        assert!(match res {
            PasswordManagerError::Security => true,
            _ => false,
        });
    }

    #[test]
    fn tampering_with_hash_is_detected() {
        let (user1, master_key_1) = generate_user_file("A");

        let mut user1 = user1.lock(&master_key_1).unwrap();
        user1.public.hash = "modified".to_string();
        let res = user1.unlock(&master_key_1);
        assert!(res.is_err());
        let res = res.err().unwrap();
        assert!(match res {
            PasswordManagerError::Security => true,
            _ => false,
        });
    }

    #[test]
    fn tampering_with_salt_is_detected() {
        let (user1, master_key_1) = generate_user_file("A");

        let mut user1 = user1.lock(&master_key_1).unwrap();
        user1.public.salt[10] ^= 0xFF;
        let res = user1.unlock(&master_key_1);
        assert!(res.is_err());
        let res = res.err().unwrap();
        assert!(match res {
            PasswordManagerError::Security => true,
            _ => false,
        });
    }
}
