use secrecy::{ExposeSecret, SecretString, SecretVec, Zeroize};
use argon2::{password_hash::{
    PasswordHasher, SaltString,
}, Argon2, ParamsBuilder, Algorithm, Version};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha512;

pub type EncryptedData = Vec<u8>;
pub type SecretKey = SecretVec<u8>;
pub type Nonce = [u8; 24];
pub type Salt = [u8; 16];

pub fn get_master_key(master_password: SecretString, salt: SaltString) -> SecretVec<u8> {
    let mut param_builder = ParamsBuilder::new();
    param_builder.output_len(32).unwrap();
    param_builder.t_cost(10).unwrap();
    param_builder.p_cost(4).unwrap();
    param_builder.m_cost(16384).unwrap();
    let p = param_builder.params().unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::default(), p);
    // TODO remove unwrap and replace by error management
    let master_key = argon2.hash_password(master_password.expose_secret().as_bytes(), &salt).unwrap().hash.unwrap();
    SecretVec::new(Vec::from(master_key.as_bytes()))
}

pub fn compute_hash(username: &str, master_key: &SecretVec<u8>) -> String {
    let hk = Hkdf::<Sha512>::new(None, master_key.expose_secret());
    let mut output = [0u8; 42];
    let mut info = String::from(username);
    info.push_str("Master-key_verification");
    hk.expand(info.as_ref(), &mut output).unwrap();
    hex::encode(output)
}

pub fn generate_password_key() -> SecretKey {
    let mut password_keys = [0u8; 32];
    OsRng.fill_bytes(&mut password_keys);
    let output = SecretKey::new(Vec::from(password_keys));
    password_keys.zeroize();
    output
}

pub fn generate_nonce() -> Nonce {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    nonce
}