use crate::error::PasswordManagerError;
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Algorithm, Argon2, ParamsBuilder, Version,
};
use ecies_ed25519::{PublicKey as SharingKeyPublic, SecretKey as SharingKeyPrivate};

use ed25519_dalek::{PublicKey as SigningKeyPublic, SecretKey as SigningKeyPrivate, Keypair, Signature, Signer, Verifier};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString, SecretVec, Zeroize};
use sha2::Sha512;

pub type EncryptedData = Vec<u8>;
pub type SecretKey = SecretVec<u8>;
pub type Nonce = [u8; 24];
pub type Salt = [u8; 16];

pub fn generate_master_key(
    master_password: SecretString,
    salt: &SaltString,
) -> Result<SecretVec<u8>, PasswordManagerError> {
    let mut param_builder = ParamsBuilder::new();
    param_builder.output_len(32).unwrap();
    param_builder.t_cost(3).unwrap();
    param_builder.p_cost(4).unwrap();
    param_builder.m_cost(65536).unwrap();
    let params = param_builder.params().unwrap();

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::default(), params);
    let master_key = argon2
        .hash_password(master_password.expose_secret().as_bytes(), &salt)?
        .hash
        .unwrap();
    Ok(SecretVec::new(Vec::from(master_key.as_bytes())))
}

pub fn generate_salt() -> (SaltString, [u8; 16]) {
    let mut salt_buf: [u8; 16] = [0; 16];
    let salt = SaltString::generate(&mut OsRng);
    salt.b64_decode(&mut salt_buf).unwrap();
    (salt, salt_buf)
}

pub fn generate_sharing_key() -> (SharingKeyPrivate, SharingKeyPublic) {
    let mut csprng = rand_7::thread_rng();
    ecies_ed25519::generate_keypair(&mut csprng)
}

pub fn generate_signing_key() -> (SigningKeyPrivate, SigningKeyPublic) {
    let output = Keypair::generate(&mut rand_7::thread_rng());
    (output.secret, output.public)
}

pub fn compute_hash(master_key: &SecretVec<u8>) -> String {
    let hk = Hkdf::<Sha512>::new(None, master_key.expose_secret());
    let mut output = [0u8; 64];
    hk.expand(&[], &mut output).unwrap();
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

pub fn share_message(receiver_key: &SharingKeyPublic, message: &[u8]) -> Result<Vec<u8>, PasswordManagerError> {
    let mut csprng = rand_7::thread_rng();
    match ecies_ed25519::encrypt(
        receiver_key,
        message,
        &mut csprng,
    ) {
        Ok(data) => { Ok(data) }
        Err(_) => { Err(PasswordManagerError::Security) }
    }
}

pub fn sign_message(username: &str, private_key: &SigningKeyPrivate, public_key: &SigningKeyPublic) -> Result<Signature, PasswordManagerError> {
    let mut a = Vec::new();
    a.extend_from_slice(private_key.as_bytes());
    a.extend_from_slice(public_key.as_bytes());
    let keypair = Keypair::from_bytes(a.as_slice())?;
    Ok(keypair.sign(username.as_bytes()))
}

pub fn verify_message(username: &str, signature: &Signature, public_key: &SigningKeyPublic) -> Result<bool, PasswordManagerError> {
    Ok(public_key.verify(username.as_bytes(), signature).is_ok())
}
