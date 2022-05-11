extern crate ed25519_dalek;

use ecies_ed25519::PublicKey;
use ed25519_dalek::{Keypair, Signer};
use ed25519_dalek::Signature;


fn get_keypair() -> Keypair {
    Keypair::from_bytes(&[174, 168, 136, 37, 44, 252, 13, 60, 36, 84, 71, 50, 109, 235, 233, 239, 69, 183, 230, 249, 153, 243, 64, 197, 179, 144, 178, 48, 85, 8, 162, 237, 64, 32, 149, 197, 12, 8, 197, 5, 225, 152, 180, 106, 200, 85, 90, 87, 47, 231, 126, 32, 117, 194, 34, 34, 8, 215, 169, 72, 1, 65, 178, 37]).unwrap()
}

fn get_message(username: &str, public_key: &PublicKey) -> Vec<u8> {
    let mut data = Vec::from(public_key.to_bytes());
    data.extend_from_slice(username.as_bytes());
    data
}

pub fn sign_public_key(username: &str, public_key: &PublicKey) -> Signature {
    let keypair = get_keypair();

    keypair.sign(get_message(username, public_key).as_slice())
}

pub fn verify_public_key(username: &str, public_key: &PublicKey, signature: &Signature) -> bool {
    let keypair = get_keypair();
    keypair.verify(get_message(username, public_key).as_slice(), signature).is_ok()
}

pub fn sign_message(username: &str) -> Signature{
    let keypair = get_keypair();
    keypair.sign(username.as_bytes())
}

pub fn verify_message(username: &str, signature: &Signature) -> bool{
    let keypair = get_keypair();
    keypair.verify(username.as_bytes(), signature).is_ok()
}