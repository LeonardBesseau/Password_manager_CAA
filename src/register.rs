use std::error::Error;
use argon2::password_hash::SaltString;
use rand_core::{OsRng};
use crate::common::save_user_file;
use crate::input::{ask_for_password, ask_for_username};
use crate::password::{compute_hash, generate_nonce, generate_password_key, get_master_key};
use crate::file_access::{create_user_directory, user_file_exists};
use crate::user_file::{PrivateData, PublicData, UserFileUnlocked};

pub fn register(path: &str) -> Result<(), Box<dyn Error>> {
    let mut username;
    let mut master_key;
    let mut salt_buf: [u8; 16] = [0; 16];
    loop {
        let user_input = ask_for_username();
        if user_input.is_none() {
            return Ok(());
        }
        username = user_input.unwrap();


        // We generate the salt here to reduce the time the password is in memory
        let salt = SaltString::generate(&mut OsRng);
        salt.b64_decode(&mut salt_buf).unwrap();

        let password = ask_for_password();
        if password.is_none() {
            return Ok(());
        }

        master_key = get_master_key(password.unwrap(), salt);
        if user_file_exists(path, username.as_str()) {
            println!("This username is already taken ! Please choose another.")
        } else {
            create_user_directory(path, username.as_str())?;
            break;
        }
    }

    let mut csprng = rand_7::thread_rng();
    let (private_key, public_key) = ecies_ed25519::generate_keypair(&mut csprng);
    let public_data = PublicData::new(salt_buf, compute_hash(username.as_str(), &master_key), &username, public_key);

    let password_key = generate_password_key();
    let private_data = PrivateData::new(password_key, private_key, vec![]);

    // encrypt password key
    let user_file = UserFileUnlocked::new(public_data, private_data);
    save_user_file(path, &user_file, &master_key)
}

