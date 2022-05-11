use crate::common::save_user_file;
use crate::crypto::{
    compute_hash, generate_asymmetric_key, generate_master_key, generate_password_key,
    generate_salt,
};
use crate::file::{create_user_directory, user_file_exists};
use crate::input::{ask_for_password, ask_for_username};
use crate::user_file::{PrivateData, PublicData, UserDataUnlocked};
use std::error::Error;

pub fn register(path: &str) -> Result<(), Box<dyn Error>> {
    let mut username;
    let mut master_key;
    let (salt, salt_buf) = generate_salt();

    loop {
        let user_input = ask_for_username();
        if user_input.is_none() {
            return Ok(());
        }
        username = user_input.unwrap();

        let password = ask_for_password();
        if password.is_none() {
            return Ok(());
        }

        master_key = generate_master_key(password.unwrap(), &salt)?;

        if user_file_exists(path, username.as_str()) {
            println!("This username is already taken ! Please choose another.")
        } else {
            create_user_directory(path, username.as_str())?;
            break;
        }
    }

    let (private_key, public_key) = generate_asymmetric_key();
    let public_data = PublicData::new(
        salt_buf,
        compute_hash(username.as_str(), &master_key),
        &username,
        public_key,
    );

    let password_key = generate_password_key();
    let private_data = PrivateData::new(password_key, private_key, vec![]);

    // encrypt password key
    let user_file = UserDataUnlocked::new(public_data, private_data);
    save_user_file(path, &user_file, &master_key)
}
