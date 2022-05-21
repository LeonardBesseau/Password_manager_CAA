use crate::crypto::{compute_hash, generate_master_key, generate_salt};
use crate::file::save_user_data;
use crate::file::{setup_user_data, user_data_exists};
use crate::input::{ask_for_password, ask_for_username};
use crate::data::user::UserDataUnlocked;
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

        if user_data_exists(path, username.as_str()) {
            println!("This username is already taken ! Please choose another.")
        } else {
            setup_user_data(path, username.as_str())?;
            break;
        }
    }

    let hash = compute_hash(&master_key);

    let user_data = UserDataUnlocked::new(&username, salt_buf, hash);
    save_user_data(path, &user_data, &master_key)
}


