use crate::crypto::{compute_hash, generate_keys, generate_master_key, generate_salt};
use crate::file::save_user_data;
use crate::file::{setup_user_data, user_data_exists};
use crate::input::{ask_for_password, ask_for_username};

use crate::data::identity::Identity;
use crate::data::private::PrivateData;
use crate::data::public::PublicData;
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

    let (password_key, (sharing_private_key, sharing_public_key), (signing_private_key, signing_public_key)) = generate_keys();

    let public_data = PublicData::new(salt_buf, compute_hash(&master_key));
    let identity = Identity::new(&username, sharing_public_key, signing_public_key);

    let private_data = PrivateData::new(
        password_key,
        sharing_private_key,
        signing_private_key,
        vec![],
    );

    // encrypt password key
    let user_data = UserDataUnlocked::new(public_data, private_data, identity);
    save_user_data(path, &user_data, &master_key)
}
