use crate::crypto::{compute_hash, generate_sharing_key, generate_master_key, generate_password_key, generate_salt, generate_signing_key};
use crate::file::save_user_file;
use crate::file::{create_user_directory, user_file_exists};
use crate::input::{ask_for_password, ask_for_username};

use crate::data::user::UserDataUnlocked;
use std::error::Error;
use crate::data::identity::Identity;
use crate::data::private::PrivateData;
use crate::data::public::PublicData;

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

    let (sharing_private_key, sharing_public_key) = generate_sharing_key();
    let (signing_private_key, signing_public_key) = generate_signing_key();
    let public_data = PublicData::new(
        salt_buf,
        compute_hash(&master_key),
    );
    let identity = Identity::new(&username,
                                 sharing_public_key,
                                 signing_public_key);

    let password_key = generate_password_key();
    let private_data = PrivateData::new(password_key, sharing_private_key, signing_private_key, vec![]);

    // encrypt password key
    let user_file = UserDataUnlocked::new(public_data, private_data, identity);
    save_user_file(path, &user_file, &master_key)
}
