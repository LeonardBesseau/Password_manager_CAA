use std::error::Error;
use argon2::password_hash::SaltString;
use crate::file_access::{read_shared_file, read_user_file, remove_shared_file, user_file_exists};
use crate::input::{ask_for_password, ask_for_username};
use crate::login::LoginResult::{EarlyAbort, Invalid, Success};
use crate::password::{get_master_key, SecretKey};
use crate::user_file::{Unlockable, UserFileUnlocked};

pub enum LoginResult {
    EarlyAbort,
    Invalid,
    Success,
}

pub fn login(path: &str) -> Result<(LoginResult, Option<(UserFileUnlocked, SecretKey)>), Box<dyn Error>> {
    let mut username;
    loop {
        let user_input = ask_for_username();
        if user_input.is_none() {
            return Ok((EarlyAbort, None));
        }

        username = user_input.unwrap();
        // TODO find a way to manage invalid user.
        if !user_file_exists(path, username.as_str()) {
            println!("This username is not registered. Please register first")
        } else {
            break;
        }
    }
    let user_file = read_user_file(path, username.as_str())?;

    let password = ask_for_password();
    if password.is_none() {
        return Ok((EarlyAbort, None));
    }

    // TODO manage salt error (Replace unwrapt by ? with custom error conversion)
    let salt = SaltString::b64_encode(&user_file.public.salt).unwrap();

    let master_key = get_master_key(password.unwrap(), salt);

    if !user_file.verify(&master_key) {
        return Ok((Invalid, None));
    }

    // Verify auth and decrypt
    let mut user_file = user_file.unlock(&master_key)?;
    login_setup(path, &mut user_file)?;
    Ok((Success, Some((user_file, master_key))))
}

fn login_setup(path: &str, user_file: &mut UserFileUnlocked) -> Result<(), Box<dyn Error>> {
    let entries = read_shared_file(path, &user_file.public.username, user_file.get_private_key())?;
    for entry in entries {
        // TODO manage invalid param
        let password = entry.get_password()?;
        user_file.add_password(password.site.as_str(), password.username.as_str(), password.password, password.shared_by)?;
    }
    remove_shared_file(path, &user_file.public.username)?;
    Ok(())
}