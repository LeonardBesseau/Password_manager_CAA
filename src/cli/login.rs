use crate::cli::login::LoginResult::{EarlyAbort, Invalid, Success};
use crate::crypto::{generate_master_key, SecretKey};
use crate::data::traits::Unlockable;
use crate::data::user::{UserDataLocked, UserDataUnlocked};
use crate::error::PasswordManagerError;
use crate::file::{read_shared_data, read_user_data, remove_shared_data, user_data_exists};
use crate::input::{ask_for_password, ask_for_username};
use argon2::password_hash::SaltString;

pub enum LoginResult {
    EarlyAbort,
    Invalid,
    Success,
}

fn convert_shared_password(
    path: &str,
    user_data: &mut UserDataUnlocked,
) -> Result<(), PasswordManagerError> {
    let entries = read_shared_data(
        path,
        &user_data.identity.username,
        user_data.get_private_sharing_key(),
    )?;
    for entry in entries {
        let password = &entry.password;
        let sender_username = &password.shared_by.clone().unwrap();
        let sender_info = read_user_data(path, &sender_username.as_str())?;
        if !sender_info.verify_identity(&sender_username) {
            eprint!(
                "Identity for {} was found invalid. Skipping",
                sender_username
            );
            continue;
        }
        if !entry.verify(
            &user_data.identity.username,
            &sender_info.identity.signing_public_key,
        )? {
            eprint!(
                "Invalid signature for password supposedly shared by {}. Skipping",
                sender_username
            );
            continue;
        }
        user_data.add_password(
            entry.password.site.as_str(),
            entry.password.username.as_str(),
            entry.password.password,
            entry.password.shared_by,
        )?;
    }
    remove_shared_data(path, &user_data.identity.username)?;
    Ok(())
}

fn get_user_data(path: &str, username: &str) -> Result<UserDataLocked, PasswordManagerError> {
    if !user_data_exists(path, username) {
        Ok(UserDataLocked::fake())
    } else {
        read_user_data(path, username)
    }
}

pub fn login(
    path: &str,
) -> Result<(LoginResult, Option<(UserDataUnlocked, SecretKey)>), PasswordManagerError> {
    let username;
    let user_input = ask_for_username();
    if user_input.is_none() {
        return Ok((EarlyAbort, None));
    }
    username = user_input.unwrap();

    // This is vulnerable to a timing attack (disk access and comparison is constant only if both operand are the same size)
    let user_file = get_user_data(path, username.as_str())?;

    let password = ask_for_password();
    if password.is_none() {
        return Ok((EarlyAbort, None));
    }

    let salt = SaltString::b64_encode(&user_file.public.salt)?;
    let master_key = generate_master_key(password.unwrap(), &salt)?;
    if !user_file.verify_master_key(&master_key) {
        return Ok((Invalid, None));
    }
    if !user_file.verify_identity(&username) {
        eprint!("Tampering Detected ! Aborting.");
        return Err(PasswordManagerError::Security);
    }

    // Verify auth and decrypt
    let mut user_file = user_file.unlock(&master_key)?;
    convert_shared_password(path, &mut user_file)?;
    Ok((Success, Some((user_file, master_key))))
}
