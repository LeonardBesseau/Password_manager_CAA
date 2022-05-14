use crate::cli::commands::utils::select_password_entry;
use crate::crypto::share_message;
use crate::data::user::UserDataUnlocked;
use crate::error::PasswordManagerError;
use crate::file::{read_user_file, user_file_exists, write_shared_file};
use crate::input::ask_for;
use crate::data::shared::SharedPassword;

pub fn share_password(
    path: &str,
    user_file: &UserDataUnlocked,
) -> Result<(), PasswordManagerError> {
    let selected_entry = match select_password_entry(&user_file) {
        None => {
            return Ok(());
        }
        Some(e) => e,
    };

    let mut username;
    loop {
        username = match ask_for("Enter the username to share the password with") {
            None => {
                return Ok(());
            }
            Some(e) => e,
        };
        if !user_file_exists(path, &username) {
            println!("The selected user does not exist !");
        } else {
            break;
        }
    }
    let target_user_file = read_user_file(path, &username)?;
    if !target_user_file.verify_identity() {
        eprint!(
            "Error public key for user {} was tampered with ! Aborting",
            target_user_file.identity.username
        );
        return Err(PasswordManagerError::Security);
    }
    let mut data = user_file.get_password(selected_entry)?;
    data.shared_by = Some(user_file.identity.username.clone());
    let shared = SharedPassword::new(data, &username,user_file.get_private_signing_key(), &user_file.identity.signing_public_key)?;
    let shared = bincode::serialize(&shared)?;

    let output = share_message(&target_user_file.identity.sharing_public_key, shared.as_slice())?;
    write_shared_file(path, username.as_str(), output)?;
    println!("Password shared !!!");
    Ok(())
}
