use crate::cli::commands::utils::select_password_entry;
use crate::crypto::share_message;
use crate::data::shared::SharedPassword;
use crate::data::user::UserDataUnlocked;
use crate::error::PasswordManagerError;
use crate::file::{read_user_data, user_data_exists, write_shared_data};
use crate::input::ask_for;

pub fn share_password(
    path: &str,
    user_data: &UserDataUnlocked,
) -> Result<(), PasswordManagerError> {
    let selected_entry = match select_password_entry(&user_data) {
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
        if !user_data_exists(path, &username) {
            println!("The selected user does not exist !");
        } else {
            break;
        }
    }
    let receiver_user_data = read_user_data(path, &username)?;
    if !receiver_user_data.verify_identity() {
        eprint!(
            "Error public key for user {} was tampered with ! Aborting",
            receiver_user_data.identity.username
        );
        return Err(PasswordManagerError::Security);
    }
    let mut data = user_data.get_password(selected_entry)?;
    data.shared_by = Some(user_data.identity.username.clone());
    let shared = SharedPassword::new(
        data,
        &username,
        user_data.get_private_signing_key(),
        &user_data.identity.signing_public_key,
    )?;
    let shared = bincode::serialize(&shared)?;

    let output = share_message(
        &receiver_user_data.identity.sharing_public_key,
        shared.as_slice(),
    )?;
    write_shared_data(path, username.as_str(), output)?;
    println!("Password shared !!!");
    Ok(())
}
