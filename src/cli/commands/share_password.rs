use crate::cli::commands::utils::select_password_entry;
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
    let mut data = user_file.get_password(selected_entry)?;
    data.shared_by = Some(user_file.public.username.clone());
    let shared = SharedPassword::new(data, &user_file.public.username)?;
    let shared = bincode::serialize(&shared)?;
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
    if !target_user_file.verify_public_key() {
        eprint!(
            "Error public key for user {} was tampered with ! Aborting",
            target_user_file.public.username
        );
        return Err(PasswordManagerError::Security);
    }
    let mut csprng = rand_7::thread_rng();
    let output = ecies_ed25519::encrypt(
        &target_user_file.public.public_key,
        shared.as_slice(),
        &mut csprng,
    )?;
    write_shared_file(path, username.as_str(), output)?;
    println!("Password shared !!!");
    Ok(())
}
