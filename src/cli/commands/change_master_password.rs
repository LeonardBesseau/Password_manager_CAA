use crate::file::save_user_file;
use crate::input::ask_for_password;
use crate::user_file::UserDataUnlocked;
use std::error::Error;

pub fn change_master_password(
    path: &str,
    user_file: UserDataUnlocked,
) -> Result<(), Box<dyn Error>> {
    let password = ask_for_password();
    if password.is_none() {
        return Ok(());
    }
    let (new_user_file, new_master_key) = user_file.change_key(password.unwrap())?;
    save_user_file(&path, &new_user_file, &new_master_key)?;
    Ok(())
}
