use crate::data::user::UserDataUnlocked;
use crate::file::save_user_data;
use crate::input::ask_for_password;
use std::error::Error;

pub fn change_master_password(
    path: &str,
    user_data: UserDataUnlocked,
) -> Result<(), Box<dyn Error>> {
    let password = ask_for_password();
    if password.is_none() {
        return Ok(());
    }
    let (new_user_data, new_master_key) = user_data.change_key(password.unwrap())?;
    save_user_data(&path, &new_user_data, &new_master_key)?;
    Ok(())
}
