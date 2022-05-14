use crate::cli::commands::utils::select_password_entry;
use crate::data::user::UserDataUnlocked;
use secrecy::ExposeSecret;
use std::error::Error;

pub fn show_password(user_data: &UserDataUnlocked) -> Result<(), Box<dyn Error>> {
    let selected_entry = match select_password_entry(&user_data) {
        None => {
            return Ok(());
        }
        Some(e) => e,
    };
    let data = user_data.get_password(selected_entry)?;
    println!("Site: {}", data.site);
    println!("Username: {}", data.username);
    println!("Password: {}", &data.password.expose_secret());
    Ok(())
}
