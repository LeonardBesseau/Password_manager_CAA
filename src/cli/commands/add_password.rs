use crate::crypto::SecretKey;
use crate::data::user::UserDataUnlocked;
use crate::file::save_user_data;
use crate::input::{ask_for, ask_for_password};
use std::error::Error;

pub fn add_password(
    path: &str,
    user_data: &mut UserDataUnlocked,
    master_key: &SecretKey,
) -> Result<(), Box<dyn Error>> {
    let site = match ask_for("Please enter a site") {
        None => {
            return Ok(());
        }
        Some(s) => s,
    };
    let username = match ask_for("Please enter a username") {
        None => {
            return Ok(());
        }
        Some(s) => s,
    };

    let password = match ask_for_password() {
        None => {
            return Ok(());
        }
        Some(s) => s,
    };

    user_data.add_password(site.as_str(), username.as_str(), password, None)?;
    save_user_data(&path, user_data, &master_key)?;
    println!("Password added successfully");
    Ok(())
}
