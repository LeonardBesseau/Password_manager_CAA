use crate::common::save_user_file;
use crate::crypto::SecretKey;
use crate::input::{ask_for, ask_for_password};
use crate::user_file::UserDataUnlocked;
use std::error::Error;

pub fn add_password(
    path: &str,
    user_file: &mut UserDataUnlocked,
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

    user_file.add_password(site.as_str(), username.as_str(), password, None)?;
    // TODO manage error
    save_user_file(&path, user_file, &master_key)?;
    println!("Password added successfully");
    Ok(())
}
