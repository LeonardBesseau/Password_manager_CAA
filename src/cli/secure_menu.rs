use crate::cli::commands::add_password::add_password;
use crate::cli::commands::change_master_password::change_master_password;
use crate::cli::commands::generate_password;
use crate::cli::commands::share_password::share_password;
use crate::cli::commands::show_password::show_password;
use crate::cli::commands::verify_password::verify_password_strength;
use crate::crypto::SecretKey;

use crate::data::user::UserDataUnlocked;
use read_input::prelude::input;
use read_input::{InputBuild, InputConstraints};
use std::error::Error;

pub(crate) fn menu(
    path: &str,
    mut user_data: UserDataUnlocked,
    master_key: SecretKey,
) -> Result<(), Box<dyn Error>> {
    println!("Welcome {} !", user_data.identity.username);
    loop {
        match input::<i32>()
            .repeat_msg(
                "Please select one of the following to continue\
        \n0 - Exit\
        \n1 - Add password\
        \n2 - Show password\
        \n3 - Share password\
        \n4 - Verify password strength\
        \n5 - Generate password\
        \n6 - Change master password\
        \n",
            )
            .min_max(0, 6)
            .get()
        {
            0 => {
                println!("Goodbye {}!", user_data.identity.username);
                return Ok(());
            }
            1 => add_password(path, &mut user_data, &master_key)?,
            2 => show_password(&user_data)?,
            3 => share_password(path, &user_data)?,
            4 => verify_password_strength(),
            5 => generate_password::menu(),
            6 => {
                change_master_password(path, user_data)?;
                println!("Please relogin to continue");
                return Ok(());
            }
            _ => panic!("Invalid input"),
        }
    }
}
