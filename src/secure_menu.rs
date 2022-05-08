use std::error::Error;
use clipboard::{ClipboardContext, ClipboardProvider};
use read_input::{InputBuild, InputConstraints};
use read_input::prelude::input;
use secrecy::ExposeSecret;
use crate::common::save_user_file;
use crate::input::{ask_for, ask_for_password};
use crate::password::SecretKey;
use crate::user_file::UserFileUnlocked;

fn add_password(user_file: &mut UserFileUnlocked) -> Result<(), Box<dyn Error>> {
    let site = match ask_for("Please enter a site") {
        None => { return Ok(()); }
        Some(s) => s
    };
    let username = match ask_for("Please enter a username") {
        None => { return Ok(()); }
        Some(s) => s
    };

    let password = match ask_for_password() {
        None => { return Ok(()); }
        Some(s) => s
    };

    user_file.add_password(site.as_str(), username.as_str(), password)?;
    println!("Password added successfully");
    Ok(())
}

fn show_password(user_file: &UserFileUnlocked) -> Result<(), Box<dyn Error>> {
    let entries = user_file.get_password_list();
    for (i, entry) in entries.iter().enumerate() {
        println!("{} - {}", i + 1, entry.site);
    }
    loop {
        let selected = input::<usize>().repeat_msg("Please select a site to display its password or 0 to return to the previous screen\n"
        ).min(0).get();
        if selected == 0 {
            break;
        } else if selected > entries.len() {
            println!("The demanded site does not exists. Please stay in the range 0-{}", entries.len());
        } else {
            let data = user_file.get_password(selected - 1)?;
            println!("Site: {}", data.site);
            println!("Username: {}", data.username);
            println!("Site: {}", &data.password.expose_secret());
        }
    }

    Ok(())
}

pub(crate) fn secure_menu(path: &str, username: &str, mut user_file: UserFileUnlocked, master_key: SecretKey) -> Result<(), Box<dyn Error>> {
    println!("Welcome {} !", username);
    loop {
        match input::<i32>().repeat_msg("Please select one of the following to continue\
        \n0 - Exit\
        \n1 - Add password\
        \n2 - Show password\
        \n3 - Share password\
        \n4 - Verify password strength\
        \n5 - Generate password\
        \n"
        ).min_max(0, 5).get() {
            0 => {
                // TODO manage error
                // TODO do we save the file even if there was no modification ?
                save_user_file(path, username, user_file, &master_key)?;
                println!("Exiting password manager !");
                break;
            }
            1 => add_password(&mut user_file)?,
            2 => show_password(&user_file)?,
            3 => todo!(),
            4 => todo!(),
            5 => todo!(),
            _ => panic!("Invalid input")
        }
    }
    Ok(())
}