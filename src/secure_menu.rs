use std::error::Error;
use rand::Rng;
use rand_core::OsRng;
use read_input::{InputBuild, InputConstraints};
use read_input::prelude::input;
use secrecy::{ExposeSecret, SecretString};
use zxcvbn::zxcvbn;
use crate::common::save_user_file;
use crate::file_access::{read_shared_file, read_user_file, user_file_exists, write_shared_file};
use crate::input::{ask_for, ask_for_password};
use crate::password::{SecretKey};
use crate::shared_file::SharedPassword;
use crate::user_file::{PasswordEntryLocked, Unlockable, UserFileUnlocked};

fn add_password(path: &str, user_file: &mut UserFileUnlocked, master_key: &SecretKey) -> Result<(), Box<dyn Error>> {
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
    // TODO manage error
    save_user_file(&path, user_file, &master_key)?;
    println!("Password added successfully");
    Ok(())
}

fn select_password_entry(user_file: &UserFileUnlocked) -> Option<usize> {
    let entries = user_file.get_password_list();
    for (i, entry) in entries.iter().enumerate() {
        println!("{} - {}", i + 1, entry.site);
    }
    loop {
        let selected = input::<usize>().repeat_msg("Please select a site to display its password or 0 to return to the previous screen\n"
        ).min(0).get();
        if selected == 0 {
            return None;
        } else if selected > entries.len() {
            println!("The demanded site does not exists. Please stay in the range 0-{}", entries.len());
        } else {
            return Some(selected - 1);
        }
    }
}

fn show_password(user_file: &UserFileUnlocked) -> Result<(), Box<dyn Error>> {
    let selected_entry = match select_password_entry(&user_file) {
        None => { return Ok(()); }
        Some(e) => { e }
    };
    let data = user_file.get_password(selected_entry)?;
    println!("Site: {}", data.site);
    println!("Username: {}", data.username);
    println!("Password: {}", &data.password.expose_secret());
    Ok(())
}

fn share_password(path: &str, user_file: &UserFileUnlocked) -> Result<(), Box<dyn Error>> {
    let selected_entry = match select_password_entry(&user_file) {
        None => { return Ok(()); }
        Some(e) => { e }
    };
    let data = user_file.get_password(selected_entry)?;
    let shared = SharedPassword::new(&user_file.public.username, data)?;
    let shared = bincode::serialize(&shared)?;
    let mut username;
    loop {
        username = match ask_for("Enter the username to share the password with") {
            None => { return Ok(()); }
            Some(e) => { e }
        };
        if !user_file_exists(path, &username) {
            println!("The selected user does not exist !");
        } else {
            break;
        }
    }
    let target_user_file = read_user_file(path, &username)?;
    let mut csprng = rand_7::thread_rng();
    let output = ecies_ed25519::encrypt(&target_user_file.public.public_key, shared.as_slice(), &mut csprng)?;
    write_shared_file(path, username.as_str(), output)?;
    println!("Password shared !!!");
    Ok(())
}


fn select_shared_password_entry(entries: &Vec<SharedPassword>) -> Option<usize> {
    for (i, entry) in entries.iter().enumerate() {
        println!("{} - {}, shared by {}", i + 1, entry.get_site(), entry.shared_by);
    }
    loop {
        let selected = input::<usize>().repeat_msg("Please select a site to display its password or 0 to return to the previous screen\n"
        ).min(0).get();
        if selected == 0 {
            return None;
        } else if selected > entries.len() {
            println!("The demanded site does not exists. Please stay in the range 0-{}", entries.len());
        } else {
            return Some(selected - 1);
        }
    }
}

fn show_shared_password(path: &str, user_file: &UserFileUnlocked) -> Result<(), Box<dyn Error>> {
    let entries = read_shared_file(path, &user_file.public.username, user_file.get_private_key())?;
    let selected_entry = match select_shared_password_entry(&entries) {
        None => { return Ok(()); }
        Some(e) => { e }
    };
    let entry = &entries.get(selected_entry).unwrap();
    let data = entry.get_password()?;
    println!("Password shared by {}", entry.shared_by);
    println!("Site: {}", data.site);
    println!("Username: {}", data.username);
    println!("Password: {}", &data.password.expose_secret());
    Ok(())

}

fn generate_password(charset: &str, length: usize) -> SecretString {
    let mut output = String::with_capacity(length);
    let distr = rand::distributions::Uniform::new(0, charset.len());
    let chars: Vec<char> = charset.chars().collect();
    for _ in 0..length {
        output.push(*chars.get(OsRng.sample(distr)).unwrap());
    }
    SecretString::new(output)
}

fn generate_password_menu() {
    println!("Password generator.");
    let number_charset = "0123456789";
    let letter_charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let special_charset = "!@#$%^&*";

    loop {
        let selected = input::<usize>().repeat_msg("Select one of the following \
        \n0 - Return to previous menu\
        \n1 - Only numbers\
        \n2 - Only letters (lower and upper case)\
        \n3 - Letters + numbers\
        \n4 - Letters + numbers + special chars (!@#$%^&*)\
        \n5 - Custom charset\n"
        ).min_max(0, 5).get();
        let select_charset = match selected {
            0 => { return; }
            1 => { String::from(number_charset) }
            2 => { String::from(letter_charset) }
            3 => {
                let mut output = String::from(number_charset);
                output.push_str(letter_charset);
                output
            }
            4 => {
                let mut output = String::from(number_charset);
                output.push_str(letter_charset);
                output.push_str(special_charset);
                output
            }
            5 => {
                let mut output;
                loop {
                    output = input::<String>().msg("Please enter your charset:").get();
                    if !output.is_empty() {
                        break;
                    }
                }
                output
            }
            _ => panic!("This should not happen")
        };
        let selected_size = input::<usize>().repeat_msg("Select the size of the password (0 to exit, maximum 64): "
        ).min_max(0, 64).get();
        println!("Your password is {}", generate_password(select_charset.as_str(), selected_size).expose_secret());
        break;
    }
}

fn verify_password_strength() {
    println!("Welcome to the password tester !");
    let password = match ask_for_password() {
        None => { return; }
        Some(s) => s
    };

    let entropy = zxcvbn(password.expose_secret(), &[]).unwrap();
    let score_description = match entropy.score() {
        0 | 1 => "catastrophic",
        2 => "bad",
        3 => "average",
        4 => "good",
        _ => panic!("Should not happen")
    };
    println!("Score {}/4. Your password is {}. It would take {} guess in average", entropy.score(), score_description, entropy.guesses());
    if (&entropy).score() < 2 && (&entropy).feedback().is_some() {
        let feedback = (entropy.feedback()).as_ref().unwrap();
        if feedback.warning().is_some() {
            println!("CAUTION!!! {}", feedback.warning().unwrap());
        }
        if !feedback.suggestions().is_empty() {
            println!("Here is a few suggestion to improve your password :");
            for i in feedback.suggestions() {
                println!("{}", i);
            }
        }
    }
}

pub(crate) fn secure_menu(path: &str, mut user_file: UserFileUnlocked, master_key: SecretKey) -> Result<(), Box<dyn Error>> {
    println!("Welcome {} !", user_file.public.username);
    loop {
        match input::<i32>().repeat_msg("Please select one of the following to continue\
        \n0 - Exit\
        \n1 - Add password\
        \n2 - Show password\
        \n3 - Share password\
        \n4 - Show password shared with me\
        \n5 - Verify password strength\
        \n6 - Generate password\
        \n7 - Change master password\
        \n"
        ).min_max(0, 7).get() {
            0 => {
                println!("Goodbye {}!", user_file.public.username);
                break;
            }
            1 => add_password(path, &mut user_file, &master_key)?,
            2 => show_password(&user_file)?,
            3 => share_password(path, &user_file)?,
            4 => show_shared_password(path, &user_file)?,
            5 => verify_password_strength(),
            6 => generate_password_menu(),
            7 => todo!(),
            _ => panic!("Invalid input")
        }
    }
    Ok(())
}