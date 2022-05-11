mod common;
mod input;
mod file_access;
mod user_file;
mod password;
mod shared_file;
mod cli;


use std::error::Error;
use read_input::prelude::*;
use cli::register;
use cli::login::{login, LoginResult};


fn secure_mode(path: &str) -> Result<(), Box<dyn Error>> {
    let (user_file, master_key) = match login(path)? {
        (LoginResult::EarlyAbort, _) => { return Ok(()); }
        (LoginResult::Invalid, _) => {
            println!("The username/password given are invalid !");
            return Ok(());
        }
        (LoginResult::Success, None) => {
            panic!("This combination should not happen !");
        }
        (LoginResult::Success, Some(t)) => t
    };
    cli::secure_menu::menu(path, user_file, master_key)
}

const PATH: &str = "files";

fn main() -> Result<(), Box<dyn Error>> {
    println!("Welcome to the very secure password manager !");

    loop {
        match input::<i32>().repeat_msg("Please select one of the following to continue\
        \n0 - Exit\
        \n1 - Login\
        \n2 - Create new account\
        \n"
        ).min_max(0, 2).get() {
            0 => {
                println!("Exiting password manager !");
                break;
            }
            1 => secure_mode(PATH)?,
            2 => register::register(PATH)?,
            _ => panic!("Invalid input")
        }
    }
    Ok(())
}
