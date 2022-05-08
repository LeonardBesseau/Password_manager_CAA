use read_input::prelude::*;
use secrecy::{ExposeSecret, SecretString};

pub(crate) fn ask_for(message: &str) -> Option<String>{
    let username = input::<String>().msg(format!("{} (Enter with no input to return to previous screen): ", message)).get();
    if username.is_empty() {
        return None;
    }
    Some(username)
}

pub(crate) fn ask_for_username() -> Option<String>{
    ask_for("Please enter your username")
}

pub(crate) fn ask_for_password() -> Option<SecretString>{
    let username = input::<SecretString>().msg("Please enter your password (Enter with no input to return to previous screen): ").get();
    if username.expose_secret().is_empty() {
        return None;
    }
    Some(username)
}