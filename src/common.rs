use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io;
use crate::file_access::write_user_file;
use crate::password::SecretKey;
use crate::user_file::{Lockable, UserFileUnlocked};

#[derive(Debug)]
pub enum PasswordManagerError {
    Io(io::Error),
    Serialisation(bincode::Error),
}

impl Display for PasswordManagerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match *self {
            PasswordManagerError::Io(ref err) => write!(f, "IO error: {}", err),
            PasswordManagerError::Serialisation(ref err) => write!(f, "Serialisation error: {}", err)
        }
    }
}

impl From<io::Error> for PasswordManagerError {
    fn from(err: io::Error) -> PasswordManagerError {
        PasswordManagerError::Io(err)
    }
}

impl From<bincode::Error> for PasswordManagerError {
    fn from(err: bincode::Error) -> PasswordManagerError {
        PasswordManagerError::Serialisation(err)
    }
}

impl Error for PasswordManagerError {}

pub(crate) fn save_user_file(path: &str, user_file: UserFileUnlocked, master_key: &SecretKey) -> Result<(), Box<dyn Error>> {
    let user_file = user_file.lock(&master_key)?;
    let username = user_file.public.username.clone();
    write_user_file(path, username.as_str(), user_file)
}