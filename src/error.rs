use argon2::password_hash;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io;

#[derive(Debug)]
pub enum PasswordManagerError {
    Io(io::Error),
    Serialisation(bincode::Error),
    Security,
    InvalidParameter,
}

impl Error for PasswordManagerError {}

impl Display for PasswordManagerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match *self {
            PasswordManagerError::Io(ref err) => write!(f, "Io error {}", err),
            PasswordManagerError::Serialisation(ref err) => {
                write!(f, "Serialisation error: {}", err)
            }
            PasswordManagerError::Security => write!(
                f,
                "Security error. The data was either corrupted or modified."
            ),
            PasswordManagerError::InvalidParameter => write!(f, "Invalid parameter encountered",),
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

impl From<ecies_ed25519::Error> for PasswordManagerError {
    fn from(_err: ecies_ed25519::Error) -> PasswordManagerError {
        PasswordManagerError::Security
    }
}

impl From<chacha20poly1305::aead::Error> for PasswordManagerError {
    fn from(_err: chacha20poly1305::aead::Error) -> PasswordManagerError {
        PasswordManagerError::Security
    }
}

impl From<password_hash::Error> for PasswordManagerError {
    fn from(_err: password_hash::Error) -> PasswordManagerError {
        PasswordManagerError::Security
    }
}
