use crate::crypto::SecretKey;
use crate::error::PasswordManagerError;

pub trait Lockable<T: Unlockable<Self>>: Sized {
    fn lock(&self, key: &SecretKey) -> Result<T, PasswordManagerError>;
}

pub trait Unlockable<T: Lockable<Self>>: Sized {
    fn unlock(&self, key: &SecretKey) -> Result<T, PasswordManagerError>;
}
