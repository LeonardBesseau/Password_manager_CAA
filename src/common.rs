use crate::crypto::SecretKey;
use crate::file::write_user_file;
use crate::user_file::{Lockable, UserDataUnlocked};
use std::error::Error;

pub(crate) fn save_user_file(
    path: &str,
    user_file: &UserDataUnlocked,
    master_key: &SecretKey,
) -> Result<(), Box<dyn Error>> {
    let user_file = user_file.lock(&master_key)?;
    let username = user_file.public.username.clone();
    write_user_file(path, username.as_str(), user_file)
}
