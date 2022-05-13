use crate::crypto::SecretKey;
use crate::data::user::{Lockable, UserDataLocked, UserDataUnlocked};
use crate::error::PasswordManagerError;
use crate::data::shared::SharedPassword;
use std::error::Error;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;
use std::{fs, io};
use uuid::Uuid;

pub const DATA_FILE_NAME: &str = "data";
pub const SHARED_FILE_NAME: &str = "shared";

fn get_uuid(username: &str) -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_OID, username.as_bytes())
}

fn get_user_filepath(path: &str, username: &str) -> String {
    let uuid = get_uuid(username);
    format!("{}/{}/{}", path, uuid, DATA_FILE_NAME)
}

fn get_user_shared_filepath(path: &str, username: &str) -> String {
    let uuid = get_uuid(username);
    format!("{}/{}/{}", path, uuid, SHARED_FILE_NAME)
}

pub(crate) fn create_user_directory(path: &str, username: &str) -> Result<(), Box<dyn Error>> {
    let uuid = get_uuid(username);
    Ok(fs::create_dir_all(format!("{}/{}/", path, uuid).as_str())?)
}

pub(crate) fn user_file_exists(path: &str, username: &str) -> bool {
    let uuid = get_uuid(username);
    Path::new(format!("{}/{}/{}", path, uuid, DATA_FILE_NAME).as_str()).exists()
}

pub(crate) fn write_user_file(
    path: &str,
    username: &str,
    data: UserDataLocked,
) -> Result<(), Box<dyn Error>> {
    let mut writer = BufWriter::new(File::create(get_user_filepath(path, username))?);
    bincode::serialize_into(&mut writer, &data)?;
    writer.flush()?;
    Ok(())
}

pub(crate) fn read_user_file(
    path: &str,
    username: &str,
) -> Result<UserDataLocked, PasswordManagerError> {
    let reader = BufReader::new(File::open(get_user_filepath(path, username))?);
    let data: UserDataLocked = bincode::deserialize_from(reader)?;
    Ok(data)
}

pub(crate) fn write_shared_file(
    path: &str,
    username: &str,
    data: Vec<u8>,
) -> Result<(), PasswordManagerError> {
    let mut passwords: Vec<Vec<u8>> = vec![];
    passwords.push(data);
    let file_result = File::open(get_user_shared_filepath(path, username));
    if file_result.is_err() {
        let error = file_result.err().unwrap();
        if error.kind() != io::ErrorKind::NotFound {
            return Err(PasswordManagerError::from(error));
        }
    } else {
        let file = file_result?;
        if (&file).metadata()?.len() != 0 {
            let reader = BufReader::new(file);
            let mut password: Vec<Vec<u8>> = bincode::deserialize_from(reader)?;
            passwords.append(&mut password);
        }
    }

    let mut writer = BufWriter::new(File::create(get_user_shared_filepath(path, username))?);
    bincode::serialize_into(&mut writer, &passwords)?;
    writer.flush()?;
    Ok(())
}

pub(crate) fn read_shared_file(
    path: &str,
    username: &str,
    key: &ecies_ed25519::SecretKey,
) -> Result<Vec<SharedPassword>, PasswordManagerError> {
    let file_result = File::open(get_user_shared_filepath(path, username));
    if file_result.is_err() {
        let error = file_result.err().unwrap();
        return if error.kind() == io::ErrorKind::NotFound {
            Ok(vec![])
        } else {
            Err(PasswordManagerError::from(error))
        };
    }
    let file = file_result?;
    let reader = BufReader::new(file);
    let passwords: Vec<Vec<u8>> = bincode::deserialize_from(reader)?;
    let mut output = Vec::with_capacity(passwords.len());
    for i in passwords {
        let a = ecies_ed25519::decrypt(key, &i)?;
        let b: SharedPassword = bincode::deserialize(a.as_slice())?;
        output.push(b);
    }
    Ok(output)
}

pub(crate) fn remove_shared_file(path: &str, username: &str) -> Result<(), PasswordManagerError> {
    let result = fs::remove_file(get_user_shared_filepath(path, username));
    if result.is_err() {
        let error = result.err().unwrap();
        if error.kind() != io::ErrorKind::NotFound {
            return Err(PasswordManagerError::from(error));
        };
    }
    Ok(())
}

pub(crate) fn save_user_file(
    path: &str,
    user_file: &UserDataUnlocked,
    master_key: &SecretKey,
) -> Result<(), Box<dyn Error>> {
    let user_file = user_file.lock(&master_key)?;
    let username = user_file.identity.username.clone();
    write_user_file(path, username.as_str(), user_file)
}
