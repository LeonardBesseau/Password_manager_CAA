use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::{fs, io};
use std::io::{BufReader, BufWriter, ErrorKind, Write};
use std::path::Path;
use uuid::Uuid;
use crate::shared_file::SharedPassword;
use crate::user_file::UserFileLocked;

#[derive(Debug)]
pub enum FileAccessError {
    Io(io::Error),
    Serialisation(bincode::Error),
    Encryption(ecies_ed25519::Error),
}

impl Error for FileAccessError {}

impl Display for FileAccessError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match *self {
            FileAccessError::Io(ref err) => write!(f, "IO error: {}", err),
            FileAccessError::Serialisation(ref err) => write!(f, "Serialisation error: {}", err),
            FileAccessError::Encryption(ref _err) => write!(f, "Encryption error:"),
        }
    }
}

impl From<io::Error> for FileAccessError {
    fn from(err: io::Error) -> FileAccessError {
        FileAccessError::Io(err)
    }
}

impl From<bincode::Error> for FileAccessError {
    fn from(err: bincode::Error) -> FileAccessError {
        FileAccessError::Serialisation(err)
    }
}

impl From<ecies_ed25519::Error> for FileAccessError {
    fn from(err: ecies_ed25519::Error) -> FileAccessError {
        FileAccessError::Encryption(err)
    }
}

fn get_uuid(username: &str) -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_OID, username.as_bytes())
}


fn get_user_filepath(path: &str, username: &str) -> String {
    let uuid = get_uuid(username);
    format!("{}/{}/data", path, uuid)
}

fn get_user_shared_filepath(path: &str, username: &str) -> String {
    let uuid = get_uuid(username);
    format!("{}/{}/shared", path, uuid)
}

pub(crate) fn create_user_directory(path: &str, username: &str) -> Result<(), Box<dyn Error>> {
    let uuid = get_uuid(username);
    Ok(fs::create_dir_all(format!("{}/{}/", path, uuid).as_str())?)
}

pub(crate) fn user_file_exists(path: &str, username: &str) -> bool {
    let uuid = get_uuid(username);
    Path::new(format!("{}/{}/data", path, uuid).as_str()).exists()
}

pub(crate) fn write_user_file(path: &str, username: &str, data: UserFileLocked) -> Result<(), Box<dyn Error>> {
    let mut writer = BufWriter::new(File::create(get_user_filepath(path, username))?);
    bincode::serialize_into(&mut writer, &data)?;
    writer.flush()?;
    Ok(())
}

pub(crate) fn read_user_file(path: &str, username: &str) -> Result<UserFileLocked, Box<dyn Error>> {
    let reader = BufReader::new(File::open(get_user_filepath(path, username))?);
    let data: UserFileLocked = bincode::deserialize_from(reader)?;
    Ok(data)
}

pub(crate) fn write_shared_file(path: &str, username: &str, data: Vec<u8>) -> Result<(), FileAccessError> {
    let mut passwords: Vec<Vec<u8>> = vec![];
    passwords.push(data);
    let file_result = File::open(get_user_shared_filepath(path, username));
    if file_result.is_err() {
        let error = file_result.err().unwrap();
        if error.kind() != io::ErrorKind::NotFound {
            return Err(FileAccessError::from(error));
        }
    } else {
        let file = file_result?;
        if (&file).metadata()?.len() != 0 {
            // TODO check if reserving vector might be useful
            let reader = BufReader::new(file);
            let mut p: Vec<Vec<u8>> = bincode::deserialize_from(reader)?;
            passwords.append(&mut p);
        }
    }

    let mut writer = BufWriter::new(File::create(get_user_shared_filepath(path, username))?);
    bincode::serialize_into(&mut writer, &passwords)?;
    writer.flush()?;
    Ok(())
}

pub(crate) fn read_shared_file(path: &str, username: &str, key: &ecies_ed25519::SecretKey) -> Result<Vec<SharedPassword>, FileAccessError> {
    // TODO manage empty file exception
    let file_result = File::open(get_user_shared_filepath(path, username));
    if file_result.is_err() {
        let error = file_result.err().unwrap();
        return if error.kind() == io::ErrorKind::NotFound {
            Ok(vec![])
        } else {
            Err(FileAccessError::from(error))
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