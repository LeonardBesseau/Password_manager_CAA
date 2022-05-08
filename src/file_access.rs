use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::{fs, io};
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;
use uuid::Uuid;
use crate::user_file::UserFileLocked;

#[derive(Debug)]
pub enum FileAccessError {
    Io(io::Error)
}

impl Error for FileAccessError {}

impl Display for FileAccessError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match *self {
            FileAccessError::Io(ref err) => write!(f, "IO error: {}", err),
        }
    }
}

impl From<io::Error> for FileAccessError {
    fn from(err: io::Error) -> FileAccessError {
        FileAccessError::Io(err)
    }
}

fn get_uuid(username: &str) -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_OID, username.as_bytes())
}



fn get_user_filepath(path: &str, username: &str) -> String {
    let uuid = get_uuid(username);
    format!("{}/{}/data", path, uuid)
}

pub(crate) fn create_user_directory(path: &str, username: &str)-> Result<(), Box<dyn Error>>{
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

pub(crate) fn read_user_file(path: &str, username: &str) -> Result<UserFileLocked, Box<dyn Error>>{
    let reader = BufReader::new(File::open(get_user_filepath(path, username))?);
    let data: UserFileLocked = bincode::deserialize_from(reader)?;
    Ok(data)
}
