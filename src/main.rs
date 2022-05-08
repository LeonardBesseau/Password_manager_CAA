mod register;
mod common;

extern crate core;

use std::fs::File;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io;
use std::io::{Write, BufReader, BufWriter};
use std::sync::{Mutex, MutexGuard};
use once_cell::sync::{OnceCell};

use serde::{Serialize, Deserialize};
use read_input::prelude::*;
use uuid::Uuid;

use rand::prelude::*;

use argon2::{password_hash::{
    rand_core::OsRng,
    PasswordHasher, SaltString,
}, Argon2, ParamsBuilder, Algorithm, Version};
use chacha20poly1305::{XChaCha20Poly1305, Key, XNonce};
use chacha20poly1305::aead::{Aead, NewAead, Payload};

use sha2::{Sha512, Digest};

use secrecy::{ExposeSecret, SecretString, SecretVec, Zeroize};
use constant_time_eq::constant_time_eq;


#[derive(Debug)]
pub enum PasswordManagerError {
    InvalidUser,
    Io(io::Error),
    Serialisation(bincode::Error),
}

impl Display for PasswordManagerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match *self {
            PasswordManagerError::InvalidUser => write!(f, "The user selected does not exists !"),
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

#[derive(Serialize, Deserialize, Debug)]
struct UserData {
    username: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct PasswordEntry {
    site: String,
    username: String,
    password: Vec<u8>,
}

impl Zeroize for PasswordEntry {
    fn zeroize(&mut self) {
        self.site.zeroize();
        self.username.zeroize();
        self.password.zeroize();
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct UserFile {
    public: UserFilePublicPart,
    private: UserFilePrivatePart,
}

#[derive(Serialize, Deserialize, Debug)]
struct UserFileCrypted {
    public: UserFilePublicPart,
    private: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
struct UserFilePublicPart {
    salt: String,
    hash: String,
    iv: [u8; 24],
}

#[derive(Serialize, Deserialize, Debug)]
struct UserFilePrivatePart {
    password_key: [u8; 32],
    password_count: u32,
    passwords: Vec<PasswordEntry>,
}

impl Zeroize for UserFile {
    fn zeroize(&mut self) {
        self.private.zeroize();
    }
}

impl Zeroize for UserFilePrivatePart {
    fn zeroize(&mut self) {
        self.password_key.zeroize();
        self.password_count.zeroize();
        self.passwords.zeroize();
    }
}

#[derive(Debug)]
struct Context {
    users_folders: String,
    current_user_path: Option<String>,
}

static CONTEXT: OnceCell<Mutex<Context>> = OnceCell::new();

impl Context {
    pub fn init() {
        CONTEXT.set(Mutex::new(Context { users_folders: "files".to_string(), current_user_path: None })).unwrap();
    }

    pub fn get() -> MutexGuard<'static, Context> {
        CONTEXT.get().unwrap().lock().unwrap()
    }

    pub fn set_user_path(path: Option<String>) {
        let mut context = CONTEXT.get().unwrap().lock().unwrap();
        context.current_user_path = path;
    }
}

fn read_user_file() -> Result<UserFileCrypted, Box<dyn Error>> {
    let file = File::open(format!("{}/data", Context::get().current_user_path.as_ref().unwrap()))?;
    let reader = BufReader::new(file);
    let data: UserFileCrypted = bincode::deserialize_from(reader)?;
    return Ok(data);
}

fn write_user_file(user_data: &UserFileCrypted) -> Result<(), PasswordManagerError> {
    if Context::get().current_user_path.is_none() {
        return Err(PasswordManagerError::InvalidUser);
    }
    let file = File::create(format!("{}/data", Context::get().current_user_path.as_ref().unwrap()))?;
    let mut writer = BufWriter::new(file);
    bincode::serialize_into(&mut writer, &user_data)?;
    writer.flush()?;
    Ok(())
}

fn get_user_uuid() -> Option<Uuid> {
    let username = input::<String>().msg("Please enter your username (Enter with no input to return to previous screen):").get();
    if username.is_empty() {
        return None;
    }
    Some(Uuid::new_v5(&Uuid::NAMESPACE_OID, username.as_bytes()))
}

fn get_master_key_from_password(salt: SaltString) -> Option<SecretVec<u8>> {
    // TODO change to make sure the password is not displayed (rpassword maybe)
    let input_user = input::<SecretString>().msg("Please enter your password (Enter with no input to return to previous screen):").get();
    println!("Verifying password. Please wait");
    let password = input_user.expose_secret();
    if password.is_empty() {
        return None;
    }
    let mut param_builder = ParamsBuilder::new();
    // TODO manage error
    param_builder.output_len(32);
    param_builder.t_cost(10);
    param_builder.p_cost(4);
    param_builder.m_cost(16384);
    let p = param_builder.params().unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::default(), p);
    // TODO remove unwrap and replace by error management
    let master_key = argon2.hash_password(password.as_bytes(), &salt).unwrap().hash.unwrap();
    Some(SecretVec::new(Vec::from(master_key.as_bytes())))
}

fn generate_key() -> Result<(), Box<dyn Error>> {
    // 0. generate 16 bytes of salt
    // 1. master_password  = input(user)
    // 2. Check master_password strength and display info about it (Check if do only on a separate function)
    // 3. master_key = Argon2(master_password)
    // 4. Clear master_password
    // 5. verify_hash = SHA-256(master_key)
    // 6. Generate password_key
    // 7. Encrypt password_key with master_key
    // 8. Write file
    let salt = SaltString::generate(&mut OsRng);
    let salt_copy = salt.clone();
    let master_key = match get_master_key_from_password(salt) {
        None => { return Ok(()); }
        Some(m) => { m }
    };

    let mut hasher = Sha512::new();
    hasher.update(&master_key.expose_secret());
    let hash = hasher.finalize();
    let mut nonce = [0u8; 24];
    let mut password_keys = [0u8; 32];
    OsRng.fill_bytes(&mut password_keys);
    OsRng.fill_bytes(&mut nonce);
    let key = Key::from_slice(master_key.expose_secret().as_slice());
    let nonce = XNonce::from_slice(&nonce);
    let aead = XChaCha20Poly1305::new(&key);


    let private = UserFilePrivatePart {
        password_key: password_keys,
        password_count: 0,
        passwords: vec![],
    };

    let private_data = bincode::serialize(&private)?;
    password_keys.zeroize();

    let public = UserFilePublicPart {
        salt: salt_copy.as_str().parse().unwrap(),
        hash: hex::encode(hash),
        iv: nonce.as_slice().try_into().expect("Invalid length"),
    };
    let public_data = bincode::serialize(&public)?;

    // TODO remove unwrap and manage Error
    // TODO check if adding the nonce in the aad is bad
    let ciphertext = aead.encrypt(nonce, Payload { msg: private_data.as_slice(), aad: public_data.as_slice() }).unwrap();


    write_user_file(&UserFileCrypted {
        public,
        private: ciphertext,
    })?;
    Ok(())
}

fn register() -> Result<(), Box<dyn Error>> {
    loop {
        let uuid = match get_user_uuid() {
            None => { break; }
            Some(uuid) => { uuid }
        };
        let user_path = format!("{}/{}", Context::get().users_folders, uuid);
        // Check username uniqueness
        if !std::path::Path::new(user_path.as_str()).exists() {
            std::fs::create_dir_all(&user_path)?;
            Context::set_user_path(Option::from(user_path));
            generate_key()?;
            println!("Account created !");
            break;
        } else {
            println!("This username already exists. Please use another one");
        }
    }
    Ok(())
}

fn login() -> Result<Option<UserFile>, Box<dyn Error>> {
    loop {
        let uuid = match get_user_uuid() {
            None => { break; }
            Some(uuid) => { uuid }
        };
        let user_path = format!("{}/{}", Context::get().users_folders, uuid);
        // Check username uniqueness
        if !std::path::Path::new(user_path.as_str()).exists() {
            println!("The username is not  registered. Please register your account first.");
        } else {
            //TODO ask for password
            // 0. Load data for user
            // 1. Ask for password
            // 2. master_key = Argon2(master_password)
            // 3. Clear master_password
            // 4. Check file_hash = SHA-256(master_key)
            // 5. Decrypt password_key and site data
            // 6. enter secure menu
            Context::set_user_path(Option::from(user_path));
            let data = read_user_file()?;
            // TODO manage unwrap to indicate invalid salt
            let salt = SaltString::new(data.public.salt.as_str()).unwrap();
            let master_key = match get_master_key_from_password(salt) {
                None => { break}
                Some(m) => { m }
            };

            let mut hasher = Sha512::new();
            hasher.update(&master_key.expose_secret());
            let hash = hasher.finalize();
            let hash = hex::encode(hash);
            // TODO check if needed or we can based ourself on the authenticity (Auth would not allow to differentiate if password is false or data was modified)
            if !constant_time_eq(hash.as_bytes(), data.public.hash.as_bytes()) {
                // TODO manage invalid hashes
                panic!("Invalid hashes")
            }

            let key = Key::from_slice(master_key.expose_secret().as_slice());
            let nonce = XNonce::from_slice(data.public.iv.as_slice());
            let aead = XChaCha20Poly1305::new(&key);

            let public_data = bincode::serialize(&data.public)?;
            // TODO manage invalid decryption
            let plaintext = aead.decrypt(nonce, Payload { msg: data.private.as_slice(), aad: public_data.as_slice() }).unwrap();
            let passwords: UserFilePrivatePart = bincode::deserialize(&plaintext)?;
            return Ok(Some(UserFile { public: data.public, private: passwords }));
        }
    }
    Ok(None)
}

fn secure_menu(data: &UserFile) {
    loop {
        match input::<i32>().repeat_msg("Please select one of the following to continue\
        \n0 - Exit\
        \n1 - Add password\
        \n2 - Show password\
        \n3 - Share password\
        \n4 - Verify password strength\
        \n5 - Generate password"
        ).min_max(0, 2).get() {
            0 => {
                println!("Exiting password manager !");
                break;
            }
            1 => todo!(),
            2 => todo!(),
            _ => panic!("Invalid input")
        }
    }
}

fn secure_mode() -> Result<(), Box<dyn Error>>{
    let data = login()?;
    if data.is_none(){
        // TODO clear memory
        return Ok(());
    }
    secure_menu(&data.unwrap());
    todo!()
}


fn main() -> Result<(), Box<dyn Error>> {
    Context::init();
    println!("Welcome to the very secure password manager !");
    loop {
        match input::<i32>().repeat_msg("Please select one of the following to continue\
        \n0 - Exit\
        \n1 - Login\
        \n2 - Create new account"
        ).min_max(0, 2).get() {
            0 => {
                println!("Exiting password manager !");
                break;
            }
            1 => secure_mode()?,
            2 => register()?,
            _ => panic!("Invalid input")
        }
    }
    Ok(())
}
