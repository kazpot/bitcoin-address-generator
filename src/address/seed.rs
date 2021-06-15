use crate::crypto::aes::{decrypt, encrypt};
use crate::crypto::password_key::gen_key;
use rand::rngs::OsRng;
use rand::RngCore;
use rpassword::read_password;
use std::env::current_dir;
use std::fs;
use std::fs::{File};
use std::process;
use std::io::Write;


/// Seed size (256 bits is advised in BIP32)
const SEED_SIZE_IN_BYTES: usize = 32;

/// Returns random seed
pub fn get_seed() -> Result<[u8; SEED_SIZE_IN_BYTES], String> {
    let mut out = [0u8; SEED_SIZE_IN_BYTES];
    OsRng.fill_bytes(&mut out);
    Ok(out)
}

/// Returns AES secret key which is derived from the typed password by user
pub fn gen_key_from_password() -> String {
    println!("Please type your seed password:");
    let password = match read_password() {
        Ok(password) => password,
        Err(e) => {
            println!("{:?}", e);
            process::exit(1)
        }
    };
    let key = match gen_key(password.trim()) {
        Ok(key) => key,
        Err(e) => {
            log::error!("{:?}", e);
            println!("Failed to generate key with password");
            process::exit(1)
        }
    };
    key
}

/// Returns seed which is read from .seed file at the same path as the running executable
pub fn read_seed_file() -> String {
    let dir = current_dir().unwrap();
    let path = dir.display().to_string();
    println!("{}", path);
    let contents = match fs::read_to_string(path + "/.seed") {
        Ok(contents) => contents,
        Err(e) => {
            log::error!("{:?}", e);
            println!("Failed to read seed file");
            process::exit(1)
        }
    };
    let contents = contents.trim();
    contents.to_string()
}

/// Returns encrypted seed and create .seed file at the same path as the running executable
pub fn encrypt_seed_with_password() -> String {
    let password = gen_key_from_password();
    let new_seed = match get_seed() {
        Ok(new_seed) => new_seed,
        Err(e) => {
            log::error!("{:?}", e);
            println!("Failed to generate seed");
            process::exit(1)
        }
    };
    let seed_hex = hex::encode(new_seed);

    let encrypted_seed = match encrypt(&password, &seed_hex) {
        Ok(encrypted_seed) => encrypted_seed,
        Err(e) => {
            log::error!("{:?}", e);
            println!("Failed to encrypt key with password");
            String::new()
        }
    };

    let mut file = match File::create(".seed") {
        Ok(f) => f,
        Err(e) => {
            log::error!("{:?}", e);
            println!("Failed to create seed file");
            process::exit(1)
        }
    };
    let res = match file.write_all(encrypted_seed.as_bytes()) {
        Ok(()) => true,
        Err(_) => false
    };
    if res {
        println!(".seed file was created successfully!");
    } else {
        println!("Failed to write seed file");
        process::exit(1)
    }
    encrypted_seed
}

/// Returns decrypted seed using the typed password by user
pub fn gen_seed_with_password() -> String {
    let password = gen_key_from_password();
    let encrypted_seed = read_seed_file();

    let decrypted_seed = match decrypt(&password, &encrypted_seed) {
        Ok(decrypted_seed) => decrypted_seed,
        Err(e) => {
            log::error!("{:?}", e);
            println!("Failed to decrypt key with password");
            process::exit(1)
        }
    };
    decrypted_seed
}

#[cfg(test)]
mod tests {
    use crate::address::seed::get_seed;

    #[test]
    fn gen_seed_test() {
        let seed = get_seed().unwrap();
        let seed_hex = hex::encode(seed);
        println!("seed: {}", seed_hex);
    }
}
