use ring::{digest, pbkdf2};
use std::num::NonZeroU32;

/// Returns Result containing AES key which is derived with they type password by user
///
/// # Arguments
///
/// * `password` - password in string
pub fn gen_key(password: &str) -> Result<String, String> {
    let n_iter = NonZeroU32::new(100_000).unwrap();
    let salt = sha256::digest("bitcoin was invented by satoshi nakamoto!");
    let salt_bytes = hex::decode(salt).map_err(|e| format!("{:?}", e))?;
    let mut hash = [0; digest::SHA256_OUTPUT_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        n_iter,
        &salt_bytes,
        password.as_bytes(),
        &mut hash,
    );
    Ok(hex::encode(&hash))
}

#[cfg(test)]
mod tests {
    use crate::crypto::password_key::gen_key;

    #[test]
    fn gen_key_test() {
        let password = "abcdef";
        let password_hash1 = gen_key(password).unwrap();
        let password_hash2 = gen_key(password).unwrap();
        assert_eq!(password_hash1, password_hash2);
    }
}
