use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use rand::rngs::OsRng;
use rand::RngCore;

/// AES CBC block mode
type AesCbc = Cbc<Aes256, Pkcs7>;

/// Initialization vector size in bytes
const IV_SIZE_IN_BYTES: usize = 16;

/// Returns Result containing encrypted data
///
/// # Arguments
///
/// * `key` - AES key in string (32-bytes)
/// * `data` - Data to be encrypted in string
pub fn encrypt(key: &str, data: &str) -> Result<String, String> {
    let key_bytes = hex::decode(key).map_err(|e| format!("{:?}", e))?;
    let mut iv = [0u8; IV_SIZE_IN_BYTES];
    OsRng.fill_bytes(&mut iv);

    let aes = AesCbc::new_from_slices(&key_bytes, &iv).map_err(|e| format!("{:?}", e))?;
    let cipher_text = aes.encrypt_vec(data.as_bytes());
    let mut buffer = bytebuffer::ByteBuffer::from_bytes(&iv);
    buffer.write_bytes(&cipher_text);
    Ok(hex::encode(buffer.to_bytes()))
}

/// Returns Result containing decrypted data
///
/// # Arguments
///
/// * `key` - AES key in string (32-bytes)
/// * `data` - Data to be decrypted in string
pub fn decrypt(key: &str, data: &str) -> Result<String, String> {
    let key_bytes = hex::decode(key).map_err(|e| format!("{:?}", e))?;
    let bytes = hex::decode(&data).map_err(|e| format!("{:?}", e))?;
    let aes = AesCbc::new_from_slices(&key_bytes, &bytes[0..16]).map_err(|e| format!("{:?}", e))?;
    let decrypted_bytes = aes
        .decrypt_vec(&bytes[16..])
        .map_err(|e| format!("{:?}", e))?;
    Ok(String::from_utf8(decrypted_bytes).map_err(|e| format!("{:?}", e))?)
}

#[cfg(test)]
mod tests {
    use crate::crypto::aes::{decrypt, encrypt};
    use crate::crypto::password_key;

    #[test]
    fn encrypt_test() {
        let key = "50f2b400fd91695eb124dc2ebc53788bbb4eac0eae8a54f7258aca15a5607bbb";
        let data = "d9b133f95b5d36dd8adc650690749467b5399ab3381751f11cfcb5c4449c4883";
        let _encrypted = encrypt(key, data).unwrap();
    }

    #[test]
    fn decrypt_test() {
        let key = "50f2b400fd91695eb124dc2ebc53788bbb4eac0eae8a54f7258aca15a5607bbb";
        let data = "d9b133f95b5d36dd8adc650690749467b5399ab3381751f11cfcb5c4449c4883";
        let encrypted = encrypt(key, data).unwrap();
        let decrypted = decrypt(key, encrypted.as_str()).unwrap();
        assert_eq!(
            decrypted,
            "d9b133f95b5d36dd8adc650690749467b5399ab3381751f11cfcb5c4449c4883"
        );
    }

    #[test]
    fn gen_key_and_encrypt_decrypt() {
        let password = "hello";
        let data = "e8f6806aef846e561731977ec92ca2090535ff03b0f15c174c9b3ea6bfd346bd";
        let key = password_key::gen_key(password).unwrap();
        let encrypted = encrypt(&key, data).unwrap();
        let decrypted = decrypt(&key, encrypted.as_str()).unwrap();
        assert_eq!(
            decrypted,
            "e8f6806aef846e561731977ec92ca2090535ff03b0f15c174c9b3ea6bfd346bd"
        );
    }
}
