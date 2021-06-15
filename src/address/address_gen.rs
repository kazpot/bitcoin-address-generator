use crate::address::bip32::Bip32Node;
use ripemd160::{Digest, Ripemd160};

pub struct BtcAddress(String);

/// Bitcoin Network Version
enum NetowrkVersion {
    /// p2sh mainnet version prefix
    P2shMainnet = 5,
    /// p2sh testnet version prefix
    P2shTestnet = 196,
}

/// Bitcoin op code
enum Op {
    /// multi-sig op code
    MultiSig = 174,
}

impl BtcAddress {
    /// Returns Result containing segwit address with the provided address index
    /// Segwit address is described in https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
    /// Create P2SH-P2WPKH SegWit Address
    /// commonly used script is a P2WPKH (Pay to Witness Public Key Hash): OP_0 0x14 <PubKey Hash>
    /// where the PubKey Hash is the RIPEMD160 of the SHA256 of the public key
    ///
    /// # Arguments
    ///
    /// * `seed` - 256-bits seed
    /// * `address_index` - The normal child keys use indices 0 through 2^31 - 1
    pub fn gen_segwit_address_by_address_index(
        seed: &[u8],
        address_index: u32,
    ) -> Result<String, String> {
        let address_node_public_key =
            Bip32Node::get_btc_address(seed, address_index).map_err(|e| format!("{:?}", e))?;
        let pub_key_bytes = hex::decode(address_node_public_key).map_err(|e| format!("{:?}", e))?;
        let segwit_address = BtcAddress::gen_segwit_address(&pub_key_bytes[..], true)
            .map_err(|e| format!("{:?}", e))?;
        Ok(segwit_address)
    }

    /// Returns Result containing P2SH multi-sig address with provided public keys
    /// P2SH address is described in https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki
    /// Create p2sh address
    /// Commonly used script is {2 [pubkey1] [pubkey2] [pubkey3] 3 OP_CHECKMULTISIG} which is for 2-of-3 multi-sig
    ///
    /// # Arguments
    ///
    /// * `threshold` - Minimum number of signature which is needed to broadcast
    /// * `pub_key_list` - List of public keys which are used for verifying signatures
    /// * `is_mainnet` - Is mainnet?
    pub fn gen_multi_sig_p2sh_address(
        threshold: u32,
        pub_key_list: &Vec<String>,
        is_mainnet: bool,
    ) -> Result<String, String> {
        let pub_key_size = pub_key_list.len() as u32;
        if threshold <= 0 || threshold > pub_key_size || pub_key_size > 16 {
            return Err(format!(
                "out of range, threshold: {}, pub_key_size: {}",
                threshold, pub_key_size
            ));
        }

        let op_threshold = Self::encode_to_op_n(threshold)?;
        let op_pub_key_size = Self::encode_to_op_n(pub_key_size)?;

        let mut redeem_script = op_threshold;
        for pub_key in pub_key_list.iter() {
            let pub_key_bytes = hex::decode(pub_key).map_err(|e| format!("{:?}", e))?;
            let pub_key_size_hex = Self::u32_to_hex(pub_key_bytes.len() as u32);
            redeem_script.push_str(&pub_key_size_hex);
            redeem_script.push_str(pub_key);
        }
        redeem_script.push_str(&op_pub_key_size);

        let op_multi_sig = Self::u32_to_hex(Op::MultiSig as u32);
        redeem_script.push_str(&op_multi_sig);

        let redeem_script_bytes = hex::decode(redeem_script).map_err(|e| format!("{:?}", e))?;
        let redeem_script_hash = Self::hash160(&redeem_script_bytes)?;
        let redeem_script_hash_bytes =
            hex::decode(redeem_script_hash).map_err(|e| format!("{:?}", e))?;

        if is_mainnet {
            // version prefix 5: Mainnet script hash
            Ok(Self::b58_encode_checked(
                NetowrkVersion::P2shMainnet as u32,
                &redeem_script_hash_bytes,
            )?)
        } else {
            // version prefix 196: Testnet script hash
            Ok(Self::b58_encode_checked(
                NetowrkVersion::P2shTestnet as u32,
                &redeem_script_hash_bytes,
            )?)
        }
    }

    /// Returns Result containing segwit address with the provided public key and network
    ///
    /// # Arguments
    ///
    /// * `pub_key_bytes` - Byte array of public key
    /// * `is_mainnet` - Is mainnet?
    pub fn gen_segwit_address(pub_key_bytes: &[u8], is_mainnet: bool) -> Result<String, String> {
        let pub_key_hash_hex = Self::hash160(pub_key_bytes)?;

        let mut script_sig_hex: String = String::new();
        script_sig_hex.push_str("0014");
        script_sig_hex.push_str(&pub_key_hash_hex);

        let script_sig_bytes = hex::decode(script_sig_hex).map_err(|e| format!("{:?}", e))?;
        let pub_key_hash = Self::hash160(&script_sig_bytes)?;
        let pub_key_hash_byte = hex::decode(pub_key_hash).map_err(|e| format!("{:?}", e))?;

        if is_mainnet {
            // version prefix 5: Mainnet script hash
            Ok(Self::b58_encode_checked(
                NetowrkVersion::P2shMainnet as u32,
                &pub_key_hash_byte,
            )?)
        } else {
            // version prefix 196: Testnet script hash
            Ok(Self::b58_encode_checked(
                NetowrkVersion::P2shTestnet as u32,
                &pub_key_hash_byte,
            )?)
        }
    }

    /// Returns Result containing base58 encoded with check sum
    ///
    /// # Arguments
    ///
    /// * `version` - Version byte
    /// * `payload` - Public key hash (20-bytes)
    fn b58_encode_checked(version: u32, payload: &[u8]) -> Result<String, String> {
        if version > 255 {
            return Err(format!("version index out of range: {}", version));
        }

        let address_size = 1 + payload.len() + 4;
        let mut address_bytes_slice = vec![0; address_size];
        address_bytes_slice[0] = (version & 0xff) as u8;

        let payload_slice = payload.to_vec();
        address_bytes_slice[1..payload.len() + 1].clone_from_slice(&*payload_slice);

        let mut address_bytes_to_be_hashed = vec![0; payload.len() + 1];
        address_bytes_to_be_hashed[0..].clone_from_slice(&address_bytes_slice[..payload.len() + 1]);

        // SHA256 hash twice
        let temp = hex::decode(sha256::digest_bytes(&address_bytes_to_be_hashed))
            .map_err(|e| format!("{:?}", e))?;
        let check_sum = hex::decode(sha256::digest_bytes(&temp).into_bytes())
            .map_err(|e| format!("{:?}", e))?;

        address_bytes_slice[payload.len() + 1..address_size].clone_from_slice(&check_sum[..4]);
        Ok(bs58::encode(address_bytes_slice.to_vec()).into_string())
    }

    /// Returns Result containing string which is made by RIPEMD-160 and SHA-256
    ///
    /// # Arguments
    ///
    /// * `data` - Data in bytes
    fn hash160(data: &[u8]) -> Result<String, String> {
        let hash = hex::decode(sha256::digest_bytes(data)).map_err(|e| format!("{:?}", e))?;
        let mut ripemd160_hasher = Ripemd160::new();
        ripemd160_hasher.update(hash);
        let second_hash = ripemd160_hasher.finalize();
        Ok(hex::encode(second_hash.as_slice()))
    }

    /// Returns Result containing valid bitcoin op code which is converted from integer
    /// For example, 0x52 => OP_2, 0x60 => OP_16
    /// to create redeem script such as
    /// OP_2(0x52) pubkey_hex1 pubkey_hex2 pubkey_hex3 OP_3(0x53) OP_CHECKMULTISIG(0xae)
    ///
    /// # Arguments
    ///
    /// * `opcode` - opcode in unsigned integer
    fn encode_to_op_n(opcode: u32) -> Result<String, String> {
        if opcode < 2 || opcode > 16 {
            return Err(format!("op code out of range: {}", opcode));
        }
        Ok(Self::u32_to_hex(opcode + 80))
    }

    /// Returns hex string which is converted from unsigned integer
    ///
    /// # Arguments
    ///
    /// * `n` - n in unsigned integer
    fn u32_to_hex(n: u32) -> String {
        format!("{:x}", n)
    }
}

#[cfg(test)]
mod tests {
    use super::BtcAddress;

    #[test]
    fn gen_segwit_address_from_public_key_main_net() {
        let pub_key_bytes =
            hex::decode("039798f33e16b796f31ad1ab73d714c43f4168ad35a2c36b1745d72d3b15ab50c5")
                .unwrap();
        let segwit_address = BtcAddress::gen_segwit_address(&pub_key_bytes[..], true).unwrap();
        assert_eq!(segwit_address, "338TFvrHGJnuUf1EEgt6reM1NREwKqJfHk");
    }

    #[test]
    fn gen_segwit_address_from_public_key_test_net() {
        let pub_key_bytes =
            hex::decode("039798f33e16b796f31ad1ab73d714c43f4168ad35a2c36b1745d72d3b15ab50c5")
                .unwrap();
        let segwit_address = BtcAddress::gen_segwit_address(&pub_key_bytes[..], false).unwrap();
        assert_eq!(segwit_address, "2MtgfKfnJsmJFgSdmupVyUbLGamT74tcvE6");
    }

    #[test]
    fn b58_encode_checked_test() {
        let payload_bytes = [0x01, 0x02, 0x03, 0x04];
        let result = BtcAddress::b58_encode_checked(4, &payload_bytes).unwrap();
        assert_eq!(result, "3xSrtjFhmp47");
    }

    #[test]
    fn encode_to_op_n_test() {
        let opcode = BtcAddress::encode_to_op_n(2);
        assert_eq!(opcode.unwrap(), "52".to_string());

        let opcode = BtcAddress::encode_to_op_n(16);
        assert_eq!(opcode.unwrap(), "60".to_string());
    }

    #[test]
    fn u32_to_hex_test() {
        let op_multi_sig = BtcAddress::u32_to_hex(174);
        assert_eq!(op_multi_sig, "ae");
    }

    #[test]
    fn get_multi_sig_p2sh_address_mainnet_test() {
        let pub_key_list = vec![
            "03b5807b167a4950e883ee383194a1e7ae0804d312b68f303743a9f3a19c3029cf".to_string(),
            "032fc4366e9eab6f4a879035e25f4c8b3bf7aece95e6ddd2e325d95fb9660c5fbf".to_string(),
            "02ab1d0cf83b59a605add3bb3cff58844271373a56f20eadac93d6ee0723ab516d".to_string(),
        ];

        // multi sig 2 of 3
        let threshold = 2 as u32;
        let address = BtcAddress::gen_multi_sig_p2sh_address(threshold, &pub_key_list, true);
        assert_eq!(address.unwrap(), "3CvvGqDgzmzh1mavUZWKSMC3qYihks1dr7");
    }

    #[test]
    fn get_multi_sig_p2sh_address_testnet_test() {
        let pub_key_list = vec![
            "03b5807b167a4950e883ee383194a1e7ae0804d312b68f303743a9f3a19c3029cf".to_string(),
            "032fc4366e9eab6f4a879035e25f4c8b3bf7aece95e6ddd2e325d95fb9660c5fbf".to_string(),
            "02ab1d0cf83b59a605add3bb3cff58844271373a56f20eadac93d6ee0723ab516d".to_string(),
            "0251722108e06299d2fd9827e6868046323161823c35a7ff8f02ce3a28424d6bb0".to_string(),
            "035ebe21bf771af0ef807806f82d7c58d3ed8af30677c1a63fbcae8168b8449133".to_string(),
        ];

        // multi sig 4 of 5
        let threshold = 4 as u32;
        let address = BtcAddress::gen_multi_sig_p2sh_address(threshold, &pub_key_list, false);
        assert_eq!(address.unwrap(), "2N5Euu6Jjeryt6zb5dv2Ys3tLZyvqJDakt8");
    }
}
