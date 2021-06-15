use ring::hmac::{Context, Key, HMAC_SHA512};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

type ChainCode = Vec<u8>;

/// Starting index of hardened child key
const HARDENED_KEY_START_INDEX: u32 = 2_147_483_648;

/// Node which is described in BIP32 Hierarchical Deterministic Wallets
#[derive(Debug, Clone)]
pub struct Bip32Node {
    /// Each Bip32 node has private key
    private_key: SecretKey,

    /// Each Bip32 node has public key
    public_key: PublicKey,

    /// Each Bip32 node has chain code
    chain_code: ChainCode,
}

impl Bip32Node {
    /// Returns master key node with the given seed
    ///
    /// # Arguments
    ///
    /// * `seed` - 256-bits seed
    pub fn get_master_key(seed: &[u8]) -> Result<Bip32Node, String> {
        let signing_key = Key::new(HMAC_SHA512, b"Bitcoin seed");
        let mut h = Context::with_key(&signing_key);
        h.update(&seed);
        let sig = h.sign();
        let sig_bytes = sig.as_ref();

        let (key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);
        let private_key = SecretKey::from_slice(key).map_err(|e| format!("{:?}", e))?;
        let public_key = PublicKey::from_secret_key(&Secp256k1::signing_only(), &private_key);

        Ok(Bip32Node {
            private_key,
            public_key,
            chain_code: chain_code.to_vec(),
        })
    }

    /// Returns normal child node
    ///
    /// # Arguments
    ///
    /// * `index` - The normal child keys use indices 0 through 2^31 - 1
    pub fn get_child(&self, index: u32) -> Result<Bip32Node, String> {
        if index >= HARDENED_KEY_START_INDEX {
            return Err(format!("Key index out of range: {}", index));
        }

        let signing_key = Key::new(HMAC_SHA512, &self.chain_code);
        let mut h = Context::with_key(&signing_key);
        let public_key = PublicKey::from_secret_key(&Secp256k1::signing_only(), &self.private_key);
        h.update(&public_key.serialize());
        h.update(&index.to_be_bytes());
        let sig = h.sign();
        let sig_bytes = sig.as_ref();
        let (key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);

        let mut private_key = SecretKey::from_slice(key).map_err(|e| format!("{:?}", e))?;
        private_key
            .add_assign(&self.private_key[..])
            .map_err(|e| format!("{:?}", e))?;

        let public_key = PublicKey::from_secret_key(&Secp256k1::signing_only(), &private_key);

        Ok(Bip32Node {
            private_key,
            public_key,
            chain_code: chain_code.to_vec(),
        })
    }

    /// Returns normal child node
    ///
    /// # Arguments
    ///
    /// * `index` - Hardened key indices represent index + 2^31
    pub fn get_child_h(&self, index: u32) -> Result<Bip32Node, String> {
        let index = index + HARDENED_KEY_START_INDEX;
        if index < HARDENED_KEY_START_INDEX {
            return Err(format!("Key index out of range: {}", index));
        }

        let signing_key = Key::new(HMAC_SHA512, &self.chain_code);
        let mut h = Context::with_key(&signing_key);
        h.update(&[0x00]);
        h.update(&self.private_key[..]);
        h.update(&index.to_be_bytes());
        let sig = h.sign();
        let sig_bytes = sig.as_ref();
        let (key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);

        let mut private_key = SecretKey::from_slice(key).map_err(|e| format!("{:?}", e))?;
        private_key
            .add_assign(&self.private_key[..])
            .map_err(|e| format!("{:?}", e))?;

        let public_key = PublicKey::from_secret_key(&Secp256k1::signing_only(), &private_key);

        Ok(Bip32Node {
            private_key,
            public_key,
            chain_code: chain_code.to_vec(),
        })
    }

    /// Returns normal child node
    ///
    /// # Arguments
    ///
    /// * `seed` - Seed to create master key node
    /// * `index` - The normal child keys use indices 0 through 2^31 - 1
    pub fn get_btc_address(seed: &[u8], address_index: u32) -> Result<String, String> {
        if let Ok(master_node) = Bip32Node::get_master_key(seed) {
            let address_node = master_node
                .get_child_h(44)?
                .get_child_h(0)?
                .get_child_h(0)?
                .get_child(0)?
                .get_child(address_index)?;
            let pubkey_hex = hex::encode(address_node.public_key.serialize());
            return Ok(pubkey_hex);
        }
        Err("Failed to get master node".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::Bip32Node;
    use crate::address::seed;
    use secp256k1::{PublicKey, Secp256k1};

    #[test]
    fn random_master_private_key() {
        let seed = seed::get_seed().unwrap();
        if Bip32Node::get_master_key(&seed).is_ok() {
            return;
        }
    }

    #[test]
    fn derive_child_private_key() {
        let seed = seed::get_seed().unwrap();
        if let Ok(master_node) = Bip32Node::get_master_key(&seed) {
            let _child_h = master_node.get_child_h(0).unwrap();
            let _child_normal = master_node.get_child(0).unwrap();
        }
    }

    #[test]
    fn derive_child_public_key() {
        let seed = seed::get_seed().unwrap();
        if let Ok(master_node) = Bip32Node::get_master_key(&seed) {
            let child_node = master_node.get_child(0).unwrap();
            let child_public_key =
                PublicKey::from_secret_key(&Secp256k1::signing_only(), &child_node.private_key);
            assert_eq!(child_node.public_key, child_public_key);
        }
    }

    #[test]
    fn derive_address_node() {
        // m/44H/0H/0H/0/56
        let seed = "e8f6806aef846e561731977ec92ca2090535ff03b0f15c174c9b3ea6bfd346bd";
        if let Ok(master_node) = Bip32Node::get_master_key(&hex::decode(seed).unwrap()) {
            let address_node = master_node
                .get_child_h(44)
                .unwrap()
                .get_child_h(0)
                .unwrap()
                .get_child_h(0)
                .unwrap()
                .get_child(0)
                .unwrap()
                .get_child(56)
                .unwrap();

            let privkey_hex = master_node.private_key.to_string();
            let pubkey_hex = hex::encode(master_node.public_key.serialize());
            assert_eq!(
                privkey_hex,
                "06d69134e8d242793839813d797783daeb9990a7720d4a08cd0aefc23d55044f"
            );
            assert_eq!(
                pubkey_hex,
                "02acf478e0c5ee9de0aff8cde2a933122d15db05d2bc1154267d99faffa2893618"
            );

            let privkey_hex = address_node.private_key.to_string();
            let pubkey_hex = hex::encode(address_node.public_key.serialize());
            assert_eq!(
                privkey_hex,
                "5d3996ba249ee5c331e9c656355970981b6c5d358a1769e858d1dfe269253626"
            );
            assert_eq!(
                pubkey_hex,
                "026151b3d43ce3a9edac363b44ab85ebd49b34fd82944d7e0faafbe7d02df6d7b4"
            );
        }
    }
}
