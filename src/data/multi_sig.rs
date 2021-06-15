use serde::{Deserialize, Serialize};

/// Request data
#[derive(Debug, Serialize, Deserialize)]
pub struct MultiSig {
    /// is mainnet?
    pub mainnet: bool,
    /// n in n-of-m
    pub n: u32,
    /// m in n-of-m
    pub m: u32,
    /// public key array
    pub public_keys: Vec<String>,
}
