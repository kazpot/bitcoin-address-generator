use serde::{Deserialize, Serialize};

/// Request data
#[derive(Debug, Serialize, Deserialize)]
pub struct HdWallet {
    /// is mainnet?
    pub mainnet: bool,
    /// address index
    pub address_index: u32,
}
