use serde::{Serialize, Deserialize};

/// Simple header for deterministic blocks
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Header {
    pub parent: [u8; 32],
    pub height: u64,
    pub proposer: Vec<u8>,   // public key bytes of proposer
    pub vrf_output: Vec<u8>, // raw VRF output used to elect proposer
    pub timestamp: u64,
}

/// Block structure
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Block {
    pub header: Header,
    pub txs: Vec<Vec<u8>>, // raw tx bytes
    pub signature: Vec<u8>, // ed25519 signature bytes
}

/// Vote structure (simple)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Vote {
    pub block_hash: [u8; 32],
    pub voter: Vec<u8>,      // public key bytes of voter
    pub signature: Vec<u8>,  // ed25519 signature bytes
}
