use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use anyhow::{Result, anyhow};

/// Minimal Block header used by state. Keep this small to avoid circular deps.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Header {
    pub parent: [u8; 32],
    pub height: u64,
    pub timestamp: u64,
    pub proposer: Vec<u8>,
}

/// Minimal Block used by the state crate.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Block {
    pub header: Header,
    pub txs: Vec<Vec<u8>>,
}

/// Deterministic state root representation (simple merkle-like hash over applied headers)
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct State {
    /// last applied block height
    pub height: u64,
    /// an evolving root hash representing deterministic state
    pub root: [u8; 32],
    /// application log (kept small in memory)
    pub applied_headers: Vec<Header>,
}

impl State {
    /// Create a fresh State
    pub fn new() -> Self {
        Self {
            height: 0,
            root: [0u8; 32],
            applied_headers: Vec::new(),
        }
    }

    /// Apply a block deterministically. Updates height and root.
    /// Returns computed block hash for reference.
    pub fn apply_block(&mut self, block: &Block) -> Result<[u8; 32]> {
        // Basic checks: height continuity
        let expected = self.height + 1;
        if block.header.height != expected {
            return Err(anyhow!(
                "block height mismatch: expected {}, got {}",
                expected,
                block.header.height
            ));
        }

        // deterministic hash = SHA256(parent || height || timestamp || proposer || concatenated txs)
        let mut hasher = Sha256::new();
        hasher.update(&block.header.parent);
        hasher.update(&block.header.height.to_be_bytes());
        hasher.update(&block.header.timestamp.to_be_bytes());
        hasher.update(&block.header.proposer);
        for tx in &block.txs {
            hasher.update(&(tx.len() as u64).to_be_bytes());
            hasher.update(tx);
        }
        let digest = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&digest[..32]);

        // update state
        self.height = block.header.height;
        self.root = hash;
        self.applied_headers.push(block.header.clone());

        Ok(hash)
    }

    /// Take a deterministic snapshot (binary serialized)
    pub fn snapshot(&self) -> Result<Vec<u8>> {
        bincode::serialize(&self).map_err(|e| e.into())
    }

    /// Restore state from snapshot bytes
    pub fn restore(snapshot: &[u8]) -> Result<Self> {
        let s: State = bincode::deserialize(snapshot)?;
        Ok(s)
    }

    /// human-friendly root hex
    pub fn root_hex(&self) -> String {
        hex::encode(self.root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dummy_block(parent: [u8;32], height: u64, proposer: &[u8]) -> Block {
        Block {
            header: Header{
                parent,
                height,
                timestamp: 1000 + height,
                proposer: proposer.to_vec(),
            },
            txs: vec![b"tx1".to_vec(), b"tx2".to_vec()],
        }
    }

    #[test]
    fn apply_and_snapshot_restore() {
        let mut s = State::new();
        let b1 = make_dummy_block([0u8;32], 1, b"node1");
        let _h1 = s.apply_block(&b1).expect("apply b1");
        assert_eq!(s.height, 1);

        let b2 = make_dummy_block(s.root, 2, b"node2");
        let _h2 = s.apply_block(&b2).expect("apply b2");
        assert_eq!(s.height, 2);

        let snap = s.snapshot().expect("snapshot");
        let restored = State::restore(&snap).expect("restore");
        assert_eq!(restored.height, s.height);
        assert_eq!(restored.root, s.root);
        assert_eq!(restored.applied_headers, s.applied_headers);
    }

    #[test]
    fn reject_non_contiguous_height() {
        let mut s = State::new();
        let b_bad = make_dummy_block([0u8;32], 2, b"node1"); // height 2 but state is 0
        assert!(s.apply_block(&b_bad).is_err());
    }
}
