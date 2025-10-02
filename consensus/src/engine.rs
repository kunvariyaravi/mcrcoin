use crate::types::{Block, Header, Vote};
use anyhow::{Result, anyhow};
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use rand_core::OsRng; // use rand_core's OsRng (matches ed25519-dalek's rand_core version)
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

use vrf::VrfBackend;

/// A ConsensusEngine is instantiated with:
/// - local keypair (ed25519)
/// - list of validators (their public keys as bytes)
/// - a VRF backend (boxed trait object)
pub struct ConsensusEngine {
    pub keypair: Keypair,
    pub validators: Vec<Vec<u8>>, // each validator's public key bytes
    pub vrf: Box<dyn VrfBackend + Send + Sync>,
    /// configurable block time in milliseconds (used by node loop)
    pub block_time_ms: u64,
}

impl ConsensusEngine {
    /// Create a new engine with a freshly-generated keypair and given validators list.
    pub fn new_with_rng(validators: Vec<Vec<u8>>, vrf: Box<dyn VrfBackend + Send + Sync>, block_time_ms: u64) -> Self {
        let mut csprng = OsRng{};
        let keypair = Keypair::generate(&mut csprng);
        Self { keypair, validators, vrf, block_time_ms }
    }

    /// Create from an existing secret key bytes (32 bytes) if you want deterministic keys.
    pub fn new_from_sk_bytes(sk_bytes: &[u8], validators: Vec<Vec<u8>>, vrf: Box<dyn VrfBackend + Send + Sync>, block_time_ms: u64) -> Result<Self> {
        if sk_bytes.len() != 32 { return Err(anyhow!("secret key must be 32 bytes")); }
        let secret = SecretKey::from_bytes(sk_bytes)?;
        let public: PublicKey = (&secret).into();
        let keypair = Keypair{ secret, public };
        Ok(Self { keypair, validators, vrf, block_time_ms })
    }

    /// Propose a block given parent hash and transactions. Signs the block with local key.
    pub fn propose_block(&self, parent: [u8;32], height: u64, txs: Vec<Vec<u8>>) -> Result<Block> {
        let ts = now_ts()?;
        // VRF seed can be parent || height
        let mut seed = Vec::new();
        seed.extend_from_slice(&parent);
        seed.extend_from_slice(&height.to_be_bytes());

        let (_proof, out) = self.vrf.prove(&seed)?;
        let header = Header {
            parent,
            height,
            proposer: self.keypair.public.to_bytes().to_vec(),
            vrf_output: out.clone(),
            timestamp: ts,
        };

        // deterministic block hash input: header fields + txs (we sign digest, not whole block)
        let digest = block_hash_for_signing(&header, &txs)?;
        let sig: Signature = self.keypair.sign(&digest);
        let block = Block {
            header,
            txs,
            signature: sig.to_bytes().to_vec(),
        };
        // NOTE: we don't persist proof in block currently (could be included)
        Ok(block)
    }

    /// Validate block signature and proposer membership
    pub fn validate_block(&self, block: &Block, expected_parent: Option<&[u8;32]>) -> Result<()> {
        // check continuity if parent provided
        if let Some(parent) = expected_parent {
            if block.header.parent != *parent {
                return Err(anyhow!("parent mismatch: expected parent ≠ block.parent"));
            }
            if block.header.height == 0 || block.header.height <= 0 {
                return Err(anyhow!("invalid height"));
            }
        }
        // verify proposer is a known validator
        if !self.validators.is_empty() {
            if !self.validators.iter().any(|v| v.as_slice() == block.header.proposer.as_slice()) {
                return Err(anyhow!("proposer not in validator set"));
            }
        }

        // verify signature
        let pubkey = PublicKey::from_bytes(&block.header.proposer)
            .map_err(|e| anyhow!("invalid proposer public key bytes: {}", e))?;
        let digest = block_hash_for_signing(&block.header, &block.txs)?;
        let sig = Signature::from_bytes(&block.signature)
            .map_err(|e| anyhow!("invalid signature bytes: {}", e))?;
        pubkey.verify(&digest, &sig)
            .map_err(|e| anyhow!("signature verification failed: {}", e))?;

        Ok(())
    }

    /// Deterministic fork resolution: choose the chain with higher length (simple longest-chain)
    pub fn resolve_fork(&self, local_chain: &Vec<Block>, remote_chain: &Vec<Block>) -> Vec<Block> {
        if remote_chain.len() > local_chain.len() {
            remote_chain.clone()
        } else {
            local_chain.clone()
        }
    }

    /// Determine whether local node is the elected proposer for the given parent/height
    /// Algorithm: each validator computes VRF(seed) where seed = parent || height (same for all);
    /// VRF is computed using validator's secret key, producing different outputs per validator.
    /// Map VRF output to a u64 and reduce modulo validators.len() to pick a winner index.
    pub fn am_i_proposer(&self, parent: [u8;32], height: u64) -> Result<bool> {
        // Build seed shared across validators (do NOT include caller's public key)
        let mut seed = Vec::new();
        seed.extend_from_slice(&parent);
        seed.extend_from_slice(&height.to_be_bytes());

        // Each validator calls VRF with the same seed using their own secret key.
        // The DummyVrf.prove uses the caller's backing key internally (not part of seed).
        let (_proof, out) = self.vrf.prove(&seed)?;
        // hash vrf output -> u64 -> modulo validators.len()
        let mut h = Sha256::new();
        h.update(&out);
        let digest = h.finalize();
        let idx = u64::from_be_bytes([
            digest[0], digest[1], digest[2], digest[3],
            digest[4], digest[5], digest[6], digest[7],
        ]) as usize;

        if self.validators.is_empty() {
            // if no validators list provided, default to a single-node proposer (local node is proposer)
            return Ok(true);
        }
        let selected = idx % self.validators.len();
        let my_pub = self.keypair.public.to_bytes();
        let winner_pub = &self.validators[selected];
        Ok(winner_pub.as_slice() == my_pub.as_ref())
    }
}

/// Helper: produce a deterministic digest for signing a block (header fields + txs)
fn block_hash_for_signing(header: &Header, txs: &Vec<Vec<u8>>) -> Result<[u8;32]> {
    let mut hasher = Sha256::new();
    hasher.update(&header.parent);
    hasher.update(&header.height.to_be_bytes());
    hasher.update(&header.proposer);
    hasher.update(&header.vrf_output);
    hasher.update(&header.timestamp.to_be_bytes());
    for tx in txs {
        hasher.update(&(tx.len() as u64).to_be_bytes());
        hasher.update(tx);
    }
    let d = hasher.finalize();
    let mut out = [0u8;32];
    out.copy_from_slice(&d[..32]);
    Ok(out)
}

/// helper to get current unix timestamp in millis
fn now_ts() -> Result<u64> {
    let dur = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(dur.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Header, Block};
    use vrf::DummyVrf;

    #[test]
    fn sign_and_verify_block() {
        let validators = vec![]; // empty -> allow any proposer
        let vrf = Box::new(DummyVrf::new());
        let engine = ConsensusEngine::new_with_rng(validators, vrf, 1000);

        let parent = [0u8;32];
        let block = engine.propose_block(parent, 1, vec![b"tx".to_vec()]).expect("propose");
        assert!(engine.validate_block(&block, Some(&parent)).is_ok());
    }

    #[test]
    fn leader_selection_rotation() {
        // create three validators with generated keys
        let mut rng = OsRng{};
        let kp1 = Keypair::generate(&mut rng);
        let kp2 = Keypair::generate(&mut rng);
        let kp3 = Keypair::generate(&mut rng);
        let validators = vec![
            kp1.public.to_bytes().to_vec(),
            kp2.public.to_bytes().to_vec(),
            kp3.public.to_bytes().to_vec(),
        ];

        // build three engines using the same validators but different SKs
        let e1 = ConsensusEngine::new_from_sk_bytes(&kp1.secret.to_bytes(), validators.clone(), Box::new(DummyVrf::new()), 1000).expect("e1");
        let e2 = ConsensusEngine::new_from_sk_bytes(&kp2.secret.to_bytes(), validators.clone(), Box::new(DummyVrf::new()), 1000).expect("e2");
        let e3 = ConsensusEngine::new_from_sk_bytes(&kp3.secret.to_bytes(), validators.clone(), Box::new(DummyVrf::new()), 1000).expect("e3");

        // simulate many heights and ensure exactly one of the three is selected as proposer per height
        let parent = [0u8;32];
        for h in 1..20u64 {
            let a = e1.am_i_proposer(parent, h).unwrap();
            let b = e2.am_i_proposer(parent, h).unwrap();
            let c = e3.am_i_proposer(parent, h).unwrap();
            // exactly one must be true
            let cnt = (a as u8) + (b as u8) + (c as u8);
            assert!(cnt == 1, "height {} had proposer count {}", h, cnt);
        }
    }

    #[test]
    fn propose_validate_multiple_txs() {
        let validators = vec![];
        let engine = ConsensusEngine::new_with_rng(validators, Box::new(DummyVrf::new()), 1000);
        let parent = [0u8;32];
        let block = engine.propose_block(parent, 1, vec![b"a".to_vec(), b"b".to_vec()]).expect("propose");
        assert!(engine.validate_block(&block, Some(&parent)).is_ok());
        // deterministic digest same as block signature
        let digest = block_hash_for_signing(&block.header, &block.txs).unwrap();
        let pubk = ed25519_dalek::PublicKey::from_bytes(&block.header.proposer).unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&block.signature).unwrap();
        assert!(pubk.verify(&digest, &sig).is_ok());
    }
}
