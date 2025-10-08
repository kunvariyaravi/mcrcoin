use thiserror::Error;
use vrf_r255::{SecretKey, PublicKey, Proof};

pub mod keys;
pub use keys::{EncryptedSkFile, generate_keypair, save_encrypted_skfile, load_encrypted_skfile};

/// VRF output bytes
pub type VrfOutput = Vec<u8>;

/// Errors from VRF operations
#[derive(Debug, Error)]
pub enum VrfError {
    /// Proof verification failed
    #[error("proof verification failed")]
    InvalidProof,
    /// Failed to parse key bytes
    #[error("key parse error: {0}")]
    KeyParse(String),
    /// Wrong key/proof length
    #[error("wrong key/proof length: expected {expected} got {got}")]
    WrongKeyLength { expected: usize, got: usize },
    /// Other error
    #[error("other error: {0}")]
    Other(String),
}

/// Thin wrapper exposing evaluate + verify helpers using vrf_r255
pub struct RealRistrettoVrf;

impl RealRistrettoVrf {
    pub fn new() -> Self { Self }

    /// Evaluate the VRF using a 32-byte secret key and return (output, proof_bytes).
    pub fn evaluate(&self, sk_bytes: &[u8], msg: &[u8]) -> Result<(VrfOutput, Vec<u8>), VrfError> {
        if sk_bytes.len() != 32 {
            return Err(VrfError::WrongKeyLength { expected: 32, got: sk_bytes.len() });
        }
        let arr: [u8; 32] = sk_bytes.try_into().map_err(|_| VrfError::WrongKeyLength { expected: 32, got: sk_bytes.len() })?;

        let sk_opt: Option<SecretKey> = SecretKey::from_bytes(arr).into();
        let sk = sk_opt.ok_or_else(|| VrfError::KeyParse("invalid secret key bytes".into()))?;

        let proof: Proof = sk.prove(msg);
        let proof_bytes = proof.to_bytes().to_vec();

        let pk = PublicKey::from(sk);
        let hash_ctopt = pk.verify(msg, &proof);
        let hash_opt: Option<[u8; 64]> = hash_ctopt.into();
        let hash = hash_opt.ok_or_else(|| VrfError::Other("failed to compute hash output".into()))?;
        Ok((hash.to_vec(), proof_bytes))
    }

    /// Verify a proof under a 32-byte public key and return the hash output bytes if valid.
    pub fn verify_and_out(&self, pk_bytes: &[u8], msg: &[u8], proof_bytes: &[u8]) -> Result<VrfOutput, VrfError> {
        if pk_bytes.len() != 32 {
            return Err(VrfError::WrongKeyLength { expected: 32, got: pk_bytes.len() });
        }
        if proof_bytes.len() != 80 {
            return Err(VrfError::WrongKeyLength { expected: 80, got: proof_bytes.len() });
        }

        let pk_arr: [u8; 32] = pk_bytes.try_into().map_err(|_| VrfError::WrongKeyLength { expected: 32, got: pk_bytes.len() })?;
        let proof_arr: [u8; 80] = proof_bytes.try_into().map_err(|_| VrfError::WrongKeyLength { expected: 80, got: proof_bytes.len() })?;

        let pk_opt: Option<PublicKey> = PublicKey::from_bytes(pk_arr).into();
        let pk = pk_opt.ok_or_else(|| VrfError::KeyParse("invalid public key bytes".into()))?;

        let proof_opt: Option<Proof> = Proof::from_bytes(proof_arr).into();
        let proof = proof_opt.ok_or_else(|| VrfError::Other("invalid proof bytes".into()))?;

        let hash_ctopt = pk.verify(msg, &proof);
        let hash_opt: Option<[u8; 64]> = hash_ctopt.into();
        let hash = hash_opt.ok_or_else(|| VrfError::InvalidProof)?;

        Ok(hash.to_vec())
    }
}

// verify wrapper (auto-added)
pub mod verify;
pub use verify::verify_proof_bytes as verify_pub;
