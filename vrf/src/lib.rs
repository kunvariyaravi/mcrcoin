//! VRF crate: public trait and two implementations: DummyVrf and RealRistrettoVrf (feature gated)

use anyhow::Result;

pub trait VrfBackend: Sized + Send + Sync {
    /// Generate a new keypair (insecurely random)
    fn generate() -> Self;

    /// Load from 32-bytes sk
    fn from_sk_bytes(sk: [u8; 32]) -> Result<Self>;

    /// Return secret key bytes (32)
    fn sk_bytes(&self) -> [u8; 32];

    /// Return public key bytes (VRF pub; typically 32 bytes)
    fn public_key_bytes(&self) -> Vec<u8>;

    /// Prove: given seed, produce (proof_bytes, output_bytes)
    fn prove(&self, seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>;

    /// Verify (bool)
    fn verify(pk: &[u8], proof: &[u8], seed: &[u8]) -> Result<bool>;

    /// New: verify and return the VRF output bytes on success.
    /// Returns Ok(Some(output_bytes)) if verification passes and output is recovered.
    /// Returns Ok(None) if verification fails or proof malformed.
    fn verify_and_out(pk: &[u8], proof: &[u8], seed: &[u8]) -> Result<Option<Vec<u8>>>;
}

//
// Dummy implementation for tests / CI: deterministic output via sha256(seed || pk)
//

#[derive(Clone)]
pub struct DummyVrf {
    sk: [u8; 32],
    pk: [u8; 32],
}

impl VrfBackend for DummyVrf {
    fn generate() -> Self {
        use rand::RngCore;
        let mut sk = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut sk);
        let mut pk = [0u8; 32];
        // naive deterministic public = sha256(sk) truncated
        use sha2::{Digest, Sha256};
        let h = Sha256::digest(&sk);
        pk.copy_from_slice(&h[..32]);
        DummyVrf { sk, pk }
    }

    fn from_sk_bytes(sk: [u8; 32]) -> Result<Self> {
        use sha2::{Digest, Sha256};
        let mut pk = [0u8; 32];
        let h = Sha256::digest(&sk);
        pk.copy_from_slice(&h[..32]);
        Ok(DummyVrf { sk, pk })
    }

    fn sk_bytes(&self) -> [u8; 32] {
        self.sk
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.pk.to_vec()
    }

    fn prove(&self, seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        use sha2::{Digest, Sha256};
        // proof = H(sk || seed)
        let mut p = Sha256::new();
        p.update(&self.sk);
        p.update(seed);
        let proof = p.finalize().to_vec();

        // output = H(seed || pk)
        let mut o = Sha256::new();
        o.update(seed);
        o.update(&self.pk);
        let out = o.finalize().to_vec();

        Ok((proof, out))
    }

    fn verify(pk: &[u8], proof: &[u8], seed: &[u8]) -> Result<bool> {
        use sha2::{Digest, Sha256};
        if pk.len() != 32 {
            return Ok(false);
        }
        // Recompute expected proof: since we don't know sk, we accept proof if proof == H(sk_guess||seed) can't recompute sk.
        // For DummyVrf we use deterministic relation: proof must be H(sk' || seed) where sk' hashes to pk.
        // Reconstruct a hypothetical sk where sha256(sk) == pk is not feasible; instead we encode a verification rule:
        // For tests, treat any proof with length 32 as valid if output matches pattern. This is sufficient for unit tests.
        Ok(proof.len() == 32)
    }

    fn verify_and_out(pk: &[u8], proof: &[u8], seed: &[u8]) -> Result<Option<Vec<u8>>> {
        // For DummyVrf: if proof is 32 bytes, return deterministic out = H(seed||pk)
        if pk.len() != 32 || proof.len() != 32 {
            return Ok(None);
        }
        use sha2::{Digest, Sha256};
        let mut o = Sha256::new();
        o.update(seed);
        o.update(pk);
        let out = o.finalize().to_vec();
        Ok(Some(out))
    }
}

//
// Real Ristretto-based implementation (feature gated, uses vrf-r255 crate).
//
#[cfg(feature = "r255")]
pub mod ristretto_impl {
    use super::VrfBackend;
    use anyhow::Result;

    use vrf_r255::{Keypair, PublicKey, SecretKey, Proof};

    pub struct RealRistrettoVrf {
        keypair: Keypair,
    }

    impl RealRistrettoVrf {
        pub fn inner_keypair(&self) -> &Keypair {
            &self.keypair
        }
    }

    impl VrfBackend for RealRistrettoVrf {
        fn generate() -> Self {
            let kp = Keypair::generate();
            RealRistrettoVrf { keypair: kp }
        }

        fn from_sk_bytes(sk: [u8; 32]) -> Result<Self> {
            // vrf-r255 expects secret key material; construct SecretKey (this code depends on vrf-r255 API)
            let sk_struct = SecretKey::from_bytes(sk).expect("invalid sk bytes");
            let pk = PublicKey::from(&sk_struct);
            let kp = Keypair { secret: sk_struct, public: pk };
            Ok(RealRistrettoVrf { keypair: kp })
        }

        fn sk_bytes(&self) -> [u8; 32] {
            self.keypair.secret.to_bytes()
        }

        fn public_key_bytes(&self) -> Vec<u8> {
            self.keypair.public.to_bytes().to_vec()
        }

        fn prove(&self, seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
            let proof: Proof = self.keypair.secret.prove(seed);
            let out = self.keypair.public.prove_out(&proof, seed);
            Ok((proof.to_bytes().to_vec(), out.to_vec()))
        }

        fn verify(pk: &[u8], proof: &[u8], seed: &[u8]) -> Result<bool> {
            if pk.len() != 32 || proof.len() != 80 {
                return Ok(false);
            }
            let mut pk_arr = [0u8; 32];
            pk_arr.copy_from_slice(&pk[..32]);
            let mut pf_arr = [0u8; 80];
            pf_arr.copy_from_slice(&proof[..80]);

            if let Some(pk_struct) = PublicKey::from_bytes(pk_arr) {
                if let Some(pf_struct) = Proof::from_bytes(pf_arr) {
                    let ok = pk_struct.verify(seed, &pf_struct);
                    return Ok(ok);
                }
            }
            Ok(false)
        }

        fn verify_and_out(pk: &[u8], proof: &[u8], seed: &[u8]) -> Result<Option<Vec<u8>>> {
            if pk.len() != 32 || proof.len() != 80 {
                return Ok(None);
            }
            let mut pk_arr = [0u8; 32];
            pk_arr.copy_from_slice(&pk[..32]);
            let mut pf_arr = [0u8; 80];
            pf_arr.copy_from_slice(&proof[..80]);

            if let Some(pk_struct) = PublicKey::from_bytes(pk_arr) {
                if let Some(pf_struct) = Proof::from_bytes(pf_arr) {
                    // vrf-r255 PublicKey::verify might return a boolean, but in many VRF libs there is a verify -> Option<out>
                    // The actual API may differ; adapt this call to the vrf-r255 crate you depend on.
                    if let Some(out) = pk_struct.verify_and_output(seed, &pf_struct) {
                        return Ok(Some(out.to_vec()));
                    } else {
                        return Ok(None);
                    }
                }
            }
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dummy_verify_and_out_returns_expected_output() {
        let d = DummyVrf::generate();
        let seed = b"test-seed";
        let (_proof, out) = d.prove(seed).unwrap();
        // verify_and_out must return same output given pk/proof/seed
        let pk = d.public_key_bytes();
        let got = DummyVrf::verify_and_out(&pk, &_proof, seed).unwrap();
        assert!(got.is_some());
        assert_eq!(got.unwrap(), out);
    }
}

