use std::convert::TryInto;

/// Verify a VRF proof given public key bytes, proof bytes, and message bytes.
/// Returns the VRF output (64 bytes) on success, or an error string on failure.
pub fn verify_proof_bytes(pubkey_bytes: &[u8], proof_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, String> {
    use vrf_r255::{PublicKey, Proof};

    const PK_LEN: usize = 32;
    const PROOF_LEN: usize = 80;

    if pubkey_bytes.len() != PK_LEN {
        return Err(format!("invalid public key length: expected {}, got {}", PK_LEN, pubkey_bytes.len()));
    }
    if proof_bytes.len() != PROOF_LEN {
        return Err(format!("invalid proof length: expected {}, got {}", PROOF_LEN, proof_bytes.len()));
    }

    let pk_arr: [u8; PK_LEN] = pubkey_bytes.try_into().map_err(|_| "failed to convert public key bytes".to_string())?;
    let proof_arr: [u8; PROOF_LEN] = proof_bytes.try_into().map_err(|_| "failed to convert proof bytes".to_string())?;

    let pk_opt: Option<PublicKey> = PublicKey::from_bytes(pk_arr).into();
    let pk = pk_opt.ok_or_else(|| "invalid public key bytes".to_string())?;
    let proof_opt: Option<Proof> = Proof::from_bytes(proof_arr).into();
    let proof = proof_opt.ok_or_else(|| "invalid proof bytes".to_string())?;

    let hash_ctopt = pk.verify(msg, &proof);
    let hash_opt: Option<[u8; 64]> = hash_ctopt.into();
    let hash = hash_opt.ok_or_else(|| "VRF verification failed".to_string())?;

    Ok(hash.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vrf_r255::SecretKey;

    #[test]
    fn roundtrip_verify() {
        let sk_bytes: [u8; 32] = [1u8; 32];
        let sk_opt: Option<SecretKey> = SecretKey::from_bytes(sk_bytes).into();
        if sk_opt.is_none() {
            return;
        }
        let sk = sk_opt.unwrap();
        let pk = vrf_r255::PublicKey::from(sk);
        let msg = b"test-message";
        let proof = sk.prove(msg);
        let proof_bytes = proof.to_bytes().to_vec();
        let pk_bytes = pk.to_bytes().to_vec();

        let out = verify_proof_bytes(&pk_bytes, &proof_bytes, msg).expect("should verify");
        assert_eq!(out.len(), 64);
    }
}
