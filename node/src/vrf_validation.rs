pub fn validate_vrf_proof(pubkey_bytes: &[u8], proof_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, String> {
    vrf::verify_pub(pubkey_bytes, proof_bytes, msg)
}
