use anyhow::{anyhow, Result};
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier, KEYPAIR_LENGTH};
use prost::Message;
use std::time::{SystemTime, UNIX_EPOCH};

/// Include prost-generated types. These are created by vrf/build.rs in the vrf crate
/// which wrote to OUT_DIR; for node we recompile the proto or include the same generated file.
/// For simplicity in this example, regenerate via prost-build in node's build.rs or share the same generated file.
/// Here we assume `mcrcoin.vrf` module is available.
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../vrf/target/debug/build/vrf/out/mcrcoin.vrf.rs"));

/// Wrap the generated VrfProof proto to sign it and verify it.
pub fn sign_vrf_proof(keypair: &Keypair,
                      slot: u64,
                      seed: &[u8],
                      vrf_pub: &[u8],
                      proof: &[u8]) -> Result<Vec<u8>> {
    let signer_pub = keypair.public.to_bytes().to_vec();
    let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;

    let mut msg = mcrcoin::vrf::VrfProof {
        slot,
        seed: seed.to_vec(),
        vrf_pub: vrf_pub.to_vec(),
        proof: proof.to_vec(),
        signer_pub,
        sig: Vec::new(),
        timestamp_ms: ts,
    };

    // deterministic prost encode
    let mut buf = Vec::with_capacity(msg.encoded_len());
    msg.encode(&mut buf)?;

    // sign the serialized proto bytes
    let sig: Signature = keypair.sign(&buf);
    msg.sig = sig.to_bytes().to_vec();

    // re-encode with sig field
    let mut out = Vec::with_capacity(msg.encoded_len());
    msg.encode(&mut out)?;

    Ok(out)
}

pub fn verify_vrf_proof(bytes: &[u8]) -> Result<()> {
    let msg = mcrcoin::vrf::VrfProof::decode(bytes)?;
    if msg.signer_pub.len() != 32 {
        return Err(anyhow!("signer pub key wrong len"));
    }
    let pk = PublicKey::from_bytes(&msg.signer_pub).map_err(|e| anyhow!(e))?;
    // Temporarily remove sig bytes for verification: build proto with empty sig to reproduce the signed payload
    let mut msg_nosig = msg.clone();
    let sig_bytes = msg_nosig.sig.clone();
    msg_nosig.sig = Vec::new();
    let mut buf = Vec::with_capacity(msg_nosig.encoded_len());
    msg_nosig.encode(&mut buf)?;

    let signature = Signature::from_bytes(&sig_bytes).map_err(|e| anyhow!(e))?;
    pk.verify(&buf, &signature).map_err(|e| anyhow!(e))?;
    Ok(())
}
