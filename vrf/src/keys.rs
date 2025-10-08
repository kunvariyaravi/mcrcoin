use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use rand::RngCore;
use rand::rngs::OsRng;
use scrypt::{scrypt, Params};
use serde::{Serialize, Deserialize};
use base64::{engine::general_purpose, Engine as _};
use zeroize::Zeroize;
use std::fs;
use std::path::Path;
use vrf_r255::{SecretKey, PublicKey};

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12; // AES-GCM 96-bit nonce
const SCRYPT_LOGN: u8 = 15; // N = 2^15, adjust cost for production depending on CPU
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedSkFile {
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
    pub pubkey: String, // base64-encoded public key
    pub kdf_params: KdfParams,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KdfParams {
    pub log_n: u8,
    pub r: u32,
    pub p: u32,
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8;32], String> {
    let params = Params::new(SCRYPT_LOGN, SCRYPT_R, SCRYPT_P).map_err(|e| e.to_string())?;
    let mut out = [0u8; 32];
    scrypt(password.as_bytes(), salt, &params, &mut out).map_err(|e| e.to_string())?;
    Ok(out)
}


/// Generate a new VRF keypair using the crate's generator. Returns (sk_bytes, pk_bytes).
pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), String> {
    // Use the crate's generate API to ensure a valid secret key
    // rand_core::OsRng is used by SecretKey::generate
    let sk = SecretKey::generate(rand_core::OsRng);
    // serialize secret key to bytes
    let sk_bytes = sk.to_bytes();
    let pk = PublicKey::from(sk);
    let pk_bytes = pk.to_bytes();
    Ok((sk_bytes.to_vec(), pk_bytes.to_vec()))
}


/// Save the secret key encrypted to disk using a password.
/// File format is JSON with base64 fields.
pub fn save_encrypted_skfile<P: AsRef<Path>>(path: P, password: &str, sk_bytes: &[u8], pubkey_bytes: &[u8]) -> Result<(), String> {
    if sk_bytes.len() != 32 {
        return Err("secret key must be 32 bytes".into());
    }
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let derived = derive_key(password, &salt)?;
    // make Key type explicit for aes-gcm to avoid inference issues
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&derived);
    let cipher = Aes256Gcm::new(key);

    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let nonce_g = Nonce::from_slice(&nonce);

    let ciphertext = cipher.encrypt(nonce_g, sk_bytes).map_err(|e| e.to_string())?;

    // base64 encode fields
    let file = EncryptedSkFile {
        salt: general_purpose::STANDARD.encode(&salt),
        nonce: general_purpose::STANDARD.encode(&nonce),
        ciphertext: general_purpose::STANDARD.encode(&ciphertext),
        pubkey: general_purpose::STANDARD.encode(pubkey_bytes),
        kdf_params: KdfParams { log_n: SCRYPT_LOGN, r: SCRYPT_R, p: SCRYPT_P },
    };

    let json = serde_json::to_vec_pretty(&file).map_err(|e| e.to_string())?;
    fs::write(path, &json).map_err(|e| e.to_string())?;
    // zeroize derived key
    let mut z = derived;
    z.zeroize();
    Ok(())
}

/// Load and decrypt the secret key file from disk with password.
/// Returns (sk_bytes, pubkey_bytes)
pub fn load_encrypted_skfile<P: AsRef<Path>>(path: P, password: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let data = fs::read(path).map_err(|e| e.to_string())?;
    let file: EncryptedSkFile = serde_json::from_slice(&data).map_err(|e| e.to_string())?;

    let salt = general_purpose::STANDARD.decode(&file.salt).map_err(|e| e.to_string())?;
    let nonce = general_purpose::STANDARD.decode(&file.nonce).map_err(|e| e.to_string())?;
    let ciphertext = general_purpose::STANDARD.decode(&file.ciphertext).map_err(|e| e.to_string())?;
    let pubkey_bytes = general_purpose::STANDARD.decode(&file.pubkey).map_err(|e| e.to_string())?;

    let derived = derive_key(password, &salt)?;
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&derived);
    let cipher = Aes256Gcm::new(key);
    let nonce_g = Nonce::from_slice(&nonce);

    let plaintext = cipher.decrypt(nonce_g, ciphertext.as_ref()).map_err(|_| "decryption failed (wrong password?)".to_string())?;

    // zeroize derived key
    let mut z = derived;
    z.zeroize();

    if plaintext.len() != 32 {
        return Err("decrypted secret key length invalid".into());
    }
    Ok((plaintext, pubkey_bytes))
}
