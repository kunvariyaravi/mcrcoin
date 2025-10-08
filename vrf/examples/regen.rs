use vrf::{generate_keypair, save_encrypted_skfile};
use std::path::PathBuf;
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (sk, pk) = generate_keypair()?;
    // determine home dir from env (fallback to current dir)
    let home = env::var("HOME").unwrap_or_else(|_| ".".into());
    let mut dir = PathBuf::from(home);
    dir.push(".mcrcoin");
    std::fs::create_dir_all(&dir)?;
    let mut path = dir.clone();
    path.push("vrf_key.json");

    let password = std::env::var("VRF_PW").unwrap_or_else(|_| "devnet".into());
    save_encrypted_skfile(&path, &password, &sk, &pk)?;
    println!("✅ New VRF key generated and saved at {}", path.display());
    Ok(())
}
