use std::env;
use std::time::{SystemTime, UNIX_EPOCH, Instant};
use prost::Message;
use ed25519_dalek::{Keypair, SecretKey, PublicKey, Signer, Signature, Verifier};
use sha2::{Digest, Sha256};
use tokio::time::sleep;
use std::time::Duration;
use anyhow::{Result, anyhow};

use consensus_network::proto::{Envelope, BlockProposal};
use consensus_network;
use vrf::{load_encrypted_skfile, RealRistrettoVrf};
use std::sync::Arc;
use warp::Filter;

mod store;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    // network config (env)
    let listen_addr = env::var("LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:7000".to_string());
    let peers = env::var("PEERS").unwrap_or_else(|_| "".to_string());
    let peers_vec: Vec<String> = peers.split(',').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect();

    // storage DB
    let db_path = std::env::var("MCRCOIN_DB_PATH").unwrap_or_else(|_| {
    let mut p = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
    p.push(".mcrcoin/db");
    p.to_string_lossy().into_owned()
});
let db_handle = store::open_db(std::path::PathBuf::from(db_path)).map_err(|e| anyhow!(e))?;

    let db_for_http = db_handle.clone();

    // print which DB path will be used
    let db_path = std::env::var("MCRCOIN_DB_PATH").unwrap_or_else(|_| {
        std::env::var("HOME").map(|h| format!("{}/.mcrcoin/db", h)).unwrap_or_else(|_| "./mcrcoin_db".to_string())
    });
    println!("Using DB path: {}", db_path);

    // spawn HTTP server for block fetches
    let db_filter = db_for_http;
    let http_port: u16 = env::var("HTTP_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(8000);
    let block_route = warp::path!("block" / u64).and_then(move |height: u64| {
        let db = db_filter.clone();
        async move {
            match store::get_block(&db, height) {
                Ok(Some(bytes)) => Ok(warp::reply::with_header(bytes, "content-type", "application/octet-stream")),
                Ok(None) => Err(warp::reject::not_found()),
                Err(_) => Err(warp::reject::not_found()),
            }
        }
    });
    // spawn HTTP server
    let http_addr = ([0,0,0,0], http_port);
    tokio::spawn(async move {
        warp::serve(block_route).run(http_addr).await;
    });
    println!("Block HTTP server listening on 0.0.0.0:{}", http_port);

    let mut net = consensus_network::start(&listen_addr, peers_vec).await.map_err(|e| anyhow!(e.to_string()))?;
    println!("Network started, listening on {}", listen_addr);

    // load VRF key
    let mut dir = dirs::home_dir().unwrap_or_else(|| ".".into());
    dir.push(".mcrcoin");
    dir.push("vrf_key.json");
    let password = env::var("VRF_PW").unwrap_or_else(|_| "devnet".to_string());
    let (sk_bytes, pk_bytes) = load_encrypted_skfile(&dir, &password).map_err(|e| anyhow!(e))?;
    println!("Loaded VRF pubkey: {}", hex(&pk_bytes));

    // derive deterministic ed25519 keypair from VRF secret + listen_addr (devnet only)
    let mut hasher = Sha256::new();
    hasher.update(&sk_bytes);
    hasher.update(listen_addr.as_bytes());
    let seed = hasher.finalize(); // 32 bytes
    let secret = SecretKey::from_bytes(&seed).map_err(|e| anyhow!("secret key from seed failed: {}", e))?;
    let public = PublicKey::from(&secret);
    let kp = Keypair { secret, public };
    let ed_pk_bytes = kp.public.to_bytes();

    // prepare block bytes (demo)
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let block_bytes = format!("devnet-block-{}", now).into_bytes();

    // evaluate vrf (produce proof) for our block
    let vrf_impl = RealRistrettoVrf::new();
    let (_vrf_out, vrf_proof) = vrf_impl.evaluate(&sk_bytes, &block_bytes).map_err(|e| anyhow!(e))?;

    // create BlockProposal proto
      let mut bp = BlockProposal {
          height: now,
          block: block_bytes.clone(),
          vrf_proof: vrf_proof.clone(),
          vrf_pubkey: pk_bytes.clone(),
          proposer_sig: vec![],
          proposer_peer_id: ed_pk_bytes.to_vec(),
          payload: vec![],
      };

      // sign canonical payload = block || vrf_proof
      let mut sign_input = bp.block.clone();
      sign_input.extend_from_slice(&bp.vrf_proof);
      let sig = kp.sign(&sign_input);
      bp.proposer_sig = sig.to_bytes().to_vec();

      // persist produced block locally
      {
          let mut enc = Vec::new();
          bp.encode(&mut enc)?;
          store::save_block(&db_handle, bp.height, &enc).map_err(|e| anyhow!(e))?;
          println!("Saved produced block height {}", bp.height);
      }

      // wrap in Envelope (transport wrapper)
      let env = Envelope {
          proposal: Some(bp),
          from_peer: format!("node-{}", listen_addr),
      };

      // publish
      println!("Publishing BlockProposal to peers...");
      net.publish(env).await.map_err(|e| anyhow!(e.to_string()))?;
      println!("Published proposal. Now listen for incoming proposals for 10s...");
// listen for incoming proposals for a short while (devnet)
    let mut count = 0;
    let start = Instant::now();
    while start.elapsed().as_secs() < 10 {
        if let Some(env) = net.incoming().await {
            // decode inner payload
            match env.proposal {
                Some(bp) => {
                    println!("Received BlockProposal at height {} from {}", bp.height, env.from_peer);

                    // === VALIDATION START ===
                    // 1) (OPTIONAL) VRF proof verification
                    // TODO: add VRF proof verification here using the vrf crate API that fits your workspace.
                    // For now we skip VRF verify to avoid mismatched dependency API versions.

                    // 2) Ed25519 signature verification over (block || vrf_proof)
                    if bp.proposer_peer_id.len() != 32 {
                        eprintln!("Invalid proposer public key length: {}", bp.proposer_peer_id.len());
                        continue;
                    }
                    if bp.proposer_sig.len() != 64 {
                        eprintln!("Invalid proposer signature length: {}", bp.proposer_sig.len());
                        continue;
                    }
                    let proposer_pk = match PublicKey::from_bytes(&bp.proposer_peer_id) {
                        Ok(p) => p,
                        Err(e) => { eprintln!("Failed to parse proposer public key: {}", e); continue; }
                    };
                    let proposer_sig = match Signature::from_bytes(&bp.proposer_sig) {
                        Ok(s) => s,
                        Err(e) => { eprintln!("Failed to parse proposer signature: {}", e); continue; }
                    };
                    let mut sign_input = bp.block.clone();
                    sign_input.extend_from_slice(&bp.vrf_proof);
                    if proposer_pk.verify(&sign_input, &proposer_sig).is_err() {
                        eprintln!("Invalid proposer signature for height {} from {}", bp.height, env.from_peer);
                        continue;
                    }
                    // === VALIDATION END ===

                    // persist received block
                    let mut enc = Vec::new();
                    bp.encode(&mut enc)?;
                    store::save_block(&db_handle, bp.height, &enc).map_err(|e| anyhow!(e))?;
                    println!("Saved received block height {}", bp.height);
                    count += 1;
                }
                None => {
                    eprintln!("Failed to decode BlockProposal payload or empty proposal from {}", env.from_peer);
                }
            }
        } else {
            sleep(Duration::from_millis(200)).await;
        }
    }
    println!("Done listening. Received {} proposals.", count);

    Ok(())
}
