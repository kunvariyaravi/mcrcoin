use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use anyhow::Result;
use base64;
use hex;
use rand::RngCore;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "dump-vrf-sk")]
struct Opt {
    /// Output path for SK (raw 32 bytes)
    #[structopt(parse(from_os_str))]
    out: PathBuf,

    /// Use deterministic seed (hex). If not provided, uses OS rng.
    #[structopt(long)]
    seed: Option<String>,

    /// Print base64 on stdout (also writes file)
    #[structopt(long)]
    base64: bool,
}

fn main() -> Result<()> {
    let opt = Opt::from_args();

    let sk: [u8; 32] = if let Some(hexstr) = opt.seed {
        let s = hex::decode(&hexstr).expect("failed to decode hex seed");
        assert!(s.len() >= 32, "seed must be at least 32 bytes hex");
        let mut out = [0u8; 32];
        out.copy_from_slice(&s[..32]);
        out
    } else {
        // use a mutable RNG instance and RngCore::fill_bytes
        let mut b = [0u8; 32];
        let mut rng = rand::rngs::OsRng;
        rng.fill_bytes(&mut b);
        b
    };

    let mut f = File::create(&opt.out)?;
    f.write_all(&sk)?;
    f.sync_all()?;

    if opt.base64 {
        // small deprecation warning may remain with base64::encode; harmless
        println!("{}", base64::encode(&sk));
    } else {
        println!("Wrote VRF SK 32 bytes to {}", opt.out.display());
    }

    Ok(())
}
