fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../proto");
    let proto_file = proto_root.join("consensus.proto");
    let out_dir = std::env::var("OUT_DIR")?;
    let mut config = prost_build::Config::new();
    config.out_dir(&out_dir);
    config.compile_protos(&[proto_file], &[proto_root])?;
    println!("cargo:rerun-if-changed=proto/consensus.proto");
    Ok(())
}
