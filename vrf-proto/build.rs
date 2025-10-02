use std::path::PathBuf;

fn main() {
    // If you prefer to use a vendored protoc binary, uncomment the next lines and
    // add protoc-bin-vendored to build-dependencies in Cargo.toml.
    //
    // if let Ok(p) = protoc_bin_vendored::protoc_bin_path() {
    //     std::env::set_var("PROTOC", p);
    // }

    // Adjust path if your proto is located elsewhere. This expects repo root /proto/vrf.proto
    let proto = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("manifest dir has no parent")
        .join("proto")
        .join("vrf.proto");

    if !proto.exists() {
        panic!("proto file not found: {}", proto.display());
    }

    println!("cargo:rerun-if-changed={}", proto.display());

    let out_dir = std::env::var("OUT_DIR").unwrap();

    prost_build::Config::new()
        .out_dir(&out_dir)
        // optional: configure type attributes, serde, etc.
        .compile_protos(&[proto], &[format!("{}/proto", std::env::var("CARGO_MANIFEST_DIR").unwrap().replace("\\", "/"))])
        .expect("prost-build failed");
}
