fn main() {
    // Tell cargo to rerun build script if proto changes
    println!("cargo:rerun-if-changed=../proto/vrf.proto");

    let proto_path = std::path::Path::new("../proto/vrf.proto");
    if !proto_path.exists() {
        panic!("proto/vrf.proto not found at {}", proto_path.display());
    }

    prost_build::Config::new()
        .out_dir(std::path::Path::new(&std::env::var("OUT_DIR").unwrap()))
        .compile_protos(&[proto_path], &["../proto"])
        .expect("prost-build failed");
}
