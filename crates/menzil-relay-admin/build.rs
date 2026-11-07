//! Compiles `proto/menzil_admin.proto` with the vendored `protoc` (no system install needed).
fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc");
    let mut config = tonic_prost_build::Config::new();
    config.protoc_executable(protoc);
    tonic_prost_build::configure()
        .build_client(std::env::var_os("CARGO_FEATURE_CLIENT").is_some())
        .build_server(true)
        .compile_with_config(
            config,
            &["../../proto/menzil_admin.proto"],
            &["../../proto"],
        )
        .expect("compile the admin proto");
    println!("cargo:rerun-if-changed=../../proto/menzil_admin.proto");
}
