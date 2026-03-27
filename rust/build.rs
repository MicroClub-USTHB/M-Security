fn main() {
    println!("cargo:rerun-if-changed=ffi-exports.map");
    println!("cargo:rerun-if-changed=build.rs");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set");

    // ELF targets (Android, Linux): use a version script to restrict the
    // cdylib's dynamic symbol table to FRB FFI symbols only.
    // This hides #[no_mangle] symbols leaked by dependencies (e.g. blake3).
    // NOTE: macOS ld is not supported — rustc generates its own -exported_symbols_list
    // for cdylib targets, and additional flags can only add to it, not restrict it.
    // macOS .dylib is dev-only; production .so builds are covered.
    if matches!(target_os.as_str(), "android" | "linux") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,--version-script={manifest_dir}/ffi-exports.map");
    }
}
