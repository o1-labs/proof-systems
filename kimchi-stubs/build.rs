fn main() {
    // The cdylib intentionally leaves the caml_* runtime symbols undefined,
    // to be resolved at load time from the host executable (see the [lib]
    // comment in Cargo.toml). macOS's linker rejects undefined symbols by
    // default, so the cdylib link needs `-undefined dynamic_lookup` — the
    // documented ocaml-rs setup. It is emitted here rather than relying on
    // the [target.aarch64-apple-darwin] rustflags in .cargo/config.toml
    // because setting the RUSTFLAGS environment variable (as CI does) makes
    // cargo ignore config-file rustflags entirely.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-arg-cdylib=-undefined");
        println!("cargo:rustc-link-arg-cdylib=dynamic_lookup");
    }
}
