fn main() {
    // This crate's [lib] declares both cdylib and rlib, so the cdylib is
    // built even when the crate is only pulled in as a dependency (e.g. by
    // kimchi-napi in a host build). Under feature unification the host
    // build can pull in OCaml-runtime-referencing deps (ocaml-boxroot-sys),
    // whose caml_* symbols stay undefined until load time. macOS's linker
    // rejects that by default, so pass `-undefined dynamic_lookup` for the
    // cdylib link. Emitted here rather than relying on the target rustflags
    // in .cargo/config.toml because a RUSTFLAGS environment variable (as CI
    // sets) makes cargo ignore config-file rustflags. Wasm targets are
    // unaffected (target_os is not "macos" there).
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-arg-cdylib=-undefined");
        println!("cargo:rustc-link-arg-cdylib=dynamic_lookup");
    }
}
