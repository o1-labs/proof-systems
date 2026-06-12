fn main() {
    // When this crate is built for a native macOS target (e.g. as a
    // dependency of kimchi-napi), the cdylib can end up referencing
    // OCaml runtime symbols (through feature unification enabling
    // kimchi/ocaml_types, which pulls in ocaml-boxroot-sys). Those
    // symbols only exist in an OCaml process, so they must be left
    // unresolved at link time. The equivalent rustflags in
    // .cargo/config.toml are ignored whenever RUSTFLAGS is set (as in
    // CI), hence this build script.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo::rustc-link-arg-cdylib=-Wl,-undefined,dynamic_lookup");
    }
}
