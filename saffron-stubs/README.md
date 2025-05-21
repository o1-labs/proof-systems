# OCaml stubs for the Saffron codebase

This library will be used to call the Rust code defined in the crate
[saffron](./saffron) in the Caml codebase of Saffron.

The bindings uses ocaml-gen to facilite the bindings of structures like
`ReadProof` and ocaml-rs to generate the C and Caml boilerplate.

The user can run `make release` (resp.`make build` to add debug symbols) from
the top-level of the workspace. A static library `libsaffron_stubs.a` will be
generated with all the symbols the Caml codebase of Saffron can used. The static
file will be available under `target/release/libsaffron_stubs.a` (resp
`target/debug/libsaffron_stubs.a`). The exposed symbols can be inspected using
`nm`. The `nm` tool can be useful to debug errors like `undefined references
[...]`.

Using the build system `dune`, the user can ask to generate the static library using:
```
(rule
 (target libsaffron_stubs.a)
 (action
   (progn
     (run
      cargo
      build
      -p
      saffron-stubs
      --release))))
```
