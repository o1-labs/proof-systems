This repository contains various zk-SNARK protocol implementations for recursive SNARK composition.

Build all targets: `$ bazel build //...` (note: three dots)

Note that the Zexe submodule is encoded as a Bazel workspace, so you
cannot build it directly by e.g. `bazel build //zexe/algebra`. Instead
you must use the Zexe workspace name: `baze build @zexe//algebra`.

## Bazel maintenance

If you change any dependencies in the `Cargo.toml` files:

1. update `bzl/cargo/Cargo.toml` to list all deps and versions
2. `cd bzl/cargo`
   a. `cargo generate-lockfile`
   b. `cargo raze`

You may also have to change the `deps` attribute of build targets in
BUILD.bazel. For example, if you add a dependency on the `ocaml`
package to Cargo.toml, you would add `//bzl/cargo:ocaml` to the deps
attribute.

If you change features, you need to edit the `crate_features`
attribute of the BUILD.bazel file accordingly.

