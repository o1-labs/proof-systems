#!/usr/bin/env bash
# Builds kimchi-stubs as a static library, links it into a small OCaml driver,
# and runs that driver under a verbose GC.
#
# The archive is passed by full path rather than as `-L$lib_dir -lkimchi_stubs`:
# the crate also builds a cdylib, and the linker would otherwise prefer
# libkimchi_stubs.so, leaving the driver with a runtime DT_NEEDED on a library
# that is not on the loader path.
#
# Requires an OCaml 5.3.0 toolchain on PATH (see the repo's OCaml 5 notes).
# Usage: kimchi-stubs/tests/ocaml_gc/run.sh [--release]
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../../.." && pwd)"

profile_dir=debug
cargo_args=()
if [[ "${1:-}" == "--release" ]]; then
  profile_dir=release
  cargo_args=(--release)
fi

echo "==> ocamlopt $(ocamlopt -version)"
echo "==> building kimchi-stubs staticlib"
cargo build --manifest-path "$root/Cargo.toml" -p kimchi-stubs "${cargo_args[@]}"

lib_dir="$root/target/$profile_dir"
if [[ ! -f "$lib_dir/libkimchi_stubs.a" ]]; then
  echo "libkimchi_stubs.a not found in $lib_dir" >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cp "$here/gc_stress.ml" "$work/"

echo "==> linking OCaml driver"
(
  cd "$work"
  ocamlfind ocamlopt -package unix -linkpkg gc_stress.ml -o gc_stress \
    -cclib "$lib_dir/libkimchi_stubs.a" \
    -cclib -lpthread -cclib -ldl -cclib -lm 2>/dev/null ||
  ocamlopt gc_stress.ml -o gc_stress \
    -cclib "$lib_dir/libkimchi_stubs.a" \
    -cclib -lpthread -cclib -ldl -cclib -lm
)

echo "==> running under OCAMLRUNPARAM=v=0x400"
OCAMLRUNPARAM=v=0x400 "$work/gc_stress"
