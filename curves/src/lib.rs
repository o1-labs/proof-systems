#![no_std]
#![deny(unsafe_code)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![deny(clippy::nursery)]
// Cryptographic constants use unseparated hex literals for consistency with
// reference implementations
#![allow(clippy::unreadable_literal)]

// `moduli_declare!` (the `openvm` feature) expands to code that allocates.
extern crate alloc;

// A RISC-V guest build with `openvm` on must actually reach the chips. Every
// acceleration gate in this crate keys on `target_os`, and OpenVM renamed it
// between releases: `zkvm` for 2.0 (riscv32im-risc0-zkvm-elf), `openvm` for 2.1
// (riscv64im-unknown-openvm-elf). When that rename landed, all the gated code
// silently vanished from the binary -- the build succeeded, the guest ran, and
// the output digest was still correct, just ~10x slower. Nothing failed, so
// nothing surfaced it; only a cycle measurement did.
//
// Fail the build instead. A host build keeps the arkworks reference path and is
// unaffected: this only fires for a RISC-V target, which is by definition a
// guest and therefore has no reason to run the software fallback.
#[cfg(all(
    feature = "openvm",
    any(target_arch = "riscv32", target_arch = "riscv64"),
    not(any(target_os = "zkvm", target_os = "openvm"))
))]
compile_error!(
    "feature `openvm` is enabled for a RISC-V target whose `target_os` is neither \
     `zkvm` nor `openvm`. The acceleration gates key on `target_os` and would \
     compile out silently, falling back to the software path. Widen the `cfg` \
     gates and the `[target.'cfg(...)'.dependencies]` sections to cover the new \
     target_os."
);

pub mod named;
pub mod pasta;
