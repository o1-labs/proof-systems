//! Pasta curves as OpenVM Weierstrass intrinsics.
//!
//! Declared here rather than downstream for a hard reason: `moduli_declare!`
//! generates `from_const_bytes` as a *private* associated function, so
//! `sw_declare!` -- which needs it to build the curve's `b` constant -- only
//! compiles in the same crate as the moduli. OpenVM's own `k256` guest lib has
//! the same shape.
//!
//! Keeping the declarations together also protects the global modulus ordering:
//! declaration order must match `[app_vm_config.modular] supported_moduli`, and
//! spreading declarations across crates makes that ordering hard to reason about.

use core::ops::{Add, Neg};

use openvm_algebra_guest::IntMod;
// The `sw_declare!` expansion references these traits by bare name, so they must
// all be in scope. Mirrors the import set in openvm's own `k256` guest lib.
use openvm_ecc_guest::{weierstrass::WeierstrassPoint, Group};
use openvm_ecc_sw_macros::sw_declare;

use super::fields::{OpenVmFpMod, OpenVmFqMod};

/// Both Pasta curves are `y² = x³ + 5`; `a = 0`, which `sw_declare!` defaults to.
const fn five_le() -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[0] = 5;
    buf
}

const VESTA_B: OpenVmFqMod = OpenVmFqMod::from_const_bytes(five_le());
const PALLAS_B: OpenVmFpMod = OpenVmFpMod::from_const_bytes(five_le());

// `OpenVmVesta`: base field Fq, group order Fp.
// `OpenVmPallas`: base field Fp, group order Fq.
//
// Line comments, not doc comments: `sw_declare!` does not accept `///` inside the
// invocation and silently produces nothing when it sees one.
sw_declare! {
    OpenVmVesta { mod_type = OpenVmFqMod, b = VESTA_B },
    OpenVmPallas { mod_type = OpenVmFpMod, b = PALLAS_B },
}
