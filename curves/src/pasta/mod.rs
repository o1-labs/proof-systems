pub mod curves;
pub mod fields;

pub use curves::{
    pallas::{Pallas, PallasParameters, ProjectivePallas},
    vesta::{ProjectiveVesta, Vesta, VestaParameters},
};
pub use fields::{Fp, Fq};

/// The OpenVM modular types backing Pasta arithmetic, re-exported so downstream
/// crates can build on them instead of calling `moduli_declare!` again.
///
/// This matters: declaration order is global across the whole binary and must
/// match `[app_vm_config.modular] supported_moduli` in openvm.toml. A second
/// declaration of the same modulus elsewhere would shift the indices and make
/// every modular op compute in the wrong field -- silently, since nothing about
/// it fails to compile.
///
/// `OpenVmFpMod` is Pallas's base / Vesta's scalar field; `OpenVmFqMod` is
/// Vesta's base / Pallas's scalar field.
#[cfg(all(target_os = "zkvm", feature = "openvm"))]
pub use fields::{OpenVmFpMod, OpenVmFqMod};

#[cfg(all(target_os = "zkvm", feature = "openvm"))]
pub mod openvm_curves;
#[cfg(all(target_os = "zkvm", feature = "openvm"))]
pub use openvm_curves::{OpenVmPallas, OpenVmVesta};
