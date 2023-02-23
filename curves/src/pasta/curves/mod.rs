pub mod pallas;
pub mod vesta;

pub use pallas::{Affine as Pallas, Config as PallasConfig, LegacyConfig as LegacyPallasConfig};
pub use vesta::{Affine as Vesta, Config as VestaConfig, LegacyConfig as LegacyVestaConfig};

#[cfg(test)]
mod tests;
