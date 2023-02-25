pub mod pallas;
pub mod vesta;

pub use pallas::{
    Affine as Pallas, Config as PallasConfig, LegacyConfig as LegacyPallasConfig,
    Projective as ProjectivePallas,
};
pub use vesta::{
    Affine as Vesta, Config as VestaConfig, LegacyConfig as LegacyVestaConfig,
    Projective as ProjectiveVesta,
};

#[cfg(test)]
mod tests;
