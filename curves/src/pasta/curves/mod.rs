pub mod pallas;
pub mod vesta;

pub use pallas::{Affine as Pallas, PallasConfig as PallasParameters, PallasConfig};
pub use vesta::{Affine as Vesta, VestaConfig as VestaParameters, VestaConfig};

#[cfg(test)]
mod tests;
