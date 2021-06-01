#[cfg(feature = "pasta")]
pub mod fp;
#[cfg(feature = "pasta")]
pub use self::fp::*;

#[cfg(feature = "pasta")]
pub mod fq;
#[cfg(feature = "pasta")]
pub use self::fq::*;

#[cfg(all(feature = "pasta", test))]
#[cfg(test)]
mod tests;
