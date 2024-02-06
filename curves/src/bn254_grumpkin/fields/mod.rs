/// Scalar field of BN254/Base field of Grumpkin
pub mod fp;
pub use self::fp::*;

/// Scalar field of Grumpkin/Base field of BN254
pub mod fq;
pub use self::fq::*;

#[cfg(test)]
mod tests;
