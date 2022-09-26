pub mod fp;
pub use self::fp::{Fp, FpParameters};

pub mod fq;
pub use self::fq::{Fq, FqParameters};

#[cfg(test)]
mod tests;
