pub const NUM_LIMBS: usize = 16;
pub const DOMAIN_SIZE: usize = 1 << 15;

// M in the paper of MVLookup
pub const NUM_LOOKUP_M: usize = 8;

pub mod column;
pub mod constraint;
pub mod lookup;
pub mod proof;
pub mod prover;
pub mod verifier;
