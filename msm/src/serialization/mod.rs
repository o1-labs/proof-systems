/// The number of intermediate limbs of 4 bits required for the circuit
pub const N_INTERMEDIATE_LIMBS: usize = 20;

pub mod constraints;
pub mod interpreter;
pub mod witness;
