use crate::N_LIMBS;

/// Number of columns in the FEC circuits.
pub const FEC_N_COLUMNS: usize = 34 * N_LIMBS + 42 * N_LIMBS; // 42 LIMBS is for debugging
