use ark_ff::{FftField, PrimeField};

use super::plonk::Plonk;


/// State to pass-through to "Wrap" proof:
struct PassThrough {

}

struct Proof<F: PrimeField + FftField> {
    pass: PassThrough,
    accum: Accumulator<F>, // accumulator for the polynomial commitment scheme
    plonk: Plonk<F>,       // plonk proof
}

/// 
/// 
/// TODO: Implements serde::Serialize / serde::Deserialize
struct Minimal {

}

/*
impl Into<Proof> for Minimal {
  
}

impl Into<Minimal> for Proof {

}
*/