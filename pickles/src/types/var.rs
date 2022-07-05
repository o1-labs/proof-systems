use circuit_construction::{Var};

use crate::context::{ToPublic, Public};

use ark_ff::{FftField, PrimeField};

impl<Fp: FftField + PrimeField> ToPublic<Fp> for Var<Fp> {
    fn to_public(&self) -> Vec<Public<Fp>> {
        vec![Public {
            size: None,
            bits: self.clone(),
        }]
    }
}