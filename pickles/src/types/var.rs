use circuit_construction::{Cs, Var};

use crate::context::{Pass, Public, ToPublic};
use crate::types::Scalar;

use ark_ec::AffineCurve;
use ark_ff::{FftField, PrimeField};

// a variable over the scalar field can be passed/converted to a scalar in the base field
impl<G> Pass<Scalar<G>> for Var<G::ScalarField>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
}

// A variable is turned into a
impl<Fp, Fr> ToPublic<Fp, Fr> for Var<Fp>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
{
    fn to_public<C: Cs<Fp>>(&self, cs: &mut C) -> Vec<Public<Fp>> {
        // check for bit decomposition
        vec![Public {
            size: None,
            bits: self.clone(),
        }]
    }
}
