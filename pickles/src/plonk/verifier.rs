use crate::transcript::Transcript;
use crate::context::MutualContext;

use super::Plonk;

use circuit_construction::Cs;

use ark_ff::{FftField, PrimeField};
use ark_ec::{AffineCurve};

///
/// Takes a mutual context with the base-field of the Plonk proof as the "native field" 
/// and generates Fp (base field) and Fr (scalar field) 
/// constraints for the verification of the proof.
fn verify<A, CsFp, CsFr, C, T>(
    ctx: &mut MutualContext<A::BaseField, A::ScalarField, CsFp, CsFr>,
    tx: &mut Transcript<A::BaseField, A::ScalarField>,
    witness: Option<Plonk<A>>
)
where
    A: AffineCurve,
    A::BaseField: FftField + PrimeField,
    CsFp: Cs<A::BaseField>,
    CsFr: Cs<A::ScalarField>,
{
    



}