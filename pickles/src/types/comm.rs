use ark_ec::AffineCurve;
use ark_ff::{FftField, PrimeField};

use circuit_construction::Cs;

use crate::transcript::{Absorb, VarSponge};
use crate::types::group::VarPoint;

/// A commitment to a polynomial
/// with a given number of chunks
pub struct VarPolyComm<A, const N: usize>
where
    A: AffineCurve,
    A::BaseField: FftField + PrimeField,
{
    chunks: [VarPoint<A>; N],
}

impl<A, const N: usize> Absorb<A::BaseField> for VarPolyComm<A, N>
where
    A: AffineCurve,
    A::BaseField: FftField + PrimeField,
{
    fn absorb<C: Cs<A::BaseField>>(&self, cs: &mut C, sponge: &mut VarSponge<A::BaseField>) {
        sponge.absorb(cs, &self.chunks);
    }
}
