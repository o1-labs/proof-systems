use ark_ec::AffineCurve;
use ark_ff::{FftField, PrimeField};

use circuit_construction::Cs;

use crate::transcript::{Absorb, VarSponge};
use crate::types::group::VarPoint;

/// A commitment to a polynomial
/// with a given number of chunks
pub struct VarPolyComm<G, const N: usize>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
    chunks: [VarPoint<G>; N],
}

impl<G, const N: usize> Absorb<G::BaseField> for VarPolyComm<G, N>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
    fn absorb<C: Cs<G::BaseField>>(&self, cs: &mut C, sponge: &mut VarSponge<G::BaseField>) {
        sponge.absorb(cs, &self.chunks);
    }
}

impl<G> Into<VarPolyComm<G, 1>> for VarPoint<G>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
    fn into(self) -> VarPolyComm<G, 1> {
        VarPolyComm { chunks: [self] }
    }
}

impl<G> AsRef<VarPoint<G>> for VarPolyComm<G, 1>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
    fn as_ref(&self) -> &VarPoint<G> {
        &self.chunks[0]
    }
}
