use ark_ec::AffineCurve;
use ark_ff::{FftField, PrimeField};

use std::marker::PhantomData;

use circuit_construction::{Cs, Var};

use crate::transcript::{Absorb, VarSponge};

pub struct VarPoint<G>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
    _ph: PhantomData<G>,
    x: Var<G::BaseField>,
    y: Var<G::BaseField>,
}

impl<A> Absorb<A::BaseField> for VarPoint<A>
where
    A: AffineCurve,
    A::BaseField: FftField + PrimeField,
{
    fn absorb<C: Cs<A::BaseField>>(&self, cs: &mut C, sponge: &mut VarSponge<A::BaseField>) {
        sponge.absorb(cs, &self.x);
        sponge.absorb(cs, &self.y);
    }
}
