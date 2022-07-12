use ark_ec::AffineCurve;
use ark_ff::{FftField, PrimeField};

use std::marker::PhantomData;

use circuit_construction::{Cs, Var};

use crate::transcript::{Absorb, VarSponge};
use crate::types::{GLVChallenge, Scalar};

#[derive(Clone, Debug)]
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

impl<G> VarPoint<G>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
    pub fn glv_scale<C: Cs<G::BaseField>>(
        &self,
        cs: &mut C,
        s: &GLVChallenge<G::BaseField>,
    ) -> Self {
        unimplemented!()
    }

    pub fn add_constant<C: Cs<G::BaseField>>(&self, cs: &mut C, other: G) -> Self {
        unimplemented!()
    }

    pub fn inv<C: Cs<G::BaseField>>(&self, cs: &mut C) -> Self {
        unimplemented!()
    }

    pub fn add<C: Cs<G::BaseField>>(&self, cs: &mut C, other: &Self) -> Self {
        unimplemented!()
    }

    pub fn sub<C: Cs<G::BaseField>>(&self, cs: &mut C, other: &Self) -> Self {
        unimplemented!()
    }

    /// Let "chal" be a GLV decomposed scalar (see GLVChallenge)
    /// and let "elems" be a list of points.
    ///
    /// Computes the element
    ///
    /// \sum_{i = 0} [chal^i] elems_i
    ///
    pub fn combine_with_scalar_power<'a, I, C>(cs: &mut C, mut elems: I, chal: &Scalar<G>) -> Self
    where
        I: Iterator<Item = &'a Self>,
        C: Cs<G::BaseField>,
    {
        let mut result: VarPoint<G> = elems
            .next()
            .expect("Empty combination of points with GLV-decomposed powers")
            .clone();

        for elem in elems {
            result = result.scale(cs, chal);
            result = result.add(cs, elem);
        }

        result
    }

    /// Let "chal" be a GLV decomposed scalar (see GLVChallenge)
    /// and let "elems" be a list of points.
    ///
    /// Computes the element
    ///
    /// \sum_{i = 0} [chal^i] elems_i
    ///
    pub fn combine_with_glv_power<'a, I, C>(
        cs: &mut C,
        mut elems: I,
        chal: &GLVChallenge<G::BaseField>,
    ) -> Self
    where
        I: Iterator<Item = &'a Self>,
        C: Cs<G::BaseField>,
    {
        let mut result: VarPoint<G> = elems
            .next()
            .expect("Empty combination of points with GLV-decomposed powers")
            .clone();

        for elem in elems {
            result = result.glv_scale(cs, chal);
            result = result.add(cs, elem);
        }

        result
    }
}
