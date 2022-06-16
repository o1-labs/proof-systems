use ark_ec::AffineCurve;
use ark_ff::{FftField, PrimeField};

use circuit_construction::{Cs, Var};

use std::marker::PhantomData;

use crate::context::Bounded;
use crate::transcript::{Absorb, Challenge, VarSponge};

use crate::plonk::CHALLENGE_LEN;

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

/// The evaluation of a (possibly chunked) polynomial.
/// The least significant chunk is first.
#[derive(Clone)]
pub struct VarOpen<F: FftField + PrimeField, const C: usize> {
    pub(super) chunks: [Var<F>; C],
}

// For exactly one chunk, we can use a polynomial opening as a variable
impl<F> AsRef<Var<F>> for VarOpen<F, 1>
where
    F: FftField + PrimeField,
{
    fn as_ref(&self) -> &Var<F> {
        &self.chunks[0]
    }
}

// In general a polynomial opening is a slice of variables
impl<F: FftField + PrimeField, const C: usize> AsRef<[Var<F>]> for VarOpen<F, C> {
    fn as_ref(&self) -> &[Var<F>] {
        &self.chunks
    }
}

impl<F> Into<VarOpen<F, 1>> for Var<F>
where
    F: FftField + PrimeField,
{
    fn into(self) -> VarOpen<F, 1> {
        VarOpen { chunks: [self] }
    }
}

impl<F: FftField + PrimeField, const N: usize> VarOpen<F, N> {
    /// Combines the evaluation chunks f_0(x), f_1(m), ..., f_m(x) to a single evaluation
    /// f(x) = f_0(x) + x^N f_1(x) + ... + x^{m N} f_m(x)
    ///
    /// pt is zeta^max_degree
    fn combine<C: Cs<F>>(&self, cs: &mut C, pt: Var<F>) -> Var<F> {
        // iterate over coefficients:
        // most-to-least significant
        let mut chk = self.chunks[..].iter().rev().cloned();

        // the initial sum is the most significant term
        let mut sum = chk.next().expect("zero chunks in poly.");

        // shift by pt and add next chunk
        for c in chk {
            sum = cs.mul(sum, pt.clone());
            sum = cs.add(sum, c);
        }

        sum
    }
}

impl<F: FftField + PrimeField, const N: usize> Absorb<F> for VarOpen<F, N> {
    fn absorb<C: Cs<F>>(&self, cs: &mut C, sponge: &mut VarSponge<F>) {
        sponge.absorb(cs, &self.chunks);
    }
}

/// A collection of CHALLENGE_LEN bits
/// (represented over the given field)
pub struct ScalarChallenge<F: FftField + PrimeField> {
    challenge: Var<F>,
}

impl<F: FftField + PrimeField> From<Var<F>> for ScalarChallenge<F> {
    fn from(v: Var<F>) -> Self {
        Self { challenge: v }
    }
}

impl<F: FftField + PrimeField> Bounded<F> for ScalarChallenge<F> {
    const SIZE: usize = CHALLENGE_LEN;
}

impl<F: FftField + PrimeField> From<(Var<F>, Option<Var<F>>)> for ScalarChallenge<F> {
    fn from(t: (Var<F>, Option<Var<F>>)) -> Self {
        assert!(t.1.is_none());
        Self { challenge: t.0 }
    }
}

impl<F: FftField + PrimeField> Into<Var<F>> for ScalarChallenge<F> {
    fn into(self) -> Var<F> {
        self.challenge
    }
}

impl<F: FftField + PrimeField> Challenge<F> for ScalarChallenge<F> {
    fn generate<C: Cs<F>>(cs: &mut C, sponge: &mut VarSponge<F>) -> Self {
        // generate challenge using sponge
        let scalar: Var<F> = Var::generate(cs, sponge);

        // create endoscalar (bit decompose)
        let challenge = cs.endo_scalar(CHALLENGE_LEN, || {
            let s: F = scalar.val();
            s.into_repr()
        });

        // enforce equality
        cs.assert_eq(challenge, scalar);

        // bit decompose challenge
        ScalarChallenge { challenge }
    }
}

impl<F: FftField + PrimeField> ScalarChallenge<F> {
    pub fn to_field<C: Cs<F>>(&self, cs: &mut C) -> Var<F> {
        unimplemented!()
    }
}
