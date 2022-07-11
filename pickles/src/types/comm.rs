use ark_ec::AffineCurve;
use ark_ff::{FftField, PrimeField};

use circuit_construction::{Cs, Var};

use crate::transcript::{Absorb, VarSponge};
use crate::types::group::VarPoint;
use crate::types::{GLVChallenge, Scalar};

/// A commitment to a polynomial
/// with a given number of chunks, least significant first
#[derive(Clone, Debug)]
pub struct VarPolyComm<G, const N: usize>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
    chunks: [VarPoint<G>; N],
}

impl<G, const N: usize> VarPolyComm<G, N>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
    /// Collapses a chunked opening of a polynomial at $\zeta$ to an unchunked polynomial at $\zeta$:
    /// A chunked evaluation of $f(\zeta)$ with $N$ chunks is represented as:
    /// 
    /// $$
    /// y = f(\zeta) = \sum_{i = 0}^{N} \zeta^{n \cdot i} \cdot \text{chunk}_i
    /// $$
    /// 
    /// This method "collapses" all these chunks to form a commitment to a polynomial $g(X)$ of degree less than $n$ st.
    /// $g(X)$ opens to $y$ at $\zeta$ ($f(\zeta) = y$) iff. the original $f(X)$ did so.
    /// 
    /// For this transformation to be meaninful zeta_n should be a passing of the Shift of $\zeta$.
    /// 
    /// If the polynomial has 1 chunk, this is a no-op.
    pub fn collapse<C: Cs<G::BaseField>>(&self, cs: &mut C, zeta_n: &Scalar<G>) -> VarPolyComm<G, 1> {
        VarPoint::combine_with_scalar_power(cs, self.chunks.iter().rev(),  zeta_n).into()
    }

    /// Shift the polynomial by the vanishing polynomial: enforcing that it evaluates to zero on the domain
    /// This means that the polynomial represents a "quotient" of some polynomial by the domain, i.e. $g(X) / Z_H(X)$
    /// 
    pub fn mul_vanish<C: Cs<G::BaseField>>(&self, cs: &mut C, zeta_n: &Scalar<G>) -> VarPolyComm<G, 1> {
        unimplemented!()
    }

    /// Adds two polynomials (in the ring F[X]})
    pub fn add<C: Cs<G::BaseField>>(&self, cs: &mut C, other: &Self) -> Self {
        unimplemented!()
    }

    /// Subtracts two polynomials (in the ring F[X])
    pub fn sub<C: Cs<G::BaseField>>(&self, cs: &mut C, other: &Self) -> Self {
        unimplemented!()
    }}

impl<G, const N: usize> Absorb<G::BaseField> for VarPolyComm<G, N>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
    fn absorb<C: Cs<G::BaseField>>(&self, cs: &mut C, sponge: &mut VarSponge<G::BaseField>) {
        sponge.absorb(cs, &self.chunks);
    }
}

impl<G, const N: usize> VarPolyComm<G, N>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
}

impl<G> VarPolyComm<G, 1>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
    /// Computes a linear combination of a number of polynomials (using the linearly homomorphic property)
    pub fn linear_combination<'a, I, C>(cs: &mut C, mut elems: I) -> Self
    where
        I: Iterator<Item = (&'a Scalar<G>, &'a Self)>,
        C: Cs<G::BaseField>,
    {
        VarPoint::var_msm(cs, elems).into()
    }
    
    /// Combines a number of polynomial commitments using a random GLV challenge
    pub fn combine_with_glv<'a, I, C>(cs: &mut C, mut elems: I, chal: &GLVChallenge<G::BaseField>) -> Self
    where
        I: Iterator<Item = &'a Self>,
        C: Cs<G::BaseField>,
    {
        VarPoint::combine_with_glv_power(cs, elems.map(|comm| comm.as_ref()), chal).into()
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
