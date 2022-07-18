use ark_ec::AffineCurve;
use ark_ff::{FftField, PrimeField};

use circuit_construction::Cs;

use crate::transcript::{Absorb, VarSponge};
use crate::types::group::VarPoint;
use crate::types::{GLVChallenge, Scalar};

/// A commitment to a polynomial in coefficient form
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
    pub fn eq<C: Cs<G::BaseField>>(&self, cs: &mut C, other: &Self) {
        for i in 0..N {
            self.chunks[i].eq(cs, &other.chunks[i]);
        }
    }

    /// "Collapses" a chunked commitment to a polynomial at the evaluation point $\zeta$ to an unchunked polynomial at $\zeta$.
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
    /// The same ShiftEval should be used to collapse the corresponding chunked openings of this commitment.
    ///
    /// If the polynomial already has 1 chunk, this is a no-op.
    pub fn collapse<C: Cs<G::BaseField>>(
        &self,
        cs: &mut C,
        zeta_n: &Scalar<G>,
    ) -> VarPolyComm<G, 1> {
        VarPoint::combine_with_scalar_power(cs, self.chunks.iter().rev(), zeta_n).into()
    }

    /// Multiplies by the vanishing polynomial Z_H(X), the new polynomial has 1 more chunk than the old.
    ///
    /// Note: this is an efficient operation (no scalar multiplications) since the vanishing polynomial has the form: X^{|H|} - 1.
    /// Hence it corresponds to shifting all the chunks up by one, and subtracting the next chunk from the previous.
    pub fn mul_vanish<C: Cs<G::BaseField>, const N1: usize>(
        &self,
        cs: &mut C,
    ) -> VarPolyComm<G, N1> {
        assert_eq!(N1, N, "multiplying a polynomial by the vanishing polynomial increases the number of chunks by 1");

        // the constant chunk is the inverse of the old constant
        let mut chunks = vec![self.chunks[0].inv(cs)];

        // the remaining chunks are shifted up by 1
        for (i, chunk) in self.chunks.iter().enumerate() {
            // shift up
            chunks.push(chunk.clone());

            // subtract from previous chunk
            if i != 0 {
                chunks[i - 1] = chunks[i - 1].sub(cs, chunk);
            }
        }

        VarPolyComm {
            chunks: chunks.try_into().unwrap(),
        }
    }

    /// Adds two polynomials (in the ring F[X]})
    pub fn add<C: Cs<G::BaseField>>(&self, cs: &mut C, other: &Self) -> Self {
        let mut chunks = Vec::new();
        for i in 0..N {
            chunks.push(self.chunks[i].add(cs, &other.chunks[i]));
        }
        VarPolyComm {
            chunks: chunks.try_into().unwrap(),
        }
    }

    /// Subtracts two polynomials (in the ring F[X])
    pub fn sub<C: Cs<G::BaseField>>(&self, cs: &mut C, other: &Self) -> Self {
        let mut chunks = Vec::new();
        for i in 0..N {
            chunks.push(self.chunks[i].sub(cs, &other.chunks[i]));
        }
        VarPolyComm {
            chunks: chunks.try_into().unwrap(),
        }
    }
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
    pub fn combine_with_glv<'a, I, C>(
        cs: &mut C,
        mut elems: I,
        chal: &GLVChallenge<G::BaseField>,
    ) -> Self
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
