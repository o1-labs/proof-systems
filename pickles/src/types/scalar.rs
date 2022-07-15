use circuit_construction::{Constants, Cs};

use crate::context::{FromPublic, Public, ToPublic};
use crate::types::DecomposedVar;
use crate::util::field_is_bigger;

use ark_ec::AffineCurve;
use ark_ff::{BigInteger, FftField, FpParameters, PrimeField};

use super::VarPoint;

/// An (elliptic curve) scalar of a given size.
/// It allows passing a full variable (with no size bound) from one side to the other,
/// however it does not enable efficient field operations.
///
/// It only implements FromPublic, i.e. it can only be "received" by not "sent" accros itself.
///
/// Every scalar will correspond to a unique generator (for the Pedersen commitment)
///
/// Note that there are no efficient way to do arithmetic on the Scalar type:
/// it corresponds to a field element in the foreign field Fr represented in Fq.
/// However efficient elliptic curve scalar multiplication.
///
/// Note: the scalar is represented over the base field of the elliptic curve, this is not a mistake!
/// This enables us to enforce scalar operations on the elliptic curve using the basefield proof system.
pub struct Scalar<G>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
    bits: DecomposedVar<G::BaseField>,
}

impl<G> VarPoint<G>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
    pub fn scale<C: Cs<G::BaseField>>(&self, cs: &mut C, scalar: &Scalar<G>) -> VarPoint<G> {
        unimplemented!()
    }

    // fixed based MSM inside the circuit
    pub fn fix_msm() -> Self {
        unimplemented!()
    }

    // variable base MSM inside the circuit, panics if the MSM is empty
    pub fn var_msm<'a, C, P, I>(cs: &mut C, mut exps: I) -> Self
    where
        C: Cs<G::BaseField>,
        P: AsRef<Self> + 'a,
        I: Iterator<Item = (&'a Scalar<G>, &'a P)>,
    {
        let (s0, g0) = exps.next().expect("empty MSM");
        let mut res = g0.as_ref().scale(cs, s0);
        for (si, gi) in exps {
            let tmp = gi.as_ref().scale(cs, si);
            res = res.add(cs, &tmp);
        }
        res
    }
}

// Can convert public inputs from the scalar field into a scalar on the basefield side
impl<G> FromPublic<G::ScalarField, G::BaseField> for Scalar<G>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
    type Error = ();

    /// A scalar is always constructed from a single (possibly bounded) element of the scalar field
    fn from_public<C: Cs<G::BaseField>, I: Iterator<Item = Public<G::BaseField>>>(
        cs: &mut C,
        cnst: &Constants<G::BaseField>,
        inputs: &mut I,
    ) -> Result<Self, Self::Error> {
        <DecomposedVar<G::BaseField> as FromPublic<G::ScalarField, G::BaseField>>::from_public(
            cs, cnst, inputs,
        )
        .map(|bits| Self { bits })
    }
}
