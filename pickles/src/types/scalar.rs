use circuit_construction::{Cs, Var};

use crate::context::{FromPublic, Public, ToPublic};

use ark_ec::AffineCurve;
use ark_ff::{BigInteger, FftField, FpParameters, PrimeField};

use super::VarPoint;

// An (elliptic curve) scalar of a given size.
// It allows passing a full variable (with no size bound) from one side to the other,
// however it does not enable efficient field operations.
//
// It only implements FromPublic, i.e. it can only be "received" by not "sent" accros itself.
//
// Every scalar will correspond to a unique generator (for the Pedersen commitment)
//
// Note that there are no efficient way to do arithmetic on the Scalar type:
// it corresponds to a field element in the foreign field Fr represented in Fq.
// However efficient elliptic curve scalar multiplication.
//
// Note: the scalar is represented over the base field of the elliptic curve,
// this is not a mistake!
pub struct Scalar<G>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
    high_bits: Var<G::BaseField>,       // "high bits" of scalar
    low_bit: Option<Var<G::BaseField>>, // single "low bit" of scalar
}

impl<G> Scalar<G>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
    fn need_low_bit() -> bool {
        let m_fp = <<G::BaseField as PrimeField>::Params as FpParameters>::MODULUS.into();
        let m_fr = <<G::ScalarField as PrimeField>::Params as FpParameters>::MODULUS.into();
        m_fp > m_fr
    }
}

impl<G> VarPoint<G>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
    fn scale<C: Cs<G::BaseField>>(&self, cs: &mut C, scalar: &Scalar<G>) -> VarPoint<G> {
        unimplemented!()
    }

    // do a MSM inside the circuit, panics if the MSM is empty
    pub fn msm<'a, C, P, I>(cs: &mut C, mut exps: I) -> Self
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
        inputs: &mut I,
    ) -> Result<Self, Self::Error> {
        // read high bits from public input
        let high_bits = inputs.next().expect("Missing high bits").bits;

        // read low bits from public input
        let low_bit = if Self::need_low_bit() {
            let low_bit = inputs.next().expect("Missing low bit");
            assert_eq!(low_bit.size, 1);
            Some(low_bit.bits)
        } else {
            None
        };

        Ok(Self { high_bits, low_bit })
    }
}
