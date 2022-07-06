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
    size: usize,                        // total number of bits in scalar
    high_bits: Var<G::BaseField>,       // "high bits" of scalar
    low_bit: Option<Var<G::BaseField>>, // single "low bit" of scalar
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

impl<G> ToPublic<G::BaseField> for Scalar<G>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
    fn to_public(&self) -> Vec<Public<G::BaseField>> {
        match self.low_bit {
            Some(low_bit) => vec![
                Public {
                    size: Some(1),
                    bits: low_bit,
                },
                Public {
                    size: Some(self.size - 1), // the lowest bit not covered
                    bits: self.high_bits,
                },
            ],
            None => vec![Public {
                size: Some(self.size),
                bits: self.high_bits,
            }],
        }
    }
}

impl<G> FromPublic<G::ScalarField, G::BaseField> for Scalar<G>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
    type Error = ();

    /// A scalar is always constructed from a single (possibly bounded) element of the scalar field
    fn from_public<C: Cs<G::BaseField>, I: Iterator<Item = Public<G::ScalarField>>>(
        cs: &mut C,
        inputs: &mut I,
    ) -> Result<Self, Self::Error> {
        // get an Fq element (of bounded size)
        let elem = inputs.next().expect("Missing public input to decompose");

        // bit decompose Fq element
        let bits = elem.bits.value.map(|v| v.into_repr().to_bits_le());

        // converts a slice of bits (minimal representative) to a field element
        fn from_bits<F: FftField + PrimeField>(bits: &[bool]) -> F {
            F::from_repr(<F as PrimeField>::BigInt::from_bits_le(bits)).unwrap()
        }

        // split if no size bound and destination field is larger
        let (low_bit, size): (Option<Var<G::BaseField>>, usize) = match elem.size {
            Some(size) => {
                // sanity check: ensure that it fits in a single field element
                assert!(size < <G::ScalarField as PrimeField>::Params::MODULUS.num_bits() as usize);
                (None, size)
            }
            None => {
                let size: usize =
                    <G::ScalarField as PrimeField>::Params::MODULUS.num_bits() as usize;
                let mod_to = <<G::BaseField as PrimeField>::Params as FpParameters>::MODULUS.into();
                let mod_from =
                    <<G::ScalarField as PrimeField>::Params as FpParameters>::MODULUS.into();
                if mod_from > mod_to {
                    // the source field is larger: we need to split
                    let low_bit = cs.var(|| from_bits(&bits.as_ref().unwrap()[..1]));
                    (Some(low_bit), size)
                } else {
                    // the source field is smaller (or equal): we can pack it in single variable
                    (None, size + 1)
                }
            }
        };

        // bit decompose Fq element
        let high_bits = cs.var(|| {
            let bits = bits.as_ref().unwrap();
            if low_bit.is_some() {
                from_bits(&bits[1..])
            } else {
                from_bits(&bits)
            }
        });

        Ok(Self {
            size,
            high_bits,
            low_bit,
        })
    }
}
