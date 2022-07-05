use circuit_construction::{Var, Cs};

use crate::context::{FromPublic, Public};

use crate::transcript::{Challenge, VarSponge};

use ark_ff::{BigInteger, FftField, FpParameters, PrimeField};


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
pub struct Scalar<F: FftField + PrimeField> {
    size: usize, // total number of bits in scalar
    high_bits: Var<F>, // "high bits" of scalar
    low_bit: Option<Var<F>> // single "low bit" of scalar
}

impl<Fq: FftField + PrimeField, Fr: FftField + PrimeField> FromPublic<Fq, Fr> for Scalar<Fr> {
    type Error = ();

    /// A scalar is always constructed from a single (possibly bounded) element of Fq
    fn from_public<C: Cs<Fr>, I: Iterator<Item = Public<Fq>>>(
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
        let (low_bit, size): (Option<Var<Fr>>, usize) = match elem.size {
            Some(size) => {
                // sanity check: ensure that it fits in a single field element
                assert!(size < Fq::Params::MODULUS.num_bits() as usize);
                (None, size)
            },
            None => {
                let size: usize = Fr::Params::MODULUS.num_bits() as usize;
                let mod_to = <Fr::Params as FpParameters>::MODULUS.into();
                let mod_from = <Fq::Params as FpParameters>::MODULUS.into();
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

        Ok(
            Self {
                size, 
                high_bits,
                low_bit
            }
        )
    }
}