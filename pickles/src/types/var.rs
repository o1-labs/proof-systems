use circuit_construction::{generic, Constants, Cs, Var};

use crate::context::{Pass, Public, ToPublic};
use crate::types::Scalar;
use crate::util::{field_is_bigger, from_bits};

use ark_ec::AffineCurve;
use ark_ff::{BigInteger, FftField, PrimeField};

// a variable over the scalar field can be passed/converted to a scalar in the base field
impl<G> Pass<Scalar<G>> for Var<G::ScalarField>
where
    G: AffineCurve,
    G::BaseField: FftField + PrimeField,
{
}

// A variable is turned into public inputs b
impl<Fp, Fr> ToPublic<Fp, Fr> for Var<Fp>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
{
    fn to_public<C: Cs<Fp>>(self, cs: &mut C, _cnst: &Constants<Fp>) -> Vec<Public<Fp>> {
        // the two fields must have the same bit-size: they differ by ~ \sqrt{Fp} factor.
        assert_eq!(Fp::size_in_bits(), Fr::size_in_bits());

        //
        if field_is_bigger::<Fp, Fr>() {
            // decompose witness (if available)
            let bits = self.value.map(|v| v.into_repr().to_bits_le());

            // introduce high_bits / low_bit
            let high_bits = cs.var(|| from_bits(&bits.as_ref().unwrap()[1..]));
            let low_bit = cs.var(|| from_bits(&bits.as_ref().unwrap()[..1]));

            // enforce decomposition
            // (range enforced on all public inputs, no need to check inside circuit)
            let two = Fp::from(2u32);
            let value = self.clone();
            generic!(cs, (high_bits, low_bit, value) : { high_bits * two + low_bit = value });

            // return two public inputs
            vec![
                Public {
                    size: Fp::size_in_bits() - 1,
                    bits: high_bits,
                },
                Public {
                    size: 1,
                    bits: low_bit,
                },
            ]
        } else {
            vec![Public {
                size: Fp::size_in_bits(),
                bits: self.clone(),
            }]
        }
    }
}
