use circuit_construction::{Cs, Constants, Var};

use crate::context::{FromPublic, Public};
use crate::util::field_is_bigger;
use crate::transcript::{Absorb, VarSponge};

use ark_ff::{FftField, PrimeField};

pub struct DecomposedVar<F: FftField + PrimeField> {
    pub high: Var<F>,       // "high bits" of scalar
    pub low: Option<Var<F>>, // single "low bit" of scalar
}


// Can convert public inputs from the scalar field into a scalar on the basefield side
impl<Fp, Fr> FromPublic<Fp, Fr> for DecomposedVar<Fr>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField
{
    type Error = ();

    /// A scalar is always constructed from a single (possibly bounded) element of the scalar field
    fn from_public<C: Cs<Fr>, I: Iterator<Item = Public<Fr>>>(
        cs: &mut C,
        _cnst: &Constants<Fr>,
        inputs: &mut I,
    ) -> Result<Self, Self::Error> {
        // read high bits from public input
        let high = inputs.next().expect("Missing high bits").bits;

        // read low bits from public input
        let low = if field_is_bigger::<Fp, Fr>() {
            let low = inputs.next().expect("Missing low bit");
            assert_eq!(low.size, Some(1));
            Some(low.bits)
        } else {
            None
        };

        Ok(Self { high, low })
    }
}

// Can absorb a variable from the same field
impl<F: FftField + PrimeField> Absorb<F> for DecomposedVar<F> {
    fn absorb<C: Cs<F>>(&self, cs: &mut C, sponge: &mut VarSponge<F>) {
        sponge.absorb(cs, &self.high);
        if let Some(low) = self.low.as_ref() {
            sponge.absorb(cs, low);
        }
    }
}