use super::context::InnerContext;

use circuit_construction::{Cs, Var};

use ark_ff::{BigInteger, FftField, FpParameters, PrimeField};

/// Represents a public input added
/// 
/// NOTE: because this represents a public input from the "source side"
/// it always fits within one variable: there can be no overflow,
/// however on the "destination side" it can overflow
/// 
/// NOTE: a "public input" 
#[derive(Clone, Debug)]
pub struct Public<F: FftField + PrimeField> {
    pub bits: Var<F>, // 
    pub size: Option<usize>,  // size of public input
}

pub trait FromPublic<Fq: FftField + PrimeField, Fr: FftField + PrimeField>: Sized {
    type Error;

    /// Constructs a type from public inputs (possibly from a different field)
    fn from_public<C, I>(cs: &mut C, inputs: &mut I) -> Result<Self, ()>
    where
        I: Iterator<Item = Public<Fq>>,
        C: Cs<Fr>;
}

pub trait ToPublic<F: FftField + PrimeField> {
    /// Transforms a type to public inputs
    fn to_public(&self) -> Vec<Public<F>>;
}

impl<Fp, Fr, CsFp, CsFr> InnerContext<Fp, Fr, CsFp, CsFr>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
    CsFp: Cs<Fp>,
    CsFr: Cs<Fr>,
{
    /// 
    /// TODO: this method should also be able to ignore
    /// the "from" and consume provided public inputs directly.
    pub fn pass<In, Out>(&mut self, from: In) -> Out
    where
        In: ToPublic<Fp>,        // the input can be converted to public inputs on Fq
        Out: FromPublic<Fp, Fr> + ToPublic<Fr>, // the (Fr) output can be created from Fq public inputs turned into Fr public inputs
    {
        // create destination type from Fr public inputs
        let output = Out::from_public(
            &mut self.fr.cs, 
            &mut from.to_public().into_iter()
        ).unwrap();

        // add to (send) public inputs on fp side
        self.fp.public.send.extend(from.to_public());

        // add to (recv) public inputs on the fr side
        self.fr.public.recv.extend(output.to_public());

        output
    }
}

/*
pub trait AsPublic<F: FftField + PrimeField> {
    fn public(&self) -> Vec<Public<F>>;
}

///
///
pub trait PassTo<D, Fp, Fr>: AsPublic<Fp>
where
    D: AsPublic<Fr>,
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
{
    fn convert<CsFp: Cs<Fp>, CsFr: Cs<Fr>>(self, csfp: &mut CsFp, csfr: &mut CsFr) -> D;
}

impl<Fr, Fp> PassTo<PassedField<Fr>, Fp, Fr> for Var<Fp>
where
    Fr: FftField + PrimeField,
    Fp: FftField + PrimeField,
{
    fn convert<CsFp: Cs<Fp>, CsFr: Cs<Fr>>(
        self,
        csfp: &mut CsFp,
        csfr: &mut CsFr,
    ) -> PassedField<Fr> {
        let split = Fr::Params::MODULUS.into() < Fp::Params::MODULUS.into();

        // convert the witness to a vec of bits
        let bits = self.value.map(|v| v.into_repr().to_bits_le());

        // converts a slice of bits (minimal representative) to a field element
        fn from_bits<F: FftField + PrimeField>(bits: &[bool]) -> F {
            F::from_repr(<F as PrimeField>::BigInt::from_bits_le(bits)).unwrap()
        }

        //
        if split {
            // split into high/low(bit)
            let decm = bits.as_ref().map(|b| {
                let h = from_bits(&b[1..b.len()]);
                let l = if b[0] { Fr::one() } else { Fr::zero() };
                (h, l)
            });

            // split and assign
            PassedField {
                high: csfr.var(|| decm.unwrap().0),
                low: Some(csfr.var(|| decm.unwrap().1)),
            }
        } else {
            // fit everything in high
            PassedField {
                high: csfr.var(|| from_bits(&bits.unwrap()[..])),
                low: None,
            }
        }
    }
}

pub struct PassedField<F: FftField + PrimeField> {
    high: Var<F>,
    low: Option<Var<F>>,
}

/*
impl <F: FftField + PrimeField> Absorb<F> for PassedField<F> {
    fn absorb<C: Cs<F>>(&self, cs: &mut C, sponge: &mut VarSponge<F>) {
        sponge.absorb(cs, &self.high);
        self.low.map(|low| sponge.absorb(cs, &self.high));
    }
}
*/

impl<F: FftField + PrimeField> AsPublic<F> for Var<F> {
    fn public(&self) -> Vec<Public<F>> {
        vec![Public {
            var: self.clone(),
            size: F::size_in_bits(),
        }]
    }
}

impl<F: FftField + PrimeField> AsPublic<F> for PassedField<F> {
    fn public(&self) -> Vec<Public<F>> {
        // check high bit
        let mut inputs = vec![Public {
            var: self.high,
            size: F::size_in_bits(),
        }];

        // check if low bit is decomposed
        if let Some(low) = self.low {
            inputs.push(Public { var: low, size: 1 })
        };

        inputs
    }
}
*/