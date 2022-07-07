use super::context::InnerContext;

use crate::util::from_bits;

use circuit_construction::{Cs, Var};

use ark_ff::{BigInteger, FftField, PrimeField};

use std::fmt::Debug;

/// Represents a public input added
///
/// NOTE: because this represents a public input from the "source side"
/// it always fits within one variable: there can be no overflow,
/// however on the "destination side" it can overflow
///
/// NOTE: a "public input"
#[derive(Clone, Debug)]
pub struct Public<F: FftField + PrimeField> {
    pub bits: Var<F>,        //
    pub size: Option<usize>, // size of public input
}

impl<Fp: FftField + PrimeField> Public<Fp> {
    /// This panics if the destination field is too small to contain the value:
    /// In case we are passing from the larger field to the smaller a
    /// decomposition in the source field is required.
    fn cast<Cr, Fr>(&self, cs: &mut Cr) -> Public<Fr>
    where
        Fr: FftField + PrimeField,
        Cr: Cs<Fr>,
    {
        // converts a slice of bits (minimal representative) to a field element
        
        Public {
            bits: cs.var(|| from_bits(&self.bits.val().into_repr().to_bits_le())),
            size: self.size,
        }
    }
}

pub trait FromPublic<Fp, Fr>: Sized
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
{
    type Error: Debug;

    /// Constructs a type from public inputs
    fn from_public<C, I>(cs: &mut C, inputs: &mut I) -> Result<Self, Self::Error>
    where
        I: Iterator<Item = Public<Fr>>,
        C: Cs<Fr>;
}

pub trait ToPublic<Fp, Fr>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
{
    /// Transforms a type to public inputs
    fn to_public<Cp: Cs<Fp>>(&self, cs: &mut Cp) -> Vec<Public<Fp>>;
}

// a marker trait which means we get compile time errors if we try to do a meaningless pass
pub trait Pass<To> {}

impl<Fp, Fr, CsFp, CsFr> InnerContext<Fp, Fr, CsFp, CsFr>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
    CsFp: Cs<Fp>,
    CsFr: Cs<Fr>,
{
    /// TODO: this method should also be able to ignore
    /// the "from" and consume provided the variable assignments in the public inputs directly.
    ///
    /// This way we can check the defered computation without implementing the logic twice.
    pub fn pass<From, To>(&mut self, from: From) -> To
    where
        From: ToPublic<Fp, Fr> + Pass<To>,
        To: FromPublic<Fp, Fr>,
    {
        // convert source type to public
        let fp_public = from.to_public(self.cs());

        // cast public inputs to different field
        for fp in fp_public.iter().cloned() {
            // cast Fp element to Fr element
            let fr = fp.cast(&mut self.fr.cs);

            // add to "public input" on both sides
            // (in finalize we whill choose which)
            self.fp.public.send.push(fp);
            self.fr.public.recv.push(fr);
        }

        // convert Fr public inputs into destination type
        To::from_public(
            &mut self.fr.cs,
            &mut self.fr.public.recv[self.fr.public.recv.len() - fp_public.len()..]
                .iter()
                .cloned(),
        )
        .unwrap()
    }

    /*
    ///
    /// TODO: this method should also be able to ignore
    /// the "from" and consume provided public inputs directly.
    pub fn pass<In, Out>(&mut self, from: In) -> Out
    where
        In: ToPublic<Fp>, // the input can be converted to public inputs on Fq
        Out: FromPublic<Fp, Fr> + ToPublic<Fr>, // the (Fr) output can be created from Fq public inputs turned into Fr public inputs
    {
        // create destination type from Fr public inputs
        let output = Out::from_public(&mut self.fr.cs, &mut from.to_public().into_iter()).unwrap();

        // add to (send) public inputs on fp side
        self.fp.public.send.extend(from.to_public());

        // add to (recv) public inputs on the fr side
        self.fr.public.recv.extend(output.to_public());

        output
    }
    */
}
