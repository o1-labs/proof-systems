use circuit_construction::{Constants, Cs, Var};

use ark_ff::{BigInteger, FftField, FpParameters, PrimeField};



mod sponge;
mod utils;

use crate::context::{Context, Public, Pass, FromPublic, ToPublic};
use crate::types::DecomposedVar;

pub use sponge::{Absorb, Challenge, VarSponge};


use std::marker::PhantomData;

pub struct Arthur<Fp: FftField + PrimeField> {
    sponge: VarSponge<Fp>,
}

pub struct Msg<T> {
    value: T,
}

impl<T> From<T> for Msg<T> {
    fn from(value: T) -> Self {
        Self { value }
    }
}

pub trait Receivable<F: FftField + PrimeField> {
    type Dst;
    fn unpack<C: Cs<F>>(self, cs: &mut C, sponge: &mut VarSponge<F>) -> Self::Dst;
}

impl<F, H> Receivable<F> for Msg<H>
where
    F: FftField + PrimeField,
    H: Absorb<F>,
{
    type Dst = H;

    fn unpack<C: Cs<F>>(self, cs: &mut C, sponge: &mut VarSponge<F>) -> Self::Dst {
        self.value.absorb(cs, sponge);
        self.value
    }
}

/// Convience: allows receiving a Vec of messages, or vec of vec of messages
/// (you get the point)
impl<F, T> Receivable<F> for Vec<T>
where
    F: FftField + PrimeField,
    T: Receivable<F>,
{
    type Dst = Vec<T::Dst>;

    fn unpack<C: Cs<F>>(self, cs: &mut C, sponge: &mut VarSponge<F>) -> Self::Dst {
        self.into_iter().map(|m| m.unpack(cs, sponge)).collect()
    }
}

impl<Fp: FftField + PrimeField> Arthur<Fp> {
    pub fn new(cnst: &Constants<Fp>) -> Self {
        Self {
            sponge: VarSponge::new(cnst.clone())
        }
    }

    // Side<F: FftField + PrimeField, C: Cs<F>>

    #[must_use]
    pub fn recv<R, Fr, Cp, Cr>(
        &mut self,
        ctx: &mut Context<Fp, Fr, Cp, Cr>,
        msg: R,
    ) -> R::Dst where
        R: Receivable<Fp>,
        Fr: FftField + PrimeField,
        Cp: Cs<Fp>,
        Cr: Cs<Fr>
    {
        msg.unpack(ctx.cs(), &mut self.sponge)
    }

    /// Generate a challenge over the current field
    #[must_use]
    pub fn challenge<C, Fr, Cp, Cr>(&mut self, ctx: &mut Context<Fp, Fr, Cp, Cr>) -> C 
    where
        C: Challenge<Fp>,
        Fr: FftField + PrimeField,
        Cp: Cs<Fp>,
        Cr: Cs<Fr>
    {
        self.sponge.challenge(ctx.cs())
    }
}


// we can send a transcript from one side to the other
// by squeezing on the source side and absorbing the hash on the destination
impl<Fp, Fr> Pass<Arthur<Fr>> for Arthur<Fp> where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
{}


impl<Fp, Fr> ToPublic<Fp, Fr> for Arthur<Fp>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
{
    fn to_public<C: Cs<Fp>>(mut self, cs: &mut C, cnst: &Constants<Fp>) -> Vec<Public<Fp>> {
        // squeeze sponge
        let hash: Var<Fp> = self.sponge.challenge(cs);

        // export variable
        <Var<Fp> as ToPublic<Fp, Fr>>::to_public(hash, cs, cnst)
    }
}

impl<Fp, Fr> FromPublic<Fp, Fr> for Arthur<Fr>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField
{
    type Error = ();

    /// A scalar is always constructed from a single (possibly bounded) element of the scalar field
    fn from_public<C: Cs<Fr>, I: Iterator<Item = Public<Fr>>>(
        cs: &mut C,
        cnst: &Constants<Fr>,
        inputs: &mut I,
    ) -> Result<Self, Self::Error> {
        // obtain decomposed hash
        let decomp_hash = <DecomposedVar<Fr> as FromPublic<Fp, Fr>>::from_public(cs, cnst, inputs)?;

        // create new sponge
        let mut sponge = VarSponge::new(cnst.clone()); 

        // absorb exported hash
        sponge.absorb(cs, &decomp_hash.high);
        if let Some(low) = decomp_hash.low.as_ref() {
            sponge.absorb(cs, low);
        }

        // wrap sponge in transcript
        Ok(
            Arthur{
                sponge
            }
        )
    }
}
