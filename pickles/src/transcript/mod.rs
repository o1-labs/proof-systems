use circuit_construction::{Constants, Cs, Var};

use ark_ff::{FftField, PrimeField};

use crate::context::{Context, FromPublic, Pass, Public, ToPublic};
use crate::types::DecomposedVar;

/// Implementation of the underlaying cryptographic sponge
/// used within the compiled public-coin verifier.
mod sponge;

pub use sponge::{Absorb, Challenge, VarSponge};

/// Represents a verifier in a Fiat-Shamir proof.
///
/// WARNING: This type is DELIBERATELY NOT "Clone"
/// This is done to avoid issues where an old version of the transcript
/// (which does not depend on all the provers messages),
/// is accidentally used to squeeze a challenge.
///
/// If you find yourself implementing "Clone" for this type,
/// be sure you know what you are doing! It is probably wrong!
///
/// Note: named after
/// https://en.wikipedia.org/wiki/Arthur%E2%80%93Merlin_protocol
pub struct Arthur<Fp: FftField + PrimeField> {
    sponge: VarSponge<Fp>,
}

/// A "container type" for a message sent by the prover
///
/// Anything can be turned into such a message,
/// however to unwrap the type it must be consumed by the verifier (Arthur).
///
/// In general: Proofs SHOULD ONLY CONTAIN the "Msg" type (or types containing "Msg" types)
/// to ensure that everything the prover send to the verifier is included in the transcript hash.
pub struct Msg<T> {
    value: T,
}

impl<T> From<T> for Msg<T> {
    fn from(value: T) -> Self {
        Self { value }
    }
}

/// A type which can be "received" by the verifier.
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
            sponge: VarSponge::new(cnst.clone()),
        }
    }

    /// Receive a message from the prover
    /// (which provides access to the inner type of the message)
    #[must_use]
    pub fn recv<R, Fr, Cp, Cr>(&mut self, ctx: &mut Context<Fp, Fr, Cp, Cr>, msg: R) -> R::Dst
    where
        R: Receivable<Fp>,
        Fr: FftField + PrimeField,
        Cp: Cs<Fp>,
        Cr: Cs<Fr>,
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
        Cr: Cs<Fr>,
    {
        self.sponge.challenge(ctx.cs())
    }
}

// We can "pass" a transcript from one side to the other
// by squeezing on the source side and absorbing the hash on the destination
impl<Fp, Fr> Pass<Arthur<Fr>> for Arthur<Fp>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
{
}

impl<Fp, Fr> ToPublic<Fp, Fr> for Arthur<Fp>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
{
    fn to_public<C: Cs<Fp>>(mut self, cs: &mut C, cnst: &Constants<Fp>) -> Vec<Public<Fp>> {
        // squeeze sponge
        let hash: Var<Fp> = self.sponge.challenge(cs);

        // include hash in public inputs
        <Var<Fp> as ToPublic<Fp, Fr>>::to_public(hash, cs, cnst)
    }
}

impl<Fp, Fr> FromPublic<Fp, Fr> for Arthur<Fr>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
{
    type Error = ();

    fn from_public<C: Cs<Fr>, I: Iterator<Item = Public<Fr>>>(
        cs: &mut C,
        cnst: &Constants<Fr>,
        inputs: &mut I,
    ) -> Result<Self, Self::Error> {
        // obtain (possibly) decomposed hash from public inputs
        let decomp_hash = <DecomposedVar<Fr> as FromPublic<Fp, Fr>>::from_public(cs, cnst, inputs)?;

        // create new sponge
        let mut sponge = VarSponge::new(cnst.clone());

        // absorb the hash from the other side
        sponge.absorb(cs, &decomp_hash.high);
        if let Some(low) = decomp_hash.low.as_ref() {
            sponge.absorb(cs, low);
        }

        // wrap sponge in transcript
        Ok(Arthur { sponge })
    }
}
