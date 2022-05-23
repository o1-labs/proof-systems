use circuit_construction::{Constants, Cs, Var};

use ark_ff::{BigInteger, FftField, FpParameters, PrimeField};

mod sponge;
mod utils;

use super::Context;

pub use sponge::{VarSponge, Absorb};

use std::ops::{Deref, DerefMut};
use std::mem;

use std::marker::PhantomData;

use utils::{decompose, lift, need_decompose, transfer_hash};

/// Defered hash transcript
///
///
/// # Dealing with Fr elements
///
/// A fresh sponge is initialized on the complement side:
///
/// The intermediate digest value is then
/// provided as part of the statement on the current side:
///  
/// Schematically it looks something like this:
///
/// ```
/// On current side:
///
///   transcript, h1, h2, transcript_new (statement)
///       |       |   |        |
/// m1 -> H       |   |        |
///       |       |   |        |
///       H <-----/   |        |
///       |           |        |
/// c1 <- H (squeeze) |        |
///       |           |        |
/// m2 -> H           |        |
///       |           |        |
///       H <---------/        |
///       |                    |
///       \---------------------
///
/// On complement side:
///
///                        h1
///                         ^
///     a, b, c -> H        |
///                |        |
///     a * b = c  |        |
///                \--------/
///     
///
///
/// ```
///
///
/// Include the final hash state in the statement of the

struct Public<F: FftField + PrimeField> {
    var: Var<F>,
    size: usize,
}

// A "container type"
struct Side<F: FftField + PrimeField> {
    sponge: VarSponge<F>, // sponge constrained inside the proof system
    merged: bool,        // has the current state been merged with the other side?
}

impl<F: FftField + PrimeField> Side<F> {
    fn new(constants: Constants<F>) -> Self {
        Self {
            sponge: VarSponge::new(constants.clone()),
            merged: true, // sponges start "syncronized": 
                          // the empty Fr transcript has been absorbed into the Fp sponge by definition
        }
    }
}

struct Inner<Fp, Fr, CsFp, CsFr>  
    where
        Fp: FftField + PrimeField,
        Fr: FftField + PrimeField 
{
        fp: Side<Fp>,
        fr: Side<Fr>,
        _ph: PhantomData<(CsFp, CsFr)>,
}

pub struct Merlin<Fp, Fr, CsFp, CsFr> 
    where
        Fp: FftField + PrimeField,
        Fr: FftField + PrimeField,
{
    inner: Option<Inner<Fp, Fr, CsFp, CsFr>>
}

/// Describes a type which can be "squeezed" (generated) from the sponge
pub trait Challenge<F: FftField + PrimeField> {
    fn generate<C: Cs<F>>(cs: &mut C, sponge: &mut VarSponge<F>) -> Self;   
}

// Can generate a variable from the same field
impl <F: FftField + PrimeField> Challenge<F> for Var<F> {
    fn generate<C: Cs<F>>(cs: &mut C, sponge: &mut VarSponge<F>) -> Self {
        sponge.squeeze(cs)
    }
}

pub struct Msg<T> {
    value: T,
}

impl <T> From<T> for Msg<T> {
    fn from(value: T) -> Self {
        Self{ value }
    }
}

/*
impl <Fp, Fr, CsFp, CsFr> AsMut<CsFp> for Merlin<Fp, Fr, CsFp, CsFr> 
    where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
    CsFp: Cs<Fp>, 
    CsFr: Cs<Fr> {
        fn as_mut(&mut self) -> &mut CsFp {
            &mut self.fp.as_mut().unwrap().cs
        }
}

impl <Fp, Fr, CsFp, CsFr> AsRef<Constants<Fp>> for Merlin<Fp, Fr, CsFp, CsFr> 
    where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
    CsFp: Cs<Fp>, 
    CsFr: Cs<Fr> {
        fn as_ref(&self) -> &Constants<Fp> {
            &self.fp.as_ref().unwrap().constants
        }
}
*/


impl <Fp, Fr, CsFp, CsFr> Merlin<Fp, Fr, CsFp, CsFr>
    where
        Fp: FftField + PrimeField,
        Fr: FftField + PrimeField,
        CsFp: Cs<Fp>,
        CsFr: Cs<Fr>
{
    pub fn new(ctx: &Context<Fp, Fr, CsFp, CsFr>) -> Self {
        Self {inner: Some(Inner::new(ctx)) }
    }

    #[must_use]
    pub fn recv<H: Absorb<Fp>>(
        &mut self, 
        ctx: &mut Context<Fp, Fr, CsFp, CsFr>, 
        msg: Msg<H>
    ) -> H {
        self.inner.as_mut().unwrap().recv(ctx, msg)
    }

    /// Generate a challenge over the current field
    #[must_use]
    pub fn challenge<C: Challenge<Fp>>(&mut self, ctx: &mut Context<Fp, Fr, CsFp, CsFr>) -> C {
        self.inner.as_mut().unwrap().challenge(ctx)
    }

    #[must_use]
    pub fn flip<T, F: FnOnce(&mut Merlin<Fr, Fp, CsFr, CsFp>) -> T>(
        &mut self, 
        scope: F,
    ) -> T {
        // flip the Merlin
        let mut merlin = Merlin{ inner: self.inner.take().map(|m| m.flipped()) };

        // invoke scope
        let msg = scope(&mut merlin);

        // flip back
        self.inner = merlin.inner.map(|m| m.flipped());
        msg
    }

    #[must_use]
    pub fn recv_fr<H: Absorb<Fr>>(
        &mut self, 
        ctx: &mut Context<Fp, Fr, CsFp, CsFr>, 
        msg: Msg<H>
    ) -> H {
        ctx.flip(|ctx| { // flip the context
            self.flip(|m| { // flip the transcript
                m.recv(ctx, msg) // receive
            })
        })
    }


    #[must_use]
    pub fn challenge_fr<C: Challenge<Fr>>(&mut self, ctx: &mut Context<Fp, Fr, CsFp, CsFr>) -> C {
        ctx.flip(|ctx| {
            self.flip(|m| { // flip the transcript
                m.challenge(ctx)
            })
        })
    }

}

impl <Fp, Fr, CsFp, CsFr> Inner<Fp, Fr, CsFp, CsFr>
    where
        Fp: FftField + PrimeField,
        Fr: FftField + PrimeField,
        CsFp: Cs<Fp>,
        CsFr: Cs<Fr>
{
    fn new(ctx: &Context<Fp, Fr, CsFp, CsFr>) -> Self {
        Self {
            fp: Side::new(ctx.fp.constants.clone()),
            fr: Side::new(ctx.fr.constants.clone()),
            _ph: PhantomData
        }
    }

    /// Receive a message from the prover
    #[must_use]
    fn recv<H: Absorb<Fp>>(
        &mut self, 
        ctx: &mut Context<Fp, Fr, CsFp, CsFr>, 
        msg: Msg<H>
    ) -> H {
        self.fp.merged = false; // state updated since last squeeze
        msg.value.absorb(&mut ctx.fp.cs, &mut self.fp.sponge);
        msg.value
    }

    /// Generate a challenge over the current field
    #[must_use]
    fn challenge<C: Challenge<Fp>>(&mut self, ctx: &mut Context<Fp, Fr, CsFp, CsFr>) -> C {
        // check if we need to merge the states
        if !self.fr.merged {
            // merge the "foreign sponge" by adding the current state to the statement
            let st_fr: Var<Fr> = self.fr.sponge.squeeze(&mut ctx.fr.cs);
            let st_fp: Var<Fp> = ctx.fp.cs.var(|| transfer_hash(st_fr.value.unwrap()));
            
            // absorb commitment to "foreign sponge"
            st_fp.absorb(&mut ctx.fp.cs, &mut self.fp.sponge);
            self.fr.merged = true;
        }

        // squeeze "native sponge" (Fp)
        C::generate(&mut ctx.fp.cs, &mut self.fp.sponge)
    }

    fn flipped(self) -> Inner<Fr, Fp, CsFr, CsFp> {
        Inner{
            fp: self.fr,
            fr: self.fp,
            _ph: PhantomData
        }
    }
}
