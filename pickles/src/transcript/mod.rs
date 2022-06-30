use circuit_construction::{Constants, Cs, Var};

use ark_ff::{BigInteger, FftField, FpParameters, PrimeField};

mod sponge;
mod utils;

use crate::context::Context;

pub use sponge::{Absorb, Challenge, VarSponge};

use std::mem;
use std::ops::{Deref, DerefMut};

use std::marker::PhantomData;

use utils::{decompose, lift, need_decompose, transfer_hash};

struct Public<F: FftField + PrimeField> {
    var: Var<F>,
    size: usize,
}

// A "container type"
struct Side<F: FftField + PrimeField> {
    constants: Constants<F>,
    sponge: Option<VarSponge<F>>, // sponge constrained inside the proof system
}

impl<F: FftField + PrimeField> Side<F> {
    fn new(constants: Constants<F>) -> Self {
        Self {
            sponge: None,
            constants,
        }
    }
}

struct Inner<Fp, Fr, CsFp, CsFr>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
{
    fp: Side<Fp>,
    fr: Side<Fr>,
    _ph: PhantomData<(CsFp, CsFr)>,
}

pub struct Arthur<Fp, Fr, CsFp, CsFr>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
{
    inner: Option<Inner<Fp, Fr, CsFp, CsFr>>,
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

impl<Fp, Fr, CsFp, CsFr> Arthur<Fp, Fr, CsFp, CsFr>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
    CsFp: Cs<Fp>,
    CsFr: Cs<Fr>,
{
    pub fn new(ctx: &Context<Fp, Fr, CsFp, CsFr>) -> Self {
        Self {
            inner: Some(Inner::new(ctx)),
        }
    }

    #[must_use]
    pub fn recv<R: Receivable<Fp>>(
        &mut self,
        ctx: &mut Context<Fp, Fr, CsFp, CsFr>,
        msg: R,
    ) -> R::Dst {
        self.inner.as_mut().unwrap().recv(ctx, msg)
    }

    /// Generate a challenge over the current field
    #[must_use]
    pub fn challenge<C: Challenge<Fp>>(&mut self, ctx: &mut Context<Fp, Fr, CsFp, CsFr>) -> C {
        self.inner.as_mut().unwrap().challenge(ctx)
    }

    #[must_use]
    pub fn flip<T, F: FnOnce(&mut Arthur<Fr, Fp, CsFr, CsFp>) -> T>(&mut self, scope: F) -> T {
        // flip the Arthur
        let mut merlin = Arthur {
            inner: self.inner.take().map(|m| m.flipped()),
        };

        // invoke scope
        let msg = scope(&mut merlin);

        // flip back
        self.inner = merlin.inner.map(|m| m.flipped());
        msg
    }

    // invoke scope without affecting the current sponge state
    // essentially "branches", this requires a scope
    pub fn fork() {}
}

impl<Fp, Fr, CsFp, CsFr> Inner<Fp, Fr, CsFp, CsFr>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
    CsFp: Cs<Fp>,
    CsFr: Cs<Fr>,
{
    fn new(ctx: &Context<Fp, Fr, CsFp, CsFr>) -> Self {
        Self {
            fp: Side::new(ctx.fp.constants.clone()),
            fr: Side::new(ctx.fr.constants.clone()),
            _ph: PhantomData,
        }
    }

    // do not invoke this manually
    fn fp_sponge(&mut self, ctx: &mut Context<Fp, Fr, CsFp, CsFr>) -> &mut VarSponge<Fp> {
        // initialize Fp sponge
        let st_fp = self
            .fp
            .sponge
            .get_or_insert_with(|| VarSponge::new(self.fp.constants.clone()));

        // check if Fr side is not none
        if let Some(mut fr_st) = self.fr.sponge.take() {
            unimplemented!();
            /*
            // compute digest in other side and pass over
            let hsh_fr: PassedField<Fp> = ctx.flip(|ctx| {
                let st_fr: Var<Fr> = fr_st.challenge(&mut ctx.fp.cs);
                ctx.pass(st_fr)
            });

            // absorb in Fp
            hsh_fr.absorb(ctx.cs(), st_fp);
            */
        }

        st_fp
    }

    /// Receive a message from the prover
    #[must_use]
    pub fn recv<R: Receivable<Fp>>(
        &mut self,
        ctx: &mut Context<Fp, Fr, CsFp, CsFr>,
        msg: R,
    ) -> R::Dst {
        let st = self.fp_sponge(ctx);
        msg.unpack(ctx.cs(), st)
    }

    /// Generate a challenge over the current field
    #[must_use]
    pub fn challenge<C: Challenge<Fp>>(&mut self, ctx: &mut Context<Fp, Fr, CsFp, CsFr>) -> C {
        let st = self.fp_sponge(ctx);
        C::generate(&mut ctx.fp.cs, st)
    }

    pub fn flipped(self) -> Inner<Fr, Fp, CsFr, CsFp> {
        Inner {
            fp: self.fr,
            fr: self.fp,
            _ph: PhantomData,
        }
    }
}
