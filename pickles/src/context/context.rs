use std::ops::{Deref, DerefMut};

use ark_ff::{FftField, PrimeField};

use circuit_construction::{Constants, Cs, Var};

use crate::context::Public;

// A "container type"
pub(crate) struct Side<F: FftField + PrimeField, C: Cs<F>> {
    pub(crate) cs: C,
    pub(crate) constants: Constants<F>,
    pub(crate) deferred: Vec<Public<F>>, // inputs provided to both sides (equal as bit strings)
}

impl<F: FftField + PrimeField, C: Cs<F>> Side<F, C> {
    fn new(cs: C, constants: Constants<F>) -> Self {
        Self {
            cs,
            deferred: Default::default(),
            constants,
        }
    }
}

pub struct InnerContext<Fp, Fr, CsFp, CsFr>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
    CsFp: Cs<Fp>,
    CsFr: Cs<Fr>,
{
    pub(crate) fp: Side<Fp, CsFp>,
    pub(crate) fr: Side<Fr, CsFr>,
}

pub struct Context<Fp, Fr, CsFp, CsFr>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
    CsFp: Cs<Fp>,
    CsFr: Cs<Fr>,
{
    pub(super) inner: Option<InnerContext<Fp, Fr, CsFp, CsFr>>,
}

impl<Fp, Fr, CsFp, CsFr> Deref for InnerContext<Fp, Fr, CsFp, CsFr>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
    CsFp: Cs<Fp>,
    CsFr: Cs<Fr>,
{
    type Target = CsFp;

    fn deref(&self) -> &Self::Target {
        &self.fp.cs
    }
}

impl<Fp, Fr, CsFp, CsFr> DerefMut for InnerContext<Fp, Fr, CsFp, CsFr>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
    CsFp: Cs<Fp>,
    CsFr: Cs<Fr>,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.fp.cs
    }
}

impl<Fp, Fr, CsFp, CsFr> Deref for Context<Fp, Fr, CsFp, CsFr>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
    CsFp: Cs<Fp>,
    CsFr: Cs<Fr>,
{
    type Target = InnerContext<Fp, Fr, CsFp, CsFr>;

    fn deref(&self) -> &Self::Target {
        self.inner.as_ref().unwrap()
    }
}

impl<Fp, Fr, CsFp, CsFr> DerefMut for Context<Fp, Fr, CsFp, CsFr>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
    CsFp: Cs<Fp>,
    CsFr: Cs<Fr>,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner.as_mut().unwrap()
    }
}

/// A variable of bounded size
///
pub trait Bounded<F: FftField + PrimeField>: Into<Var<F>> + From<(Var<F>, Option<Var<F>>)> {
    const SIZE: usize;
}

impl<Fp, CsFp> AsRef<Side<Fp, CsFp>> for Option<Side<Fp, CsFp>>
where
    Fp: FftField + PrimeField,
    CsFp: Cs<Fp>,
{
    fn as_ref(&self) -> &Side<Fp, CsFp> {
        self.as_ref().unwrap()
    }
}

impl<Fp, Fr, CsFp, CsFr> AsMut<CsFp> for InnerContext<Fp, Fr, CsFp, CsFr>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
    CsFp: Cs<Fp>,
    CsFr: Cs<Fr>,
{
    fn as_mut(&mut self) -> &mut CsFp {
        &mut self.fp.cs
    }
}

impl<Fp, Fr, CsFp, CsFr> AsRef<Constants<Fp>> for InnerContext<Fp, Fr, CsFp, CsFr>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
    CsFp: Cs<Fp>,
    CsFr: Cs<Fr>,
{
    fn as_ref(&self) -> &Constants<Fp> {
        &self.fp.constants
    }
}

impl<Fp, Fr, CsFp, CsFr> InnerContext<Fp, Fr, CsFp, CsFr>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
    CsFp: Cs<Fp>,
    CsFr: Cs<Fr>,
{
    pub fn new(
        cs_fp: CsFp,
        cs_fr: CsFr,
        consts_fp: Constants<Fp>,
        consts_fr: Constants<Fr>,
    ) -> Self {
        Self {
            fp: Side::new(cs_fp, consts_fp),
            fr: Side::new(cs_fr, consts_fr),
        }
    }

    pub fn fp(&mut self) -> &mut CsFp {
        &mut self.fp.cs
    }

    pub fn fr(&mut self) -> &mut CsFr {
        &mut self.fr.cs
    }

    pub fn cs(&mut self) -> &mut CsFp {
        self.as_mut()
    }

    pub fn constants(&self) -> &Constants<Fp> {
        self.as_ref()
    }

    pub fn flipped(self) -> InnerContext<Fr, Fp, CsFr, CsFp> {
        InnerContext {
            fp: self.fr,
            fr: self.fp,
        }
    }
}

impl<Fp, Fr, CsFp, CsFr> Context<Fp, Fr, CsFp, CsFr>
where
    Fp: FftField + PrimeField,
    Fr: FftField + PrimeField,
    CsFp: Cs<Fp>,
    CsFr: Cs<Fr>,
{
    pub fn new(
        cs_fp: CsFp,
        cs_fr: CsFr,
        consts_fp: Constants<Fp>,
        consts_fr: Constants<Fr>,
    ) -> Self {
        Self {
            inner: Some(InnerContext::new(cs_fp, cs_fr, consts_fp, consts_fr))
        }
    }

    /// Creates a scope in which the roles of the fields is flipped,
    /// this enables accessing "the other side" and automatically returning.
    ///
    /// Note: this is a "zero cost" operation, which adds no constraints to the proof system
    pub fn flip<T, F: FnOnce(&mut Context<Fr, Fp, CsFr, CsFp>) -> T>(&mut self, scope: F) -> T {
        // flip the inner
        let inner = self.inner.take().unwrap();
        let mut flipped = Context {
            inner: Some(inner.flipped()),
        };

        // invoke scope with the flip
        let res = scope(&mut flipped);

        // return to original
        self.inner = Some(flipped.inner.unwrap().flipped());
        res
    }

    pub fn flipped(self) -> Context<Fr, Fp, CsFr, CsFp> {
        Context {
            inner: Some(self.inner.unwrap().flipped()),
        }
    }
}
