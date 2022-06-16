use circuit_construction::{Constants, Cs, Var};

use ark_ff::{BigInteger, FftField, FpParameters, PrimeField};

use std::ops::{Deref, DerefMut};

struct Public<F: FftField + PrimeField> {
    var: Var<F>,
    size: usize,
}

// A "container type"
pub(crate) struct Side<F: FftField + PrimeField, C: Cs<F>> {
    pub(crate) cs: C,
    pub(crate) constants: Constants<F>,
    public: Vec<Public<F>>,   // "export / pass"
    passthrough: Vec<Var<F>>, // passthough fields from this side (to the complement)
}

impl<F: FftField + PrimeField, C: Cs<F>> Side<F, C> {
    fn new(cs: C, constants: Constants<F>) -> Self {
        Self {
            cs,
            public: vec![],
            passthrough: vec![],
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
    inner: Option<InnerContext<Fp, Fr, CsFp, CsFr>>,
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

    /// Pass through a type (representable as a variable) of bounded size
    /// (adding it to the statement on both sides)
    #[must_use]
    pub fn pass<F: Bounded<Fp>, T: Bounded<Fr>>(&mut self, val: F) -> T {
        // idearly we would be able to check this at compile time!
        assert!(
            T::SIZE >= F::SIZE,
            "we can only pass to a looser/equal bound!"
        );

        // covert to variable
        let var: Var<Fp> = val.into();

        // add to public inputs
        self.fp.public.push(Public { size: F::SIZE, var });

        // converts a slice of bits (minimal representative) to a field element
        fn from_bits<F: FftField + PrimeField>(bits: &[bool]) -> F {
            F::from_repr(<F as PrimeField>::BigInt::from_bits_le(bits)).unwrap()
        }

        // needs split if:
        // 1. the modulus of Fr is smaller
        // AND
        // 2. the Fp size is greater/equal than Fr
        let mut split = true;
        split &= Fr::Params::MODULUS.into() < Fp::Params::MODULUS.into();
        split &= Fp::Params::MODULUS_BITS < (F::SIZE as u32);

        // convert the witness to a vec of bits
        let bits = var.value.map(|v| v.into_repr().to_bits_le());

        //
        if split {
            // split into high/low(bit)
            let decm = bits.as_ref().map(|b| {
                let h = from_bits(&b[1..b.len()]);
                let l = if b[0] { Fr::one() } else { Fr::zero() };
                (h, l)
            });

            // split and assign
            (
                self.fr.cs.var(|| decm.unwrap().0),
                Some(self.fr.cs.var(|| decm.unwrap().1)),
            )
                .into()
        } else {
            // fit everything in high
            (self.fr.cs.var(|| from_bits(&bits.unwrap()[..])), None).into()
        }
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
