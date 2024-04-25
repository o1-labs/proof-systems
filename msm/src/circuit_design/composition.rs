/// Tools to compose different circit designers.
use crate::{
    circuit_design::capabilities::{ColAccessCap, ColWriteCap, LookupCap},
    columns::ColumnIndexer,
    logup::LookupTableID,
};
use ark_ff::PrimeField;

/// `MPrism` allows one to Something like a Prism, but for Maybe and not just any Applicative.
///
/// See
/// - <https://hackage.haskell.org/package/lens-4.17.1/docs/Control-Lens-Prism.html>
/// - <https://hackage.haskell.org/package/lens-tutorial-1.0.4/docs/Control-Lens-Tutorial.html>
pub trait MPrism {
    /// The lens source type, i.e., the object containing the field.
    type Source;

    /// The lens target type, i.e., the field to be accessed or modified.
    type Target;

    fn traverse(&self, source: Self::Source) -> Option<Self::Target>;

    fn re_get(&self, target: Self::Target) -> Self::Source;
}

pub struct ComposedMPrism<LHS, RHS> {
    /// The left-hand side of the composition.
    lhs: LHS,

    /// The right-hand side of the composition.
    rhs: RHS,
}

impl<LHS, RHS> ComposedMPrism<LHS, RHS>
where
    LHS: MPrism,
    LHS::Target: 'static,
    RHS: MPrism<Source = LHS::Target>,
{
    pub fn compose(lhs: LHS, rhs: RHS) -> ComposedMPrism<LHS, RHS> {
        ComposedMPrism { lhs, rhs }
    }
}

impl<LHS, RHS> MPrism for ComposedMPrism<LHS, RHS>
where
    LHS: MPrism,
    LHS::Target: 'static,
    RHS: MPrism<Source = LHS::Target>,
{
    type Source = LHS::Source;
    type Target = RHS::Target;

    fn traverse(&self, source: Self::Source) -> Option<Self::Target> {
        let r1: Option<_> = self.lhs.traverse(source);
        let r2: Option<_> = r1.and_then(|x| self.rhs.traverse(x));
        r2
    }

    fn re_get(&self, target: Self::Target) -> Self::Source {
        self.lhs.re_get(self.rhs.re_get(target))
    }
}

////////////////////////////////////////////////////////////////////////////
// Interpreter and sub-interpreter
////////////////////////////////////////////////////////////////////////////

// Generic sub-environment struct. Internal object to avoid copy-paste.
struct SubEnv<'a, F: PrimeField, CIx1: ColumnIndexer, Env1: ColAccessCap<F, CIx1>, L> {
    env: &'a mut Env1,
    lens: L,
    phantom: core::marker::PhantomData<(F, CIx1)>,
}

/// Sub environment with a lens that is mapping lookup tables.
/// Can't use `SubEnv` directly because rust is not idris.
pub struct SubEnvColumn<'a, F: PrimeField, CIx1: ColumnIndexer, Env1: ColAccessCap<F, CIx1>, L>(
    SubEnv<'a, F, CIx1, Env1, L>,
);

/// Sub environment with a lens that is mapping lookup tables.
pub struct SubEnvLookup<'a, F: PrimeField, CIx1: ColumnIndexer, Env1: ColAccessCap<F, CIx1>, L>(
    SubEnv<'a, F, CIx1, Env1, L>,
);

////////////////////////////////////////////////////////////////////////////
// Trait implementations
////////////////////////////////////////////////////////////////////////////

impl<'a, F: PrimeField, CIx1: ColumnIndexer, Env1: ColAccessCap<F, CIx1>, L>
    SubEnv<'a, F, CIx1, Env1, L>
{
    pub fn new(env: &'a mut Env1, lens: L) -> Self {
        SubEnv {
            env,
            lens,
            phantom: Default::default(),
        }
    }
}

impl<'a, F: PrimeField, CIx1: ColumnIndexer, Env1: ColAccessCap<F, CIx1>, L>
    SubEnvColumn<'a, F, CIx1, Env1, L>
{
    pub fn new(env: &'a mut Env1, lens: L) -> Self {
        SubEnvColumn(SubEnv::new(env, lens))
    }
}

impl<'a, F: PrimeField, CIx1: ColumnIndexer, Env1: ColAccessCap<F, CIx1>, L>
    SubEnvLookup<'a, F, CIx1, Env1, L>
{
    pub fn new(env: &'a mut Env1, lens: L) -> Self {
        SubEnvLookup(SubEnv::new(env, lens))
    }
}

impl<
        'a,
        F: PrimeField,
        CIx1: ColumnIndexer,
        CIx2: ColumnIndexer,
        Env1: ColAccessCap<F, CIx1>,
        L: MPrism<Source = CIx1, Target = CIx2>,
    > ColAccessCap<F, CIx2> for SubEnv<'a, F, CIx1, Env1, L>
{
    type Variable = Env1::Variable;

    fn assert_zero(&mut self, cst: Self::Variable) {
        self.env.assert_zero(cst);
    }

    fn constant(value: F) -> Self::Variable {
        Env1::constant(value)
    }

    fn read_column(&self, ix: CIx2) -> Self::Variable {
        self.env.read_column(self.lens.re_get(ix))
    }
}

impl<
        'a,
        F: PrimeField,
        CIx1: ColumnIndexer,
        CIx2: ColumnIndexer,
        Env1: ColWriteCap<F, CIx1>,
        L: MPrism<Source = CIx1, Target = CIx2>,
    > ColWriteCap<F, CIx2> for SubEnv<'a, F, CIx1, Env1, L>
{
    fn write_column(&mut self, ix: CIx2, value: &Self::Variable) {
        self.env.write_column(self.lens.re_get(ix), value)
    }
}

impl<
        'a,
        F: PrimeField,
        CIx1: ColumnIndexer,
        CIx2: ColumnIndexer,
        Env1: ColAccessCap<F, CIx1>,
        L: MPrism<Source = CIx1, Target = CIx2>,
    > ColAccessCap<F, CIx2> for SubEnvColumn<'a, F, CIx1, Env1, L>
{
    type Variable = Env1::Variable;

    fn assert_zero(&mut self, cst: Self::Variable) {
        self.0.assert_zero(cst);
    }

    fn constant(value: F) -> Self::Variable {
        Env1::constant(value)
    }

    fn read_column(&self, ix: CIx2) -> Self::Variable {
        self.0.read_column(ix)
    }
}

impl<
        'a,
        F: PrimeField,
        CIx1: ColumnIndexer,
        CIx2: ColumnIndexer,
        Env1: ColWriteCap<F, CIx1>,
        L: MPrism<Source = CIx1, Target = CIx2>,
    > ColWriteCap<F, CIx2> for SubEnvColumn<'a, F, CIx1, Env1, L>
{
    fn write_column(&mut self, ix: CIx2, value: &Self::Variable) {
        self.0.write_column(ix, value);
    }
}

impl<'a, F: PrimeField, CIx1: ColumnIndexer, Env1: ColAccessCap<F, CIx1>, L> ColAccessCap<F, CIx1>
    for SubEnvLookup<'a, F, CIx1, Env1, L>
{
    type Variable = Env1::Variable;

    fn assert_zero(&mut self, cst: Self::Variable) {
        self.0.env.assert_zero(cst);
    }

    fn constant(value: F) -> Self::Variable {
        Env1::constant(value)
    }

    fn read_column(&self, ix: CIx1) -> Self::Variable {
        self.0.env.read_column(ix)
    }
}

impl<'a, F: PrimeField, CIx1: ColumnIndexer, Env1: ColWriteCap<F, CIx1>, L> ColWriteCap<F, CIx1>
    for SubEnvLookup<'a, F, CIx1, Env1, L>
{
    fn write_column(&mut self, ix: CIx1, value: &Self::Variable) {
        self.0.env.write_column(ix, value);
    }
}

impl<
        'a,
        F: PrimeField,
        CIx: ColumnIndexer,
        LT1: LookupTableID,
        LT2: LookupTableID,
        Env1: LookupCap<F, CIx, LT1>,
        L: MPrism<Source = LT1, Target = LT2>,
    > LookupCap<F, CIx, LT2> for SubEnvLookup<'a, F, CIx, Env1, L>
{
    fn lookup(&mut self, lookup_id: LT2, value: &Self::Variable) {
        self.0.env.lookup(self.0.lens.re_get(lookup_id), value)
    }
}

impl<
        'a,
        F: PrimeField,
        CIx1: ColumnIndexer,
        CIx2: ColumnIndexer,
        LT: LookupTableID,
        Env1: LookupCap<F, CIx1, LT>,
        L: MPrism<Source = CIx1, Target = CIx2>,
    > LookupCap<F, CIx2, LT> for SubEnvColumn<'a, F, CIx1, Env1, L>
{
    fn lookup(&mut self, lookup_id: LT, value: &Self::Variable) {
        self.0.env.lookup(lookup_id, value)
    }
}
