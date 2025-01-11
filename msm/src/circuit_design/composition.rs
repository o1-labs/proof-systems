/// Tools to /compose/ different circuit designers.
///
/// Assume we have several sets of columns:
/// Col0 ⊂ Col1 ⊂ Col2, and
///       Col1' ⊂ Col2
///
///
/// For example they are laid out like this:
///
/// |-------------------------------------------| Col2
/// |-|  |----------------------|                 Col1
///        |-----|     |--| |---|                 Col0
/// |---|        |-----|        |---------------| Col1'
///
/// Some columns might be even shared (e.g. Col1 and Col1' share column#0).
///
/// Using capabilities one can define functions that operate over different sets of columns,
/// and does not "know" in which bigger context it operates.
/// - function0<Env: ColumnAccess<Col0>>(env: Env, ...)
/// - function1<Env: ColumnAccess<Col1>>(env: Env, ...)
/// - function1'<Env: ColumnAccess<Col1'>>(env: Env, ...)
/// - function2<Env: ColumnAccess<Col2>>(env: Env, ...)
///
/// This is similar to memory separation: a program function0 might
/// need just three columns for A * B - C constraint, and if it works
/// in a 1000 column environment it needs to be told /which three
/// exactly/ will it see.
///
/// One only needs a single concrete Env (e.g. WitnessBuilder or
/// Constraint Builder) over the "top level" Col2, and then all these
/// functions can be called using lenses. Each lens describes how the
/// layouts will be mapped.
///
/// |-------------------------------------------|                        Col2
///            |                  |      |
///            | Col2To1Lens      |      |
///            V                  |      |
/// |-|  |----------------------| | (compose(Col2To1Lens . Col1To0Lens)  Col1
///            |                  |      |
///            | Col1To0Lens     /       |
///            |                /        |
///            V               V         | Col2To1'Lens
///        |-----|     |--| |---|        |                               Col0
///                                      V
/// |---|        |-----|        |---------------|                        Col1'
///
///
/// Similar "mapping" intuition applies to lookup tables.
use crate::{
    circuit_design::capabilities::{
        ColAccessCap, ColWriteCap, DirectWitnessCap, HybridCopyCap, LookupCap, MultiRowReadCap,
    },
    columns::ColumnIndexer,
    logup::LookupTableID,
};
use ark_ff::PrimeField;
use std::marker::PhantomData;

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

/// Identity `MPrism` from any type `T` to itself.
///
/// Can be used in many situations. E.g. when `foo1` and `foo2` both
/// call `bar` that is parameterised by a lens, and `foo1` has
/// identical context to `bar` (so requires the ID lens), but `foo2`
/// needs an actual non-ID lens.
#[derive(Clone, Copy, Debug)]
pub struct IdMPrism<T>(pub PhantomData<T>);

impl<T> Default for IdMPrism<T> {
    fn default() -> Self {
        IdMPrism(PhantomData)
    }
}

impl<T> MPrism for IdMPrism<T> {
    type Source = T;
    type Target = T;

    fn traverse(&self, source: Self::Source) -> Option<Self::Target> {
        Some(source)
    }

    fn re_get(&self, target: Self::Target) -> Self::Source {
        target
    }
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

/// Generic sub-environment struct: don't use directly. It's an
/// internal object to avoid copy-paste.
///
/// We can't use `SubEnv` directly because rust is not idris: it is
/// impossible to instantiate `SubEnv` with two /completely/ different
/// lenses and then write proper trait implementations. Rust complains
/// about conflicting trait implementations.
struct SubEnv<'a, F: PrimeField, CIx1: ColumnIndexer<usize>, Env1: ColAccessCap<F, CIx1>, L> {
    env: &'a mut Env1,
    lens: L,
    phantom: PhantomData<(F, CIx1)>,
}

/// Sub environment with a lens that is mapping columns.
pub struct SubEnvColumn<
    'a,
    F: PrimeField,
    CIx1: ColumnIndexer<usize>,
    Env1: ColAccessCap<F, CIx1>,
    L,
>(SubEnv<'a, F, CIx1, Env1, L>);

/// Sub environment with a lens that is mapping lookup tables.
pub struct SubEnvLookup<
    'a,
    F: PrimeField,
    CIx1: ColumnIndexer<usize>,
    Env1: ColAccessCap<F, CIx1>,
    L,
>(SubEnv<'a, F, CIx1, Env1, L>);

////////////////////////////////////////////////////////////////////////////
// Trait implementations
////////////////////////////////////////////////////////////////////////////

impl<'a, F: PrimeField, CIx1: ColumnIndexer<usize>, Env1: ColAccessCap<F, CIx1>, L>
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

impl<'a, F: PrimeField, CIx1: ColumnIndexer<usize>, Env1: ColAccessCap<F, CIx1>, L>
    SubEnvColumn<'a, F, CIx1, Env1, L>
{
    pub fn new(env: &'a mut Env1, lens: L) -> Self {
        SubEnvColumn(SubEnv::new(env, lens))
    }
}

impl<'a, F: PrimeField, CIx1: ColumnIndexer<usize>, Env1: ColAccessCap<F, CIx1>, L>
    SubEnvLookup<'a, F, CIx1, Env1, L>
{
    pub fn new(env: &'a mut Env1, lens: L) -> Self {
        SubEnvLookup(SubEnv::new(env, lens))
    }
}

impl<
        'a,
        F: PrimeField,
        CIx1: ColumnIndexer<usize>,
        CIx2: ColumnIndexer<usize>,
        Env1: ColAccessCap<F, CIx1>,
        L: MPrism<Source = CIx1, Target = CIx2>,
    > ColAccessCap<F, CIx2> for SubEnv<'a, F, CIx1, Env1, L>
{
    type Variable = Env1::Variable;

    fn assert_zero(&mut self, cst: Self::Variable) {
        self.env.assert_zero(cst);
    }

    fn set_assert_mapper(&mut self, mapper: Box<dyn Fn(Self::Variable) -> Self::Variable>) {
        self.env.set_assert_mapper(mapper);
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
        CIx1: ColumnIndexer<usize>,
        CIx2: ColumnIndexer<usize>,
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
        CIx1: ColumnIndexer<usize>,
        CIx2: ColumnIndexer<usize>,
        Env1: HybridCopyCap<F, CIx1>,
        L: MPrism<Source = CIx1, Target = CIx2>,
    > HybridCopyCap<F, CIx2> for SubEnv<'a, F, CIx1, Env1, L>
{
    fn hcopy(&mut self, x: &Self::Variable, ix: CIx2) -> Self::Variable {
        self.env.hcopy(x, self.lens.re_get(ix))
    }
}

impl<
        'a,
        F: PrimeField,
        CIx1: ColumnIndexer<usize>,
        CIx2: ColumnIndexer<usize>,
        Env1: ColAccessCap<F, CIx1>,
        L: MPrism<Source = CIx1, Target = CIx2>,
    > ColAccessCap<F, CIx2> for SubEnvColumn<'a, F, CIx1, Env1, L>
{
    type Variable = Env1::Variable;

    fn assert_zero(&mut self, cst: Self::Variable) {
        self.0.assert_zero(cst);
    }

    fn set_assert_mapper(&mut self, mapper: Box<dyn Fn(Self::Variable) -> Self::Variable>) {
        self.0.set_assert_mapper(mapper);
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
        CIx1: ColumnIndexer<usize>,
        CIx2: ColumnIndexer<usize>,
        Env1: ColWriteCap<F, CIx1>,
        L: MPrism<Source = CIx1, Target = CIx2>,
    > ColWriteCap<F, CIx2> for SubEnvColumn<'a, F, CIx1, Env1, L>
{
    fn write_column(&mut self, ix: CIx2, value: &Self::Variable) {
        self.0.write_column(ix, value);
    }
}

impl<
        'a,
        F: PrimeField,
        CIx1: ColumnIndexer<usize>,
        CIx2: ColumnIndexer<usize>,
        Env1: HybridCopyCap<F, CIx1>,
        L: MPrism<Source = CIx1, Target = CIx2>,
    > HybridCopyCap<F, CIx2> for SubEnvColumn<'a, F, CIx1, Env1, L>
{
    fn hcopy(&mut self, x: &Self::Variable, ix: CIx2) -> Self::Variable {
        self.0.hcopy(x, ix)
    }
}

impl<'a, F: PrimeField, CIx1: ColumnIndexer<usize>, Env1: ColAccessCap<F, CIx1>, L>
    ColAccessCap<F, CIx1> for SubEnvLookup<'a, F, CIx1, Env1, L>
{
    type Variable = Env1::Variable;

    fn assert_zero(&mut self, cst: Self::Variable) {
        self.0.env.assert_zero(cst);
    }

    fn set_assert_mapper(&mut self, mapper: Box<dyn Fn(Self::Variable) -> Self::Variable>) {
        self.0.env.set_assert_mapper(mapper);
    }

    fn constant(value: F) -> Self::Variable {
        Env1::constant(value)
    }

    fn read_column(&self, ix: CIx1) -> Self::Variable {
        self.0.env.read_column(ix)
    }
}

impl<'a, F: PrimeField, CIx1: ColumnIndexer<usize>, Env1: ColWriteCap<F, CIx1>, L>
    ColWriteCap<F, CIx1> for SubEnvLookup<'a, F, CIx1, Env1, L>
{
    fn write_column(&mut self, ix: CIx1, value: &Self::Variable) {
        self.0.env.write_column(ix, value);
    }
}

impl<'a, F: PrimeField, CIx1: ColumnIndexer<usize>, Env1: HybridCopyCap<F, CIx1>, L>
    HybridCopyCap<F, CIx1> for SubEnvLookup<'a, F, CIx1, Env1, L>
{
    fn hcopy(&mut self, x: &Self::Variable, ix: CIx1) -> Self::Variable {
        self.0.env.hcopy(x, ix)
    }
}

impl<
        'a,
        F: PrimeField,
        CIx: ColumnIndexer<usize>,
        LT1: LookupTableID,
        LT2: LookupTableID,
        Env1: LookupCap<F, CIx, LT1>,
        L: MPrism<Source = LT1, Target = LT2>,
    > LookupCap<F, CIx, LT2> for SubEnvLookup<'a, F, CIx, Env1, L>
{
    fn lookup(&mut self, lookup_id: LT2, value: Vec<Self::Variable>) {
        self.0.env.lookup(self.0.lens.re_get(lookup_id), value)
    }

    fn lookup_runtime_write(&mut self, lookup_id: LT2, value: Vec<Self::Variable>) {
        self.0
            .env
            .lookup_runtime_write(self.0.lens.re_get(lookup_id), value)
    }
}

impl<
        'a,
        F: PrimeField,
        CIx1: ColumnIndexer<usize>,
        CIx2: ColumnIndexer<usize>,
        LT: LookupTableID,
        Env1: LookupCap<F, CIx1, LT>,
        L: MPrism<Source = CIx1, Target = CIx2>,
    > LookupCap<F, CIx2, LT> for SubEnvColumn<'a, F, CIx1, Env1, L>
{
    fn lookup(&mut self, lookup_id: LT, value: Vec<Self::Variable>) {
        self.0.env.lookup(lookup_id, value)
    }

    fn lookup_runtime_write(&mut self, lookup_id: LT, value: Vec<Self::Variable>) {
        self.0.env.lookup_runtime_write(lookup_id, value)
    }
}

impl<'a, F: PrimeField, CIx: ColumnIndexer<usize>, Env1: MultiRowReadCap<F, CIx>, L>
    MultiRowReadCap<F, CIx> for SubEnvLookup<'a, F, CIx, Env1, L>
{
    /// Read value from a (row,column) position.
    fn read_row_column(&mut self, row: usize, col: CIx) -> Self::Variable {
        self.0.env.read_row_column(row, col)
    }

    /// Progresses to the next row.
    fn next_row(&mut self) {
        self.0.env.next_row();
    }

    /// Returns the current row.
    fn curr_row(&self) -> usize {
        self.0.env.curr_row()
    }
}

impl<'a, F: PrimeField, CIx: ColumnIndexer<usize>, Env1: DirectWitnessCap<F, CIx>, L>
    DirectWitnessCap<F, CIx> for SubEnvLookup<'a, F, CIx, Env1, L>
{
    fn variable_to_field(value: Self::Variable) -> F {
        Env1::variable_to_field(value)
    }
}

// TODO add traits for SubEnvColumn
