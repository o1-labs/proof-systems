use crate::logup::LookupTableID;
use ark_ff::PrimeField;
use strum_macros::EnumIter;

////////////////////////////////////////////////////////////////////////////
// Abstract lenses
////////////////////////////////////////////////////////////////////////////

/// Something like a Prism, but for Maybe and not just any
/// Applicative. Not sure what's a better name. To me this looks most
/// like a prism.
///
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

pub fn compose<LHS, RHS>(lhs: LHS, rhs: RHS) -> ComposedMPrism<LHS, RHS>
where
    LHS: MPrism,
    LHS::Target: 'static,
    RHS: MPrism<Source = LHS::Target>,
{
    ComposedMPrism { lhs, rhs }
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
// Column definitions
////////////////////////////////////////////////////////////////////////////

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct Column(usize);

// PRototype-y
pub trait ColIndexer {
    const IX_COL_N: usize;

    // TODO: rename it in to_column. It is not necessary to have ix_
    fn ix_to_column(self) -> Column;
    //    fn flatten_one_level(self) -> usize;
}

pub const FOO_COL_N: usize = 17;

pub enum FooColIndexer {
    Foo1(usize),
    Foo2(usize),
}

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Default, EnumIter)]
pub enum FooLookupTable {
    #[default]
    RangeCheckFoo1,
    RangeCheckFoo2,
}

pub const BLA_COL_N: usize = 2 * FOO_COL_N + 4;

pub enum BlaColIndexer {
    SubFoo1(FooColIndexer),
    SubFoo2(FooColIndexer),
    Bla1(usize), // at most 2
    Bla2(usize), // at most 2
}

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Default, EnumIter)]
pub enum BlaLookupTable {
    SumFooRangeCheck(FooLookupTable),
    #[default]
    RangeCheckBla1,
    RangeCheckBla2,
}

pub const KEK_COL_N: usize = 2 * FOO_COL_N + 4;

pub enum KekColIndexer {
    SubFoo1(FooColIndexer),
    SubBla1(BlaColIndexer),
    Kek1(usize), // at most 2
    Kek2(usize), // at most 2
    Kek3(usize), // at most 2
    Kek4(usize), // at most 2
}

impl ColIndexer for FooColIndexer {
    const IX_COL_N: usize = FOO_COL_N;
    fn ix_to_column(self) -> Column {
        unimplemented!()
    }
}

impl ColIndexer for BlaColIndexer {
    const IX_COL_N: usize = BLA_COL_N;
    fn ix_to_column(self) -> Column {
        unimplemented!()
    }
}

impl ColIndexer for KekColIndexer {
    const IX_COL_N: usize = KEK_COL_N;
    fn ix_to_column(self) -> Column {
        unimplemented!()
    }
}

impl LookupTableID for FooLookupTable {
    fn to_u32(&self) -> u32 {
        todo!()
    }

    fn from_u32(_value: u32) -> Self {
        todo!()
    }

    fn is_fixed(&self) -> bool {
        true
    }

    fn length(&self) -> usize {
        todo!()
    }
}

impl LookupTableID for BlaLookupTable {
    fn to_u32(&self) -> u32 {
        todo!()
    }

    fn from_u32(_value: u32) -> Self {
        todo!()
    }

    fn is_fixed(&self) -> bool {
        true
    }

    fn length(&self) -> usize {
        todo!()
    }
}

////////////////////////////////////////////////////////////////////////////
// Concrete lenses for our columns
////////////////////////////////////////////////////////////////////////////

pub struct BlaFoo1Lens {}

impl MPrism for BlaFoo1Lens {
    type Source = BlaColIndexer;
    type Target = FooColIndexer;

    fn traverse(&self, source: Self::Source) -> Option<Self::Target> {
        match source {
            BlaColIndexer::SubFoo1(ixer) => Some(ixer),
            _ => None,
        }
    }

    fn re_get(&self, target: Self::Target) -> Self::Source {
        BlaColIndexer::SubFoo1(target)
    }
}

pub struct BlaFoo2Lens {}

impl MPrism for BlaFoo2Lens {
    type Source = BlaColIndexer;
    type Target = FooColIndexer;

    fn traverse(&self, source: Self::Source) -> Option<Self::Target> {
        match source {
            BlaColIndexer::SubFoo2(ixer) => Some(ixer),
            _ => None,
        }
    }

    fn re_get(&self, target: Self::Target) -> Self::Source {
        BlaColIndexer::SubFoo2(target)
    }
}

pub struct KekBla1Lens {}

impl MPrism for KekBla1Lens {
    type Source = KekColIndexer;
    type Target = BlaColIndexer;

    fn traverse(&self, source: Self::Source) -> Option<Self::Target> {
        match source {
            KekColIndexer::SubBla1(ixer) => Some(ixer),
            _ => None,
        }
    }

    fn re_get(&self, target: Self::Target) -> Self::Source {
        KekColIndexer::SubBla1(target)
    }
}

pub struct KekFooComplexLens {}

impl MPrism for KekFooComplexLens {
    type Source = KekColIndexer;
    type Target = FooColIndexer;

    fn traverse(&self, source: Self::Source) -> Option<Self::Target> {
        match source {
            KekColIndexer::Kek1(ixer) => Some(FooColIndexer::Foo1(ixer)),
            KekColIndexer::Kek2(ixer) => Some(FooColIndexer::Foo2(ixer)),
            _ => None,
        }
    }

    fn re_get(&self, target: Self::Target) -> Self::Source {
        match target {
            FooColIndexer::Foo1(i) => KekColIndexer::Kek1(i),
            FooColIndexer::Foo2(i) => KekColIndexer::Kek2(i),
        }
    }
}

////////////////////////////////////////////////////////////////////////////
// Interpreter and sub-interpreter
////////////////////////////////////////////////////////////////////////////

/// Environment capability for reading columns. This is necessary for
/// building constraints.
pub trait ColAccessCap<CIx: ColIndexer, F: PrimeField> {
    type Variable: Clone
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::fmt::Debug;

    fn assert_zero(&mut self, cst: Self::Variable);

    fn read_column(&self, ix: CIx) -> Self::Variable;

    fn constant(&self, value: F) -> Self::Variable;
}

/// Same as `ColAcessT` but also writing constraints.
pub trait ColWriteCap<CIx: ColIndexer, F: PrimeField>
where
    Self: ColAccessCap<CIx, F>,
{
    fn write_column(&mut self, ix: CIx, value: Self::Variable);
}

/// Capability for invoking fixed table lookups (range checks).
pub trait FixedLookupCap<CIx: ColIndexer, F: PrimeField, LT: LookupTableID>
where
    Self: ColAccessCap<CIx, F>,
{
    fn lookup_fixed(&mut self, lookup_id: LT, value: Self::Variable);
}

pub struct SubEnv<'a, F: PrimeField, CIx1: ColIndexer, Env1: ColAccessCap<CIx1, F>, L> {
    env: &'a mut Env1,
    lens: L,
    phantom: core::marker::PhantomData<(F, CIx1)>,
}

impl<'a, F: PrimeField, CIx1: ColIndexer, Env1: ColAccessCap<CIx1, F>, L>
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

impl<
        'a,
        F: PrimeField,
        CIx1: ColIndexer,
        CIx2: ColIndexer,
        Env1: ColAccessCap<CIx1, F>,
        L: MPrism<Source = CIx1, Target = CIx2>,
    > ColAccessCap<CIx2, F> for SubEnv<'a, F, CIx1, Env1, L>
{
    type Variable = Env1::Variable;

    fn assert_zero(&mut self, cst: Self::Variable) {
        self.env.assert_zero(cst);
    }

    fn constant(&self, value: F) -> Self::Variable {
        self.env.constant(value)
    }

    fn read_column(&self, ix: CIx2) -> Self::Variable {
        self.env.read_column(self.lens.re_get(ix))
    }
}

impl<
        'a,
        F: PrimeField,
        CIx1: ColIndexer,
        CIx2: ColIndexer,
        Env1: ColWriteCap<CIx1, F>,
        L: MPrism<Source = CIx1, Target = CIx2>,
    > ColWriteCap<CIx2, F> for SubEnv<'a, F, CIx1, Env1, L>
{
    fn write_column(&mut self, ix: CIx2, value: Self::Variable) {
        self.env.write_column(self.lens.re_get(ix), value)
    }
}

impl<
        'a,
        F: PrimeField,
        CIx1: ColIndexer,
        CIx2: ColIndexer,
        LT: LookupTableID,
        Env1: FixedLookupCap<CIx1, F, LT>,
        L: MPrism<Source = CIx1, Target = CIx2>,
    > FixedLookupCap<CIx2, F, LT> for SubEnv<'a, F, CIx1, Env1, L>
{
    fn lookup_fixed(&mut self, lookup_id: LT, value: Self::Variable) {
        self.env.lookup_fixed(lookup_id, value)
    }
}

//pub struct SubEnvLT<
//    'a,
//    LT1: LookupTableID,
//    LT2: LookupTableID,
//    Env,
//    L: MPrism<Source = LT1, Target = LT2>,
//> {
//    env: &'a mut Env,
//    lens: L,
//}

////////////////////////////////////////////////////////////////////////////
// Functions using interpreter env
////////////////////////////////////////////////////////////////////////////

pub fn constrain_foo<F, Env>(env: &mut Env) -> Env::Variable
where
    F: PrimeField,
    Env: ColAccessCap<FooColIndexer, F>,
{
    let a_var: Env::Variable = Env::read_column(env, FooColIndexer::Foo1(0));
    a_var
}

pub fn constrain_foo_w<F, Env>(env: &mut Env) -> Env::Variable
where
    F: PrimeField,
    Env: ColWriteCap<FooColIndexer, F>,
{
    let a_var: Env::Variable = Env::read_column(env, FooColIndexer::Foo1(0));
    Env::write_column(env, FooColIndexer::Foo1(1), a_var.clone());
    a_var
}

pub fn constrain_foo_lookup<F, LT, Env>(env: &mut Env) -> Env::Variable
where
    F: PrimeField,
    Env: FixedLookupCap<FooColIndexer, F, FooLookupTable>,
{
    let a_var: Env::Variable = Env::read_column(env, FooColIndexer::Foo1(0));
    env.lookup_fixed(FooLookupTable::RangeCheckFoo1, a_var.clone());
    a_var
}

pub fn constrain_bla<F, Env>(env: &mut Env) -> Env::Variable
where
    F: PrimeField,
    Env: ColAccessCap<BlaColIndexer, F>,
{
    let a_var: Env::Variable = Env::read_column(env, BlaColIndexer::Bla1(0));
    constrain_foo(&mut SubEnv::new(env, BlaFoo1Lens {}));
    constrain_foo(&mut SubEnv::new(env, BlaFoo2Lens {}));
    // This cannot compile since we're calling writer sub-env from a reader-only env
    // constrain_foo_w(&mut SubEnv::new(env, BlaFoo2Lens {}));
    a_var
}

pub fn constrain_bla_w<F, Env>(env: &mut Env) -> Env::Variable
where
    F: PrimeField,
    Env: ColWriteCap<BlaColIndexer, F>,
{
    let a_var: Env::Variable = Env::read_column(env, BlaColIndexer::Bla1(0));
    constrain_foo(&mut SubEnv::new(env, BlaFoo1Lens {}));
    constrain_foo_w(&mut SubEnv::new(env, BlaFoo2Lens {}));
    a_var
}

pub fn constrain_bla_lookup<F, Env>(env: &mut Env) -> Env::Variable
where
    F: PrimeField,
    Env: FixedLookupCap<BlaColIndexer, F, BlaLookupTable>,
{
    let a_var: Env::Variable = Env::read_column(env, BlaColIndexer::Bla1(0));
    constrain_foo(&mut SubEnv::new(env, BlaFoo1Lens {}));
    constrain_foo(&mut SubEnv::new(env, BlaFoo2Lens {}));
    // This cannot compile since we're calling writer sub-env from a reader-only env
    // constrain_foo_w(&mut SubEnv::new(env, BlaFoo2Lens {}));
    a_var
}

pub fn constrain_kek<F, Env>(env: &mut Env) -> Env::Variable
where
    F: PrimeField,
    Env: ColAccessCap<KekColIndexer, F>,
{
    let a_var: Env::Variable = Env::read_column(env, KekColIndexer::Kek1(0));
    constrain_bla(&mut SubEnv::new(env, KekBla1Lens {}));
    constrain_foo(&mut SubEnv::new(
        env,
        compose(KekBla1Lens {}, BlaFoo1Lens {}),
    ));
    constrain_foo(&mut SubEnv::new(env, KekFooComplexLens {}));

    a_var
}
