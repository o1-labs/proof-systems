use ark_ff::PrimeField;

// To bring trait methods like `get_ref` and `set` into scope
use pl_lens::LensPath;

////////////////////////////////////////////////////////////////////////////
// Abstract lenses
////////////////////////////////////////////////////////////////////////////

/// Something like a Traversal
///
/// https://hackage.haskell.org/package/lens-4.17.1/docs/Control-Lens-Traversal.html
///
/// but for Maybe in a Getter-style
///
/// https://hackage.haskell.org/package/lens-4.17.1/docs/Control-Lens-Getter.html
///
/// Also seems very similar to a Prism: https://hackage.haskell.org/package/lens-4.17.1/docs/Control-Lens-Prism.html
pub trait MGetter {
    /// The lens source type, i.e., the object containing the field.
    type Source;

    /// The lens target type, i.e., the field to be accessed or modified.
    type Target;

    /// Returns a `LensPath` that describes the target of this lens relative to its source.
    fn path(&self) -> LensPath;

    fn traverse(&self, source: Self::Source) -> Option<Self::Target>;

    fn re_get(&self, target: Self::Target) -> Self::Source;
}

pub struct ComposedMGetter<LHS, RHS> {
    /// The left-hand side of the composition.
    lhs: LHS,

    /// The right-hand side of the composition.
    rhs: RHS,
}

pub fn compose<LHS, RHS>(lhs: LHS, rhs: RHS) -> ComposedMGetter<LHS, RHS>
where
    LHS: MGetter,
    LHS::Target: 'static,
    RHS: MGetter<Source = LHS::Target>,
{
    ComposedMGetter { lhs, rhs }
}

impl<LHS, RHS> MGetter for ComposedMGetter<LHS, RHS>
where
    LHS: MGetter,
    LHS::Target: 'static,
    RHS: MGetter<Source = LHS::Target>,
{
    type Source = LHS::Source;
    type Target = RHS::Target;

    fn path(&self) -> LensPath {
        LensPath::concat(self.lhs.path(), self.rhs.path())
    }

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

pub const BLA_COL_N: usize = 2 * FOO_COL_N + 4;

pub enum BlaColIndexer {
    SubFoo1(FooColIndexer),
    SubFoo2(FooColIndexer),
    Bla1(usize), // at most 2
    Bla2(usize), // at most 2
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

////////////////////////////////////////////////////////////////////////////
// Concrete lenses for our columns
////////////////////////////////////////////////////////////////////////////

pub struct BlaFoo1Lens {}

impl MGetter for BlaFoo1Lens {
    type Source = BlaColIndexer;
    type Target = FooColIndexer;

    fn path(&self) -> LensPath {
        LensPath::new(0)
    }

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

impl MGetter for BlaFoo2Lens {
    type Source = BlaColIndexer;
    type Target = FooColIndexer;

    fn path(&self) -> LensPath {
        LensPath::new(0)
    }

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

impl MGetter for KekBla1Lens {
    type Source = KekColIndexer;
    type Target = BlaColIndexer;

    fn path(&self) -> LensPath {
        LensPath::new(0)
    }

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

impl MGetter for KekFooComplexLens {
    type Source = KekColIndexer;
    type Target = FooColIndexer;

    fn path(&self) -> LensPath {
        LensPath::new(0)
    }

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

/// Attempt to define a generic interpreter.
/// It is not used yet.
pub trait InterpreterEnv<CIx: ColIndexer, F: PrimeField> {
    type Variable: Clone
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::fmt::Debug;

    fn assert_zero(&mut self, cst: Self::Variable);

    fn read_column(&self, ix: CIx) -> Self::Variable;

    fn constant(&self, value: F) -> Self::Variable;
}

pub struct SubInterpreter<
    'a,
    F: PrimeField,
    CIx1: ColIndexer,
    CIx2: ColIndexer,
    Env1: InterpreterEnv<CIx1, F>,
    L: MGetter<Source = CIx1, Target = CIx2>,
> {
    env: &'a mut Env1,
    lens: L,
    field_phantom: core::marker::PhantomData<F>,
}

impl<
        'a,
        F: PrimeField,
        CIx1: ColIndexer,
        CIx2: ColIndexer,
        Env1: InterpreterEnv<CIx1, F>,
        L: MGetter<Source = CIx1, Target = CIx2>,
    > SubInterpreter<'a, F, CIx1, CIx2, Env1, L>
{
    pub fn new(env: &'a mut Env1, lens: L) -> Self {
        SubInterpreter {
            env,
            lens,
            field_phantom: Default::default(),
        }
    }
}

impl<
        'a,
        F: PrimeField,
        CIx1: ColIndexer,
        CIx2: ColIndexer,
        Env1: InterpreterEnv<CIx1, F>,
        L: MGetter<Source = CIx1, Target = CIx2>,
    > InterpreterEnv<CIx2, F> for SubInterpreter<'a, F, CIx1, CIx2, Env1, L>
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

////////////////////////////////////////////////////////////////////////////
// Functions using interpreter env
////////////////////////////////////////////////////////////////////////////

pub fn constrain_foo<F, Env>(env: &mut Env) -> Env::Variable
where
    F: PrimeField,
    Env: InterpreterEnv<FooColIndexer, F>,
{
    let _a_var: Env::Variable = Env::read_column(env, FooColIndexer::Foo1(0));
    unimplemented!()
}

pub fn constrain_bla<F, Env>(env: &mut Env) -> Env::Variable
where
    F: PrimeField,
    Env: InterpreterEnv<BlaColIndexer, F>,
{
    let _a_var: Env::Variable = Env::read_column(env, BlaColIndexer::Bla1(0));
    constrain_foo(&mut SubInterpreter::new(env, BlaFoo1Lens {}));
    constrain_foo(&mut SubInterpreter::new(env, BlaFoo2Lens {}));
    unimplemented!()
}

pub fn constrain_kek<F, Env>(env: &mut Env) -> Env::Variable
where
    F: PrimeField,
    Env: InterpreterEnv<KekColIndexer, F>,
{
    let _a_var: Env::Variable = Env::read_column(env, KekColIndexer::Kek1(0));
    constrain_bla(&mut SubInterpreter::new(env, KekBla1Lens {}));
    constrain_foo(&mut SubInterpreter::new(
        env,
        compose(KekBla1Lens {}, BlaFoo1Lens {}),
    ));
    constrain_foo(&mut SubInterpreter::new(env, KekFooComplexLens {}));

    unimplemented!()
}
