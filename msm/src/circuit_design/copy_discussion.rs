use crate::{
    circuit_design::{ColAccessCap, ColWriteCap},
    columns::{Column, ColumnIndexer},
    N_LIMBS,
};
use ark_ff::PrimeField;

////////////////////////////////////////////////////////////////////////////
// Step 1: Addition (a + b - c) with just write/read
////////////////////////////////////////////////////////////////////////////

/// Number of columns in the test circuits.
pub const N_COLUMNS: usize = 4 * N_LIMBS;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MyColumn {
    A,
    B,
    C,
}

impl ColumnIndexer for MyColumn {
    const COL_N: usize = N_COLUMNS;
    fn to_column(self) -> Column {
        match self {
            MyColumn::A => Column::X(0),
            MyColumn::B => Column::X(1),
            MyColumn::C => Column::X(2),
        }
    }
}

pub fn constrain_addition1<F: PrimeField, Env: ColAccessCap<F, MyColumn>>(env: &mut Env) {
    let a = Env::read_column(env, MyColumn::A);
    let b = Env::read_column(env, MyColumn::B);
    let c = Env::read_column(env, MyColumn::C);
    env.assert_zero(a + b - c);
}

fn fill_a_b1<F: PrimeField, Env: ColAccessCap<F, MyColumn> + ColWriteCap<F, MyColumn>>(
    env: &mut Env,
    a: F,
    b: F,
) {
    env.write_column(MyColumn::A, &Env::constant(a));
    env.write_column(MyColumn::B, &Env::constant(b));
}

pub fn test_addition1<F: PrimeField, Env: ColAccessCap<F, MyColumn> + ColWriteCap<F, MyColumn>>(
    env: &mut Env,
    a: F,
    b: F,
) {
    fill_a_b1(env, a, b);
    env.write_column(MyColumn::C, &Env::constant(a + b));
    constrain_addition1(env);
}

////////////////////////////////////////////////////////////////////////////
// Step 2: Problem. Assume we also want to compute smth.
////////////////////////////////////////////////////////////////////////////

// Bad function. It will correctly generate a /constraint/, but it will fail in the witness mode.
pub fn constrain_addition2<F: PrimeField, Env: ColAccessCap<F, MyColumn>>(
    env: &mut Env,
) -> <Env as ColAccessCap<F, MyColumn>>::Variable {
    let a = Env::read_column(env, MyColumn::A);
    let b = Env::read_column(env, MyColumn::B);
    let c = Env::read_column(env, MyColumn::C);
    env.assert_zero(a + b - c.clone());
    c
}

// Bad function. This will fail, because the column c is written after
// assert_zero is executed. So in the witness mode assert_zero will
// fail since C = 0 at that point.
pub fn test_addition2<F: PrimeField, Env: ColAccessCap<F, MyColumn> + ColWriteCap<F, MyColumn>>(
    env: &mut Env,
    a: F,
    b: F,
) {
    fill_a_b1(env, a, b);
    let c = constrain_addition2(env);
    env.write_column(MyColumn::C, &c);
}

////////////////////////////////////////////////////////////////////////////
// Step 3: So we kind of want to have Copy, right?
////////////////////////////////////////////////////////////////////////////

pub trait ColCopyCap<F: PrimeField, CIx: ColumnIndexer>
where
    Self: ColAccessCap<F, CIx>,
{
    fn copy(&mut self, x: &Self::Variable, position: CIx) -> Self::Variable;
}

// This behaves /exactly the same/ in the constraint mode. But
// differently in the witness mode.
pub fn constrain_addition3<F: PrimeField, Env: ColCopyCap<F, MyColumn>>(
    env: &mut Env,
) -> <Env as ColAccessCap<F, MyColumn>>::Variable {
    let a = Env::read_column(env, MyColumn::A);
    let b = Env::read_column(env, MyColumn::B);
    env.copy(&(a + b), MyColumn::C)
}

// Unlike test_addition2, this will not fail, because
// constrain_addition3 is will write column C at the same time.
pub fn test_addition3<F: PrimeField, Env: ColAccessCap<F, MyColumn> + ColWriteCap<F, MyColumn>>(
    env: &mut Env,
    a: F,
    b: F,
) {
    fill_a_b1(env, a, b);
    let _c = constrain_addition2(env);
    // we can do something /else/ with c now
}

////////////////////////////////////////////////////////////////////////////
// Step 4: So what's the problem?
////////////////////////////////////////////////////////////////////////////

// It's definitional. The names "copy" and "write" seem to live in the
// same semantic space, but with our definitions they are not. In
// fact, our copy is "maybe copy", which lives in the same semantic
// space with "maybe write", where "maybe write" is ... writing in the
// witness case but is not writing in the constraint case.
//
//
// 1. Intuitively, the name "copy" implies that
// write is always happening. So we would expect to be able to
// implement write_column using copy. However this is just not true.
// If we do it, then write_column for ConstraintBuilderEnv will not
// write any columns at all. We want our write_column to be /always/
// factually writing, and to be /only/ available for the witness_env.
//
// 2. The name "copy" seems to imply that we can implement it using write.
//
// We would do it like this: Copy(x,pos) = { write_column(x,pos); assert_zero(x - read_column(pos)) }
//
// But simultaneosly, write_column is not implemented for
// ConstraintBuilderEnv! So on one hand, for the WitnessBuilderEnv,
// copy is "equal or above" and thus must not be available for ConstraintBuilderEnv since ConstraintBuilderEnv is strictly weaker, but on the other hand for ConstraintBuilderEnv we do implement it.
//
// Solution: rename copy. link, passthrough, sync, mcopy (maybe copy? as in mwrite), hybrid, hcopy?
//
//
// What traits do we want? What kind of circuit builder environments do we have?
// 1. Read only.
//    - Constraints where we only assert stuff. It generally does not make sense to compute
//      anything at this level. E.g. constrain_addition1.
// 2. Hybrid arithmetic compute (hybrid copy).
//    - Functions that depend on Variable and can compute arithmetic operations along the way.
// 3. Hybrid non-arithmetic: Arithmetic compute (mcopy) + non-arithmetic compute via hacks
//    - @volhovm I dislike this and think we should generally not have
//      this. Example is bitmask_be: it does nontrivial Field-level (not
//      variable-level! so it can operate on bits, bitmaps, any general
//      computation) operations, but is available for constraint builder
//      by providing "no-op" trait implementaiton.
//    - The allure of this is that you can write e.g. one implementation
//      of F(X), say a hash function, that takes x, and generates you both
//      constraints and
//    - The downside is that (1) verifier does not have any witness, so it
//      will have to pass some "fake" x0 to get constraints, (2) not all the
//      functions allow this, e.g. one should be careful with branching not
//      to generate different constraints based on x0, (3) it makes interfaces
//      non-intuitive. If an interface says it writes something, it should write
//      something; maybe a different naming convention ("opt write") can alleviate
//      this.
//    - One can instead write the same code using ColWriteCap and write
//      into columns separately. It's much more clean. In this case, certain duplication
//      (witness generation + constraint generation) is almost beneficial because
//      it increases confidence in that we didn't make the same bug twice.
// 4. Write and non-arithmetic compute
//    - Functions that depend on F, compute in F, and write columns
//    - This environment is only available for the witness builder.
//      From this environment we can still call the previous ones,
//      where asserts will be doing computational asserts.
//    - E.g. our test_addition1.
