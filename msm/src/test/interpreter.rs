use crate::{test::columns::TestColumnIndexer, Ff1, LIMB_BITSIZE, N_LIMBS};
use ark_ff::{PrimeField, Zero};
use num_bigint::BigUint;
use o1_utils::{field_helpers::FieldHelpers, foreign_field::ForeignElement};

pub trait TestInterpreterEnv<F: PrimeField> {
    type Position;

    type Variable: Clone
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::fmt::Debug;

    fn empty() -> Self;

    fn assert_zero(&mut self, cst: Self::Variable);

    fn copy(&mut self, x: &Self::Variable, position: Self::Position) -> Self::Variable;

    fn constant(value: F) -> Self::Variable;

    fn column_pos(ix: TestColumnIndexer) -> Self::Position;

    fn read_column(&self, ix: TestColumnIndexer) -> Self::Variable;
}

fn limb_decompose_bui<F: PrimeField>(input: BigUint) -> [F; N_LIMBS] {
    let ff_el: ForeignElement<F, LIMB_BITSIZE, N_LIMBS> = ForeignElement::from_biguint(input);
    ff_el.limbs
}

fn limb_decompose_ff<F: PrimeField, Ff: PrimeField>(input: &Ff) -> [F; N_LIMBS] {
    let input_bi: BigUint = FieldHelpers::to_biguint(input);
    limb_decompose_bui(input_bi)
}

fn fill_limbs_a_b<F: PrimeField, Env: TestInterpreterEnv<F>>(env: &mut Env, a: Ff1, b: Ff1) {
    let a_limbs: [Env::Variable; N_LIMBS] = limb_decompose_ff(&a).map(Env::constant);
    let b_limbs: [Env::Variable; N_LIMBS] = limb_decompose_ff(&b).map(Env::constant);
    a_limbs.iter().enumerate().for_each(|(i, var)| {
        env.copy(var, Env::column_pos(TestColumnIndexer::A(i)));
    });
    b_limbs.iter().enumerate().for_each(|(i, var)| {
        env.copy(var, Env::column_pos(TestColumnIndexer::B(i)));
    });
}

/// A consraint function for A + B - C that reads values from limbs A
/// and B, and additionally returns resulting value in C.
pub fn constrain_addition<F: PrimeField, Env: TestInterpreterEnv<F>>(
    env: &mut Env,
) -> [Env::Variable; N_LIMBS] {
    let a_limbs: [Env::Variable; N_LIMBS] =
        core::array::from_fn(|i| Env::read_column(env, TestColumnIndexer::A(i)));
    let b_limbs: [Env::Variable; N_LIMBS] =
        core::array::from_fn(|i| Env::read_column(env, TestColumnIndexer::B(i)));
    // fix cloning
    let c_limbs: [Env::Variable; N_LIMBS] =
        core::array::from_fn(|i| a_limbs[i].clone() + b_limbs[i].clone());
    c_limbs.iter().enumerate().for_each(|(i, var)| {
        env.copy(var, Env::column_pos(TestColumnIndexer::C(i)));
    });
    c_limbs
}

/// Circuit generator function for A + B - C, with D = 0.
pub fn test_addition<F: PrimeField, Env: TestInterpreterEnv<F>>(env: &mut Env, a: Ff1, b: Ff1) {
    fill_limbs_a_b(env, a, b);

    let _ = constrain_addition(env); // we don't do anything else further with c_limbs

    let d_limbs: [Env::Variable; N_LIMBS] = [Zero::zero(); N_LIMBS].map(Env::constant);
    d_limbs.iter().enumerate().for_each(|(i, var)| {
        env.copy(var, Env::column_pos(TestColumnIndexer::D(i)));
    });
}

/// A consraint function for A * B - D that reads values from limbs A
/// and B, and additionally returns resulting value in D.
pub fn constrain_multiplication<F: PrimeField, Env: TestInterpreterEnv<F>>(
    env: &mut Env,
) -> [Env::Variable; N_LIMBS] {
    let a_limbs: [Env::Variable; N_LIMBS] =
        core::array::from_fn(|i| Env::read_column(env, TestColumnIndexer::A(i)));
    let b_limbs: [Env::Variable; N_LIMBS] =
        core::array::from_fn(|i| Env::read_column(env, TestColumnIndexer::B(i)));
    // fix cloning
    let c_limbs: [Env::Variable; N_LIMBS] =
        core::array::from_fn(|i| a_limbs[i].clone() * b_limbs[i].clone());
    c_limbs.iter().enumerate().for_each(|(i, var)| {
        env.copy(var, Env::column_pos(TestColumnIndexer::C(i)));
    });
    c_limbs
}

/// Circuit generator function for A * B - D, with C = 0.
pub fn test_multiplication<F: PrimeField, Env: TestInterpreterEnv<F>>(
    env: &mut Env,
    a: Ff1,
    b: Ff1,
) {
    fill_limbs_a_b(env, a, b);

    let _ = constrain_multiplication(env); // we don't do anything else further with c_limbs

    let d_limbs: [Env::Variable; N_LIMBS] = [Zero::zero(); N_LIMBS].map(Env::constant);
    d_limbs.iter().enumerate().for_each(|(i, var)| {
        env.copy(var, Env::column_pos(TestColumnIndexer::D(i)));
    });
}
