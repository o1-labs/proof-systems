use crate::{ffa::columns::FFAColumnIndexer, Ff1, LIMB_BITSIZE, N_LIMBS};
use ark_ff::{PrimeField, Zero};
use num_bigint::BigUint;
use o1_utils::{field_helpers::FieldHelpers, foreign_field::ForeignElement};

pub trait FFAInterpreterEnv<F: PrimeField> {
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

    fn column_pos(ix: FFAColumnIndexer) -> Self::Position;

    fn read_column(&self, ix: FFAColumnIndexer) -> Self::Variable;

    /// In constraint environment does nothing (?). In witness environment progresses to the next row.
    fn next_row(&mut self);
}

// TODO use more foreign_field.rs with from/to bigint conversion
fn limb_decompose<F: PrimeField>(input: &Ff1) -> [F; N_LIMBS] {
    let input_bi: BigUint = FieldHelpers::to_biguint(input);
    let ff_el: ForeignElement<F, LIMB_BITSIZE, N_LIMBS> = ForeignElement::from_biguint(input_bi);
    ff_el.limbs
}

/// Reads values from limbs A and B, returns resulting value in C.
pub fn constrain_multiplication<F: PrimeField, Env: FFAInterpreterEnv<F>>(
    env: &mut Env,
) -> [Env::Variable; N_LIMBS] {
    let a_limbs: [Env::Variable; N_LIMBS] =
        core::array::from_fn(|i| Env::read_column(env, FFAColumnIndexer::A(i)));
    let b_limbs: [Env::Variable; N_LIMBS] =
        core::array::from_fn(|i| Env::read_column(env, FFAColumnIndexer::B(i)));
    // fix cloning
    let c_limbs: [Env::Variable; N_LIMBS] =
        core::array::from_fn(|i| a_limbs[i].clone() * b_limbs[i].clone());
    c_limbs.iter().enumerate().for_each(|(i, var)| {
        env.copy(var, Env::column_pos(FFAColumnIndexer::C(i)));
    });
    c_limbs
}

pub fn test_multiplication<F: PrimeField, Env: FFAInterpreterEnv<F>>(
    env: &mut Env,
    a: Ff1,
    b: Ff1,
) {
    let a_limbs: [Env::Variable; N_LIMBS] = limb_decompose(&a).map(Env::constant);
    let b_limbs: [Env::Variable; N_LIMBS] = limb_decompose(&b).map(Env::constant);
    a_limbs.iter().enumerate().for_each(|(i, var)| {
        env.copy(var, Env::column_pos(FFAColumnIndexer::A(i)));
    });
    b_limbs.iter().enumerate().for_each(|(i, var)| {
        env.copy(var, Env::column_pos(FFAColumnIndexer::B(i)));
    });

    let _ = constrain_multiplication(env); // we don't do anything else further with c_limbs

    let d_limbs: [Env::Variable; N_LIMBS] = [Zero::zero(); N_LIMBS].map(Env::constant);
    d_limbs.iter().enumerate().for_each(|(i, var)| {
        env.copy(var, Env::column_pos(FFAColumnIndexer::D(i)));
    });
}

/// Reads values from limbs A and B, returns resulting value in C.
pub fn constrain_addition<F: PrimeField, Env: FFAInterpreterEnv<F>>(
    env: &mut Env,
) -> [Env::Variable; N_LIMBS] {
    let a_limbs: [Env::Variable; N_LIMBS] =
        core::array::from_fn(|i| Env::read_column(env, FFAColumnIndexer::A(i)));
    let b_limbs: [Env::Variable; N_LIMBS] =
        core::array::from_fn(|i| Env::read_column(env, FFAColumnIndexer::B(i)));
    // fix cloning
    let c_limbs: [Env::Variable; N_LIMBS] =
        core::array::from_fn(|i| a_limbs[i].clone() + b_limbs[i].clone());
    c_limbs.iter().enumerate().for_each(|(i, var)| {
        env.copy(var, Env::column_pos(FFAColumnIndexer::C(i)));
    });
    c_limbs
}

pub fn test_addition<F: PrimeField, Env: FFAInterpreterEnv<F>>(env: &mut Env, a: Ff1, b: Ff1) {
    let a_limbs: [Env::Variable; N_LIMBS] = limb_decompose(&a).map(Env::constant);
    let b_limbs: [Env::Variable; N_LIMBS] = limb_decompose(&b).map(Env::constant);
    a_limbs.iter().enumerate().for_each(|(i, var)| {
        env.copy(var, Env::column_pos(FFAColumnIndexer::A(i)));
    });
    b_limbs.iter().enumerate().for_each(|(i, var)| {
        env.copy(var, Env::column_pos(FFAColumnIndexer::B(i)));
    });

    let _ = constrain_addition(env); // we don't do anything else further with c_limbs

    let d_limbs: [Env::Variable; N_LIMBS] = [Zero::zero(); N_LIMBS].map(Env::constant);
    d_limbs.iter().enumerate().for_each(|(i, var)| {
        env.copy(var, Env::column_pos(FFAColumnIndexer::D(i)));
    });
}
