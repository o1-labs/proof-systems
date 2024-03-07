use crate::{ffa::columns::FFAColumnIndexer, Ff1, LIMB_BITSIZE, N_LIMBS};
use ark_ff::{FpParameters, PrimeField, Zero};
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

fn limb_decompose_ff_modulus<F: PrimeField<BigInt = BigUint>, Ff: PrimeField>() -> [F; N_LIMBS] {
    let input_modulus_bi: BigUint = F::Params::MODULUS;
    let ff_el: ForeignElement<F, LIMB_BITSIZE, N_LIMBS> =
        ForeignElement::from_biguint(input_modulus_bi);
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

// For now this function does not /compute/ anything, although it could.
/// Constraint for one row of FF addition.
/// - First:        a_0 + b_0 - q * f_0 - r_0 - c_0 * 2^{15} = 0
/// - Intermediate: a_i + b_i - q * f_i - r_i - c_i * 2^{15} + c_{i-1} = 0
/// - Last (n=16):  a_n + b_n - q * f_n - r_n                + c_{n-1} = 0
pub fn constrain_ff_addition_row<F: PrimeField, Env: FFAInterpreterEnv<F>>(
    env: &mut Env,
    limb_num: usize,
) {
    let a: Env::Variable = Env::read_column(env, FFAColumnIndexer::InputA(limb_num));
    let b: Env::Variable = Env::read_column(env, FFAColumnIndexer::InputB(limb_num));
    let f: Env::Variable = Env::read_column(env, FFAColumnIndexer::ModulusF(limb_num));
    let q: Env::Variable = Env::read_column(env, FFAColumnIndexer::Quotient);
    let r: Env::Variable = Env::read_column(env, FFAColumnIndexer::Remainder(limb_num));
    let constraint = if limb_num == 0 {
        let limb_size = Env::constant(From::from((1 << LIMB_BITSIZE) as u64));
        let c0: Env::Variable = Env::read_column(env, FFAColumnIndexer::Carry(limb_num));
        a + b - q * f - r - c0 * limb_size
    } else if limb_num < N_LIMBS - 1 {
        let c_prev: Env::Variable = Env::read_column(env, FFAColumnIndexer::Carry(limb_num - 1));
        let c_cur: Env::Variable = Env::read_column(env, FFAColumnIndexer::Carry(limb_num));
        let limb_size = Env::constant(From::from((1 << LIMB_BITSIZE) as u64));
        a + b - q * f - r - c_cur * limb_size + c_prev
    } else {
        let c_prev: Env::Variable = Env::read_column(env, FFAColumnIndexer::Carry(limb_num - 1));
        a + b - q * f - r + c_prev
    };
    env.assert_zero(constraint);
}

pub fn ff_addition_circuit<F: PrimeField<BigInt = BigUint>, Env: FFAInterpreterEnv<F>>(
    env: &mut Env,
    a: Ff1,
    b: Ff1,
) {
    let a_limbs: [Env::Variable; N_LIMBS] = limb_decompose(&a).map(Env::constant);
    let b_limbs: [Env::Variable; N_LIMBS] = limb_decompose(&b).map(Env::constant);
    let f_limbs: [Env::Variable; N_LIMBS] =
        limb_decompose_ff_modulus::<F, Ff1>().map(Env::constant);
    a_limbs.iter().enumerate().for_each(|(i, var)| {
        env.copy(var, Env::column_pos(FFAColumnIndexer::InputA(i)));
    });
    b_limbs.iter().enumerate().for_each(|(i, var)| {
        env.copy(var, Env::column_pos(FFAColumnIndexer::InputB(i)));
    });
    f_limbs.iter().enumerate().for_each(|(i, var)| {
        env.copy(var, Env::column_pos(FFAColumnIndexer::ModulusF(i)));
    });

    for limb_i in 0..N_LIMBS {
        // TODO Insert computations of q / r / c
        constrain_ff_addition_row(env, limb_i);
    }
}
