use crate::{ffa::columns::FFAColumnIndexer, Ff1, LIMB_BITSIZE, N_LIMBS};
use ark_ff::{FpParameters, PrimeField, Zero};
use num_bigint::BigUint;
use num_integer::Integer;
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

    /// Checks |x| = 1, that is x ∈ {-1,0,1}
    fn range_check_abs1(&mut self, value: &Self::Variable);

    /// Checks input x ∈ [0,2^15)
    fn range_check_15bit(&mut self, value: &Self::Variable);

    /// In constraint environment does nothing (?). In witness environment progresses to the next row.
    fn next_row(&mut self);
}

fn limb_decompose_bui<F: PrimeField>(input: BigUint) -> [F; N_LIMBS] {
    let ff_el: ForeignElement<F, LIMB_BITSIZE, N_LIMBS> = ForeignElement::from_biguint(input);
    ff_el.limbs
}

// TODO use more foreign_field.rs with from/to bigint conversion
fn limb_decompose_ff<F: PrimeField, Ff: PrimeField>(input: &Ff) -> [F; N_LIMBS] {
    let input_bi: BigUint = FieldHelpers::to_biguint(input);
    limb_decompose_bui(input_bi)
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
    let a_limbs: [Env::Variable; N_LIMBS] = limb_decompose_ff(&a).map(Env::constant);
    let b_limbs: [Env::Variable; N_LIMBS] = limb_decompose_ff(&b).map(Env::constant);
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
    let a_limbs: [Env::Variable; N_LIMBS] = limb_decompose_ff(&a).map(Env::constant);
    let b_limbs: [Env::Variable; N_LIMBS] = limb_decompose_ff(&b).map(Env::constant);
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
/// Constraint for one row of FF addition:
///
/// - First:        a_0 + b_0 - q * f_0 - r_0 - c_0 * 2^{15} = 0
/// - Intermediate: a_i + b_i - q * f_i - r_i - c_i * 2^{15} + c_{i-1} = 0
/// - Last (n=16):  a_n + b_n - q * f_n - r_n                + c_{n-1} = 0
///
/// q, c_i ∈ {-1,0,1}
/// a_i, b_i, f_i, r_i ∈ [0,2^15)
pub fn constrain_ff_addition_row<F: PrimeField, Env: FFAInterpreterEnv<F>>(
    env: &mut Env,
    limb_num: usize,
) {
    let a: Env::Variable = Env::read_column(env, FFAColumnIndexer::InputA(limb_num));
    let b: Env::Variable = Env::read_column(env, FFAColumnIndexer::InputB(limb_num));
    let f: Env::Variable = Env::read_column(env, FFAColumnIndexer::ModulusF(limb_num));
    let r: Env::Variable = Env::read_column(env, FFAColumnIndexer::Remainder(limb_num));
    let q: Env::Variable = Env::read_column(env, FFAColumnIndexer::Quotient);
    env.range_check_15bit(&a);
    env.range_check_15bit(&b);
    env.range_check_15bit(&f);
    env.range_check_15bit(&r);
    env.range_check_abs1(&q);
    let constraint = if limb_num == 0 {
        let limb_size = Env::constant(From::from((1 << LIMB_BITSIZE) as u64));
        let c0: Env::Variable = Env::read_column(env, FFAColumnIndexer::Carry(limb_num));
        env.range_check_abs1(&c0);
        a + b - q * f - r - c0 * limb_size
    } else if limb_num < N_LIMBS - 1 {
        let limb_size = Env::constant(From::from((1 << LIMB_BITSIZE) as u64));
        let c_prev: Env::Variable = Env::read_column(env, FFAColumnIndexer::Carry(limb_num - 1));
        let c_cur: Env::Variable = Env::read_column(env, FFAColumnIndexer::Carry(limb_num));
        env.range_check_abs1(&c_prev);
        env.range_check_abs1(&c_cur);
        a + b - q * f - r - c_cur * limb_size + c_prev
    } else {
        let c_prev: Env::Variable = Env::read_column(env, FFAColumnIndexer::Carry(limb_num - 1));
        env.range_check_abs1(&c_prev);
        a + b - q * f - r + c_prev
    };
    env.assert_zero(constraint);
}

pub fn constrain_ff_addition<F: PrimeField, Env: FFAInterpreterEnv<F>>(env: &mut Env) {
    for limb_i in 0..N_LIMBS {
        constrain_ff_addition_row(env, limb_i);
    }
}

pub fn ff_addition_circuit<F: PrimeField, Ff: PrimeField, Env: FFAInterpreterEnv<F>>(
    env: &mut Env,
    a: Ff,
    b: Ff,
) {
    let f_bigint: BigUint = TryFrom::try_from(Ff::Params::MODULUS).unwrap();

    let a_limbs: [F; N_LIMBS] = limb_decompose_ff(&a);
    let b_limbs: [F; N_LIMBS] = limb_decompose_ff(&b);
    let f_limbs: [F; N_LIMBS] = limb_decompose_bui(f_bigint.clone());
    a_limbs.iter().enumerate().for_each(|(i, var)| {
        env.copy(
            &Env::constant(*var),
            Env::column_pos(FFAColumnIndexer::InputA(i)),
        );
    });
    b_limbs.iter().enumerate().for_each(|(i, var)| {
        env.copy(
            &Env::constant(*var),
            Env::column_pos(FFAColumnIndexer::InputB(i)),
        );
    });
    f_limbs.iter().enumerate().for_each(|(i, var)| {
        env.copy(
            &Env::constant(*var),
            Env::column_pos(FFAColumnIndexer::ModulusF(i)),
        );
    });

    let a_bigint = FieldHelpers::to_biguint(&a);
    let b_bigint = FieldHelpers::to_biguint(&b);

    // TODO FIXME this computation must be done over BigInts, not BigUInts
    // q can be -1! But only in subtraction, so for now we don't care.
    // for now with addition only q ∈ {0,1}
    let (q_bigint, r_bigint) = (a_bigint + b_bigint).div_rem(&f_bigint);
    let r_limbs: [F; N_LIMBS] = limb_decompose_bui(r_bigint);
    // We expect just one limb.
    let q: F = limb_decompose_bui(q_bigint)[0];

    env.copy(
        &Env::constant(q),
        Env::column_pos(FFAColumnIndexer::Quotient),
    );
    r_limbs.iter().enumerate().for_each(|(i, var)| {
        env.copy(
            &Env::constant(*var),
            Env::column_pos(FFAColumnIndexer::Remainder(i)),
        );
    });

    let limb_size: F = From::from((1 << LIMB_BITSIZE) as u64);
    let mut carry: F = From::from(0u64);
    for limb_i in 0..N_LIMBS {
        let res = a_limbs[limb_i] + b_limbs[limb_i] - q * f_limbs[limb_i] - r_limbs[limb_i] + carry;
        let newcarry: F = if res == limb_size {
            // Overflow
            F::one()
        } else if res == -limb_size {
            // Underflow
            F::zero() - F::one()
        } else if res.is_zero() {
            // Neither overflow nor overflow, the transcendent way of being
            F::zero()
        } else {
            panic!("Computed carry is not -1,0,1, impossible: limb number {limb_i:?}")
        };
        // Last carry should be zero, otherwise we record it
        if limb_i < N_LIMBS - 1 {
            env.copy(
                &Env::constant(newcarry),
                Env::column_pos(FFAColumnIndexer::Carry(limb_i)),
            );
            carry = newcarry;
        } else {
            // should this be in circiut?
            assert!(newcarry.is_zero());
        }
        constrain_ff_addition_row(env, limb_i);
    }
}
