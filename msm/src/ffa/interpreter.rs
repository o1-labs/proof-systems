use crate::{
    circuit_design::{ColAccessCap, ColWriteCap, LookupCap},
    ffa::{columns::FFAColumn, lookups::LookupTable},
    serialization::interpreter::{limb_decompose_biguint, limb_decompose_ff},
    LIMB_BITSIZE, N_LIMBS,
};
use ark_ff::{FpParameters, PrimeField};
use num_bigint::BigUint;
use num_integer::Integer;
use o1_utils::field_helpers::FieldHelpers;

// For now this function does not /compute/ anything, although it could.
/// Constraint for one row of FF addition:
///
/// - First:        a_0 + b_0 - q * f_0 - r_0 - c_0 * 2^{15} = 0
/// - Intermediate: a_i + b_i - q * f_i - r_i - c_i * 2^{15} + c_{i-1} = 0
/// - Last (n=16):  a_n + b_n - q * f_n - r_n                + c_{n-1} = 0
///
/// q, c_i ∈ {-1,0,1}
/// a_i, b_i, f_i, r_i ∈ [0,2^15)
pub fn constrain_ff_addition_row<
    F: PrimeField,
    Env: ColAccessCap<F, FFAColumn> + LookupCap<F, FFAColumn, LookupTable>,
>(
    env: &mut Env,
    limb_num: usize,
) {
    let a: Env::Variable = Env::read_column(env, FFAColumn::InputA(limb_num));
    let b: Env::Variable = Env::read_column(env, FFAColumn::InputB(limb_num));
    let f: Env::Variable = Env::read_column(env, FFAColumn::ModulusF(limb_num));
    let r: Env::Variable = Env::read_column(env, FFAColumn::Remainder(limb_num));
    let q: Env::Variable = Env::read_column(env, FFAColumn::Quotient);
    env.lookup(LookupTable::RangeCheck15, &a);
    env.lookup(LookupTable::RangeCheck15, &b);
    env.lookup(LookupTable::RangeCheck15, &f);
    env.lookup(LookupTable::RangeCheck15, &r);
    env.lookup(LookupTable::RangeCheck1BitSigned, &q);
    let constraint = if limb_num == 0 {
        let limb_size = Env::constant(From::from((1 << LIMB_BITSIZE) as u64));
        let c0: Env::Variable = Env::read_column(env, FFAColumn::Carry(limb_num));
        env.lookup(LookupTable::RangeCheck1BitSigned, &c0);
        a + b - q * f - r - c0 * limb_size
    } else if limb_num < N_LIMBS - 1 {
        let limb_size = Env::constant(From::from((1 << LIMB_BITSIZE) as u64));
        let c_prev: Env::Variable = Env::read_column(env, FFAColumn::Carry(limb_num - 1));
        let c_cur: Env::Variable = Env::read_column(env, FFAColumn::Carry(limb_num));
        env.lookup(LookupTable::RangeCheck1BitSigned, &c_prev);
        env.lookup(LookupTable::RangeCheck1BitSigned, &c_cur);
        a + b - q * f - r - c_cur * limb_size + c_prev
    } else {
        let c_prev: Env::Variable = Env::read_column(env, FFAColumn::Carry(limb_num - 1));
        env.lookup(LookupTable::RangeCheck1BitSigned, &c_prev);
        a + b - q * f - r + c_prev
    };
    env.assert_zero(constraint);
}

pub fn constrain_ff_addition<
    F: PrimeField,
    Env: ColAccessCap<F, FFAColumn> + LookupCap<F, FFAColumn, LookupTable>,
>(
    env: &mut Env,
) {
    for limb_i in 0..N_LIMBS {
        constrain_ff_addition_row(env, limb_i);
    }
}

pub fn ff_addition_circuit<
    F: PrimeField,
    Ff: PrimeField,
    Env: ColAccessCap<F, FFAColumn> + ColWriteCap<F, FFAColumn> + LookupCap<F, FFAColumn, LookupTable>,
>(
    env: &mut Env,
    a: Ff,
    b: Ff,
) {
    let f_bigint: BigUint = TryFrom::try_from(Ff::Params::MODULUS).unwrap();

    let a_limbs: [F; N_LIMBS] = limb_decompose_ff::<F, Ff, LIMB_BITSIZE, N_LIMBS>(&a);
    let b_limbs: [F; N_LIMBS] = limb_decompose_ff::<F, Ff, LIMB_BITSIZE, N_LIMBS>(&b);
    let f_limbs: [F; N_LIMBS] =
        limb_decompose_biguint::<F, LIMB_BITSIZE, N_LIMBS>(f_bigint.clone());
    a_limbs.iter().enumerate().for_each(|(i, var)| {
        env.write_column(FFAColumn::InputA(i), &Env::constant(*var));
    });
    b_limbs.iter().enumerate().for_each(|(i, var)| {
        env.write_column(FFAColumn::InputB(i), &Env::constant(*var));
    });
    f_limbs.iter().enumerate().for_each(|(i, var)| {
        env.write_column(FFAColumn::ModulusF(i), &Env::constant(*var));
    });

    let a_bigint = FieldHelpers::to_biguint(&a);
    let b_bigint = FieldHelpers::to_biguint(&b);

    // TODO FIXME this computation must be done over BigInts, not BigUInts
    // q can be -1! But only in subtraction, so for now we don't care.
    // for now with addition only q ∈ {0,1}
    let (q_bigint, r_bigint) = (a_bigint + b_bigint).div_rem(&f_bigint);
    let r_limbs: [F; N_LIMBS] = limb_decompose_biguint::<F, LIMB_BITSIZE, N_LIMBS>(r_bigint);
    // We expect just one limb.
    let q: F = limb_decompose_biguint::<F, LIMB_BITSIZE, N_LIMBS>(q_bigint)[0];

    env.write_column(FFAColumn::Quotient, &Env::constant(q));
    r_limbs.iter().enumerate().for_each(|(i, var)| {
        env.write_column(FFAColumn::Remainder(i), &Env::constant(*var));
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
            env.write_column(FFAColumn::Carry(limb_i), &Env::constant(newcarry));
            carry = newcarry;
        } else {
            // should this be in circiut?
            assert!(newcarry.is_zero());
        }
        constrain_ff_addition_row(env, limb_i);
    }
}
