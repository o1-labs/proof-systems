use crate::{
    circuit_design::{ColAccessCap, ColWriteCap},
    serialization::interpreter::limb_decompose_ff,
    test::columns::TestColumn,
    LIMB_BITSIZE, N_LIMBS,
};
use ark_ff::{PrimeField, Zero};

fn fill_limbs_a_b<
    F: PrimeField,
    Ff: PrimeField,
    Env: ColAccessCap<F, TestColumn> + ColWriteCap<F, TestColumn>,
>(
    env: &mut Env,
    a: Ff,
    b: Ff,
) -> ([Env::Variable; N_LIMBS], [Env::Variable; N_LIMBS]) {
    let a_limbs: [Env::Variable; N_LIMBS] =
        limb_decompose_ff::<F, Ff, LIMB_BITSIZE, N_LIMBS>(&a).map(Env::constant);
    let b_limbs: [Env::Variable; N_LIMBS] =
        limb_decompose_ff::<F, Ff, LIMB_BITSIZE, N_LIMBS>(&b).map(Env::constant);
    a_limbs.iter().enumerate().for_each(|(i, var)| {
        env.write_column(TestColumn::A(i), var);
    });
    b_limbs.iter().enumerate().for_each(|(i, var)| {
        env.write_column(TestColumn::B(i), var);
    });
    (a_limbs, b_limbs)
}

/// A consraint function for A + B - C that reads values from limbs A
/// and B, and additionally returns resulting value in C.
pub fn constrain_addition<F: PrimeField, Env: ColAccessCap<F, TestColumn>>(env: &mut Env) {
    let a_limbs: [Env::Variable; N_LIMBS] =
        core::array::from_fn(|i| Env::read_column(env, TestColumn::A(i)));
    let b_limbs: [Env::Variable; N_LIMBS] =
        core::array::from_fn(|i| Env::read_column(env, TestColumn::B(i)));
    // fix cloning
    let c_limbs: [Env::Variable; N_LIMBS] =
        core::array::from_fn(|i| Env::read_column(env, TestColumn::C(i)));
    let equation: [Env::Variable; N_LIMBS] =
        core::array::from_fn(|i| a_limbs[i].clone() * b_limbs[i].clone() - c_limbs[i].clone());
    equation.iter().for_each(|var| {
        env.assert_zero(var.clone());
    });
}

/// Circuit generator function for A + B - C, with D = 0.
pub fn test_addition<
    F: PrimeField,
    Ff: PrimeField,
    Env: ColAccessCap<F, TestColumn> + ColWriteCap<F, TestColumn>,
>(
    env: &mut Env,
    a: Ff,
    b: Ff,
) {
    let (a_limbs, b_limbs) = fill_limbs_a_b(env, a, b);

    (0..N_LIMBS).for_each(|i| {
        env.write_column(TestColumn::C(i), &(a_limbs[i].clone() + b_limbs[i].clone()));
        env.write_column(TestColumn::D(i), &Env::constant(Zero::zero()));
    });

    constrain_addition(env);
}

/// A consraint function for A * B - D that reads values from limbs A
/// and B, and multiplicationally returns resulting value in D.
pub fn constrain_multiplication<F: PrimeField, Env: ColAccessCap<F, TestColumn>>(env: &mut Env) {
    let a_limbs: [Env::Variable; N_LIMBS] =
        core::array::from_fn(|i| Env::read_column(env, TestColumn::A(i)));
    let b_limbs: [Env::Variable; N_LIMBS] =
        core::array::from_fn(|i| Env::read_column(env, TestColumn::B(i)));
    // fix cloning
    let d_limbs: [Env::Variable; N_LIMBS] =
        core::array::from_fn(|i| Env::read_column(env, TestColumn::D(i)));
    let equation: [Env::Variable; N_LIMBS] =
        core::array::from_fn(|i| a_limbs[i].clone() * b_limbs[i].clone() - d_limbs[i].clone());
    equation.iter().for_each(|var| {
        env.assert_zero(var.clone());
    });
}

/// Circuit generator function for A * B - C, with D = 0.
pub fn test_multiplication<
    F: PrimeField,
    Ff: PrimeField,
    Env: ColAccessCap<F, TestColumn> + ColWriteCap<F, TestColumn>,
>(
    env: &mut Env,
    a: Ff,
    b: Ff,
) {
    let (a_limbs, b_limbs) = fill_limbs_a_b(env, a, b);

    (0..N_LIMBS).for_each(|i| {
        env.write_column(TestColumn::D(i), &(a_limbs[i].clone() * b_limbs[i].clone()));
        env.write_column(TestColumn::C(i), &Env::constant(Zero::zero()));
    });

    constrain_multiplication(env);
}

/// A consraint function for A * B - D that reads values from limbs A
/// and B, and multiplication_constally returns resulting value in D.
pub fn constrain_test_const<F: PrimeField, Env: ColAccessCap<F, TestColumn>>(
    env: &mut Env,
    constant: F,
) {
    let a0 = Env::read_column(env, TestColumn::A(0));
    let b0 = Env::read_column(env, TestColumn::B(0));
    let equation = a0.clone() * b0.clone() - Env::constant(constant);
    env.assert_zero(equation.clone());
}

/// Circuit generator function for A_0 * B_0 - const, with every other column = 0
pub fn test_const<F: PrimeField, Env: ColAccessCap<F, TestColumn> + ColWriteCap<F, TestColumn>>(
    env: &mut Env,
    a: F,
    b: F,
    constant: F,
) {
    env.write_column(TestColumn::A(0), &Env::constant(a));
    env.write_column(TestColumn::B(0), &Env::constant(b));

    constrain_test_const(env, constant);
}

/// A consraint function for A_0 + B_0 - FIXED_E
pub fn constrain_test_fixed_sel<F: PrimeField, Env: ColAccessCap<F, TestColumn>>(env: &mut Env) {
    let a0 = Env::read_column(env, TestColumn::A(0));
    let b0 = Env::read_column(env, TestColumn::B(0));
    let fixed_e = Env::read_column(env, TestColumn::FixedE);
    let equation = a0.clone() + b0.clone() - fixed_e;
    env.assert_zero(equation.clone());
}

/// Circuit generator function for A_0 + B_0 - FIXED_E.
pub fn test_fixed_sel<
    F: PrimeField,
    Env: ColAccessCap<F, TestColumn> + ColWriteCap<F, TestColumn>,
>(
    env: &mut Env,
    a: F,
) {
    env.write_column(TestColumn::A(0), &Env::constant(a));
    let fixed_e = env.read_column(TestColumn::FixedE);
    env.write_column(TestColumn::B(0), &(fixed_e - Env::constant(a)));

    constrain_test_fixed_sel(env);
}
