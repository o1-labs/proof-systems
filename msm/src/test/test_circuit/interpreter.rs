use crate::{
    circuit_design::{ColAccessCap, ColWriteCap, DirectWitnessCap, LookupCap},
    test::test_circuit::{
        columns::{TestColumn, N_FSEL_TEST},
        lookups::LookupTable,
    },
    LIMB_BITSIZE, N_LIMBS,
};
use ark_ff::{Field, PrimeField, Zero};
use num_bigint::BigUint;

/// Decomposes a field element into limbs of the given bitsize.
/// This is a simplified version of the function that was in the serialization module.
fn limb_decompose_ff<F: PrimeField, Ff: PrimeField, const B: usize, const N: usize>(
    input: &Ff,
) -> [F; N] {
    let input_bi: BigUint = (*input).into();
    let ff_modulus: BigUint = Ff::MODULUS.into();
    assert!(
        input_bi < ff_modulus,
        "Input must be smaller than the field modulus"
    );
    let limb_mask = (BigUint::from(1u64) << B) - 1u64;
    core::array::from_fn(|i| {
        let limb = (&input_bi >> (i * B)) & &limb_mask;
        F::from(limb)
    })
}

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

/// A constraint function for A + B - C that reads values from limbs A
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

/// A constraint function for A * B - D that reads values from limbs A
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

/// A constraint function for A * B - D that reads values from limbs A
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

/// A constraint function for A_0 + B_0 - FIXED_SEL_1
pub fn constrain_test_fixed_sel<F: PrimeField, Env: ColAccessCap<F, TestColumn>>(env: &mut Env) {
    let a0 = Env::read_column(env, TestColumn::A(0));
    let b0 = Env::read_column(env, TestColumn::B(0));
    let fixed_e = Env::read_column(env, TestColumn::FixedSel1);
    let equation = a0.clone() + b0.clone() - fixed_e;
    env.assert_zero(equation.clone());
}

/// A constraint function for A_0^7 + B_0 - FIXED_SEL_1
pub fn constrain_test_fixed_sel_degree_7<F: PrimeField, Env: ColAccessCap<F, TestColumn>>(
    env: &mut Env,
) {
    let a0 = Env::read_column(env, TestColumn::A(0));
    let b0 = Env::read_column(env, TestColumn::B(0));
    let fixed_e = Env::read_column(env, TestColumn::FixedSel1);
    let a0_2 = a0.clone() * a0.clone();
    let a0_4 = a0_2.clone() * a0_2.clone();
    let a0_6 = a0_4.clone() * a0_2.clone();
    let a0_7 = a0_6.clone() * a0.clone();
    let equation = a0_7.clone() + b0.clone() - fixed_e;
    env.assert_zero(equation.clone());
}

/// A constraint function for 3 * A_0^7 + 42 * B_0 - FIXED_SEL_1
pub fn constrain_test_fixed_sel_degree_7_with_constants<
    F: PrimeField,
    Env: ColAccessCap<F, TestColumn>,
>(
    env: &mut Env,
) {
    let a0 = Env::read_column(env, TestColumn::A(0));
    let forty_two = Env::constant(F::from(42u32));
    let three = Env::constant(F::from(3u32));
    let b0 = Env::read_column(env, TestColumn::B(0));
    let fixed_e = Env::read_column(env, TestColumn::FixedSel1);
    let a0_2 = a0.clone() * a0.clone();
    let a0_4 = a0_2.clone() * a0_2.clone();
    let a0_6 = a0_4.clone() * a0_2.clone();
    let a0_7 = a0_6.clone() * a0.clone();
    let equation = three * a0_7.clone() + forty_two * b0.clone() - fixed_e;
    env.assert_zero(equation.clone());
}

// NB: Assumes non-standard selectors
/// A constraint function for 3 * A_0^7 + B_0 * FIXED_SEL_3
pub fn constrain_test_fixed_sel_degree_7_mul_witness<
    F: PrimeField,
    Env: ColAccessCap<F, TestColumn>,
>(
    env: &mut Env,
) {
    let a0 = Env::read_column(env, TestColumn::A(0));
    let three = Env::constant(F::from(3u32));
    let b0 = Env::read_column(env, TestColumn::B(0));
    let fixed_e = Env::read_column(env, TestColumn::FixedSel3);
    let a0_2 = a0.clone() * a0.clone();
    let a0_4 = a0_2.clone() * a0_2.clone();
    let a0_6 = a0_4.clone() * a0_2.clone();
    let a0_7 = a0_6.clone() * a0.clone();
    let equation = three * a0_7.clone() + b0.clone() * fixed_e;
    env.assert_zero(equation.clone());
}

/// Circuit generator function for A_0 + B_0 - FIXED_SEL_1.
pub fn test_fixed_sel<
    F: PrimeField,
    Env: ColAccessCap<F, TestColumn> + ColWriteCap<F, TestColumn>,
>(
    env: &mut Env,
    a: F,
) {
    env.write_column(TestColumn::A(0), &Env::constant(a));
    let fixed_e = env.read_column(TestColumn::FixedSel1);
    env.write_column(TestColumn::B(0), &(fixed_e - Env::constant(a)));

    constrain_test_fixed_sel(env);
}

/// Circuit generator function for A_0^7 + B_0 - FIXED_SEL_1.
pub fn test_fixed_sel_degree_7<
    F: PrimeField,
    Env: ColAccessCap<F, TestColumn> + ColWriteCap<F, TestColumn>,
>(
    env: &mut Env,
    a: F,
) {
    env.write_column(TestColumn::A(0), &Env::constant(a));
    let a_2 = a * a;
    let a_4 = a_2 * a_2;
    let a_6 = a_4 * a_2;
    let a_7 = a_6 * a;
    let fixed_e = env.read_column(TestColumn::FixedSel1);
    env.write_column(TestColumn::B(0), &(fixed_e - Env::constant(a_7)));
    constrain_test_fixed_sel_degree_7(env);
}

/// Circuit generator function for 3 * A_0^7 + 42 * B_0 - FIXED_SEL_1.
pub fn test_fixed_sel_degree_7_with_constants<
    F: PrimeField,
    Env: ColAccessCap<F, TestColumn> + ColWriteCap<F, TestColumn>,
>(
    env: &mut Env,
    a: F,
) {
    env.write_column(TestColumn::A(0), &Env::constant(a));
    let a_2 = a * a;
    let a_4 = a_2 * a_2;
    let a_6 = a_4 * a_2;
    let a_7 = a_6 * a;
    let fixed_e = env.read_column(TestColumn::FixedSel1);
    let inv_42 = F::from(42u32).inverse().unwrap();
    let three = F::from(3u32);
    env.write_column(
        TestColumn::B(0),
        &((fixed_e - Env::constant(three) * Env::constant(a_7)) * Env::constant(inv_42)),
    );
    constrain_test_fixed_sel_degree_7_with_constants(env);
}

// NB: Assumes non-standard selectors
/// Circuit generator function for 3 * A_0^7 + B_0 * FIXED_SEL_3.
pub fn test_fixed_sel_degree_7_mul_witness<
    F: PrimeField,
    Env: ColAccessCap<F, TestColumn> + ColWriteCap<F, TestColumn> + DirectWitnessCap<F, TestColumn>,
>(
    env: &mut Env,
    a: F,
) {
    env.write_column(TestColumn::A(0), &Env::constant(a));
    let a_2 = a * a;
    let a_4 = a_2 * a_2;
    let a_6 = a_4 * a_2;
    let a_7 = a_6 * a;
    let fixed_e = env.read_column(TestColumn::FixedSel3);
    let three = F::from(3u32);
    let val_fixed_e: F = Env::variable_to_field(fixed_e);
    let inv_fixed_e: F = val_fixed_e.inverse().unwrap();
    let res = -three * a_7 * inv_fixed_e;
    let res_var = Env::constant(res);
    env.write_column(TestColumn::B(0), &res_var);
    constrain_test_fixed_sel_degree_7_mul_witness(env);
}

pub fn constrain_lookups<
    F: PrimeField,
    Env: ColAccessCap<F, TestColumn> + LookupCap<F, TestColumn, LookupTable>,
>(
    env: &mut Env,
) {
    let a0 = Env::read_column(env, TestColumn::A(0));
    let a1 = Env::read_column(env, TestColumn::A(1));

    env.lookup(LookupTable::RangeCheck15, vec![a0.clone()]);
    env.lookup(LookupTable::RangeCheck15, vec![a1.clone()]);

    let cur_index = Env::read_column(env, TestColumn::FixedSel1);
    let prev_index = Env::read_column(env, TestColumn::FixedSel2);
    let next_index = Env::read_column(env, TestColumn::FixedSel3);

    env.lookup(
        LookupTable::RuntimeTable1,
        vec![
            cur_index.clone(),
            prev_index.clone(),
            next_index.clone(),
            Env::constant(F::from(4u64)),
        ],
    );

    // For now we only allow one read per runtime table with runtime_create_column = true.
    //env.lookup(LookupTable::RuntimeTable1, vec![a0.clone(), a1.clone()]);

    env.lookup_runtime_write(
        LookupTable::RuntimeTable2,
        vec![
            Env::constant(F::from(1u64 << 26)),
            Env::constant(F::from(5u64)),
        ],
    );
    env.lookup_runtime_write(
        LookupTable::RuntimeTable2,
        vec![cur_index, Env::constant(F::from(5u64))],
    );
    env.lookup(
        LookupTable::RuntimeTable2,
        vec![
            Env::constant(F::from(1u64 << 26)),
            Env::constant(F::from(5u64)),
        ],
    );
    env.lookup(
        LookupTable::RuntimeTable2,
        vec![prev_index, Env::constant(F::from(5u64))],
    );
}

pub fn lookups_circuit<
    F: PrimeField,
    Env: ColAccessCap<F, TestColumn>
        + ColWriteCap<F, TestColumn>
        + DirectWitnessCap<F, TestColumn>
        + LookupCap<F, TestColumn, LookupTable>,
>(
    env: &mut Env,
    domain_size: usize,
) {
    for row_i in 0..domain_size {
        env.write_column(TestColumn::A(0), &Env::constant(F::from(11u64)));
        env.write_column(TestColumn::A(1), &Env::constant(F::from(17u64)));

        constrain_lookups(env);

        if row_i < domain_size - 1 {
            env.next_row();
        }
    }
}

/// Fixed selectors for the test circuit.
pub fn build_fixed_selectors<F: Field>(domain_size: usize) -> Box<[Vec<F>; N_FSEL_TEST]> {
    // 0 1 2 3 4 ...
    let sel1 = (0..domain_size).map(|i| F::from(i as u64)).collect();
    // 0 0 1 2 3 4 ...
    let sel2 = (0..domain_size)
        .map(|i| {
            if i == 0 {
                F::zero()
            } else {
                F::from((i as u64) - 1)
            }
        })
        .collect();
    // 1 2 3 4 5 ...
    let sel3 = (0..domain_size).map(|i| F::from((i + 1) as u64)).collect();

    Box::new([sel1, sel2, sel3])
}
