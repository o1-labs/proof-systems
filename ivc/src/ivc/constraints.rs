use super::{
    columns::{IVCColumn, IVCHashLens, N_BLOCKS},
    helpers::{combine_large_to_xlarge, combine_small_to_full},
    lookups::{IVCFECLookupLens, IVCLookupTable},
    N_LIMBS_XLARGE,
};

use crate::poseidon_8_56_5_3_2::bn254::PoseidonBN254Parameters;

use crate::{ivc::columns::IVCFECLens, poseidon_8_56_5_3_2};
use ark_ff::PrimeField;
use kimchi_msm::{
    circuit_design::{
        capabilities::read_column_array,
        composition::{SubEnvColumn, SubEnvLookup},
        ColAccessCap, HybridCopyCap, LookupCap,
    },
    fec::{columns::FECColumnOutput, interpreter::constrain_ec_addition},
    serialization::{
        interpreter::{combine_small_to_large, N_LIMBS_LARGE, N_LIMBS_SMALL},
        lookups as serlookup,
    },
    Fp,
};
use std::marker::PhantomData;

fn range_check_scalar_limbs<F, Ff, Env>(
    env: &mut Env,
    input_limbs_small: &[Env::Variable; N_LIMBS_SMALL],
) where
    F: PrimeField,
    Ff: PrimeField,
    Env: ColAccessCap<F, IVCColumn> + LookupCap<F, IVCColumn, IVCLookupTable<Ff>>,
{
    for (i, x) in input_limbs_small.iter().enumerate() {
        if i % N_LIMBS_SMALL == N_LIMBS_SMALL - 1 {
            // If it's the highest limb, we need to check that it's representing a field
            // element.
            env.lookup(
                IVCLookupTable::SerLookupTable(serlookup::LookupTable::RangeCheckFfHighest(
                    PhantomData,
                )),
                vec![x.clone()],
            );
        } else {
            // TODO Add this lookup.
            // env.lookup(IVCLookupTable::RangeCheckFHighest, x);
        }
    }
}

fn range_check_small_limbs<F, Ff, Env>(
    env: &mut Env,
    input_limbs_small: &[Env::Variable; N_LIMBS_SMALL],
) where
    F: PrimeField,
    Ff: PrimeField,
    Env: ColAccessCap<F, IVCColumn> + LookupCap<F, IVCColumn, IVCLookupTable<Ff>>,
{
    for (i, x) in input_limbs_small.iter().enumerate() {
        if i % N_LIMBS_SMALL == N_LIMBS_SMALL - 1 {
            // If it's the highest limb, we need to check that it's representing a field
            // element.
            env.lookup(
                IVCLookupTable::SerLookupTable(serlookup::LookupTable::RangeCheckFfHighest(
                    PhantomData,
                )),
                vec![x.clone()],
            );
        } else {
            env.lookup(
                IVCLookupTable::SerLookupTable(serlookup::LookupTable::RangeCheck15),
                vec![x.clone()],
            );
        }
    }
}

/// Constraints for the inputs block.
pub fn constrain_inputs<F, Ff, Env>(env: &mut Env)
where
    F: PrimeField,
    Ff: PrimeField,
    Env: ColAccessCap<F, IVCColumn> + LookupCap<F, IVCColumn, IVCLookupTable<Ff>>,
{
    let input_limbs_small_x: [_; N_LIMBS_SMALL] = read_column_array(env, IVCColumn::Block1Input);
    let input_limbs_small_y: [_; N_LIMBS_SMALL] =
        read_column_array(env, |x| IVCColumn::Block1Input(N_LIMBS_SMALL + x));
    // Range checks on 15 bits
    {
        range_check_small_limbs::<F, Ff, Env>(env, &input_limbs_small_x);
        range_check_small_limbs::<F, Ff, Env>(env, &input_limbs_small_y);
    }

    let input_limbs_large_x: [_; N_LIMBS_LARGE] =
        read_column_array(env, IVCColumn::Block1InputRepacked75);
    let input_limbs_large_y: [_; N_LIMBS_LARGE] =
        read_column_array(env, |x| IVCColumn::Block1InputRepacked75(N_LIMBS_LARGE + x));

    // Repacking to 75 bits
    {
        let input_limbs_large_x_expected =
            combine_small_to_large::<_, _, Env>(input_limbs_small_x.clone());
        let input_limbs_large_y_expected =
            combine_small_to_large::<_, _, Env>(input_limbs_small_y.clone());
        input_limbs_large_x_expected
            .into_iter()
            .zip(input_limbs_large_x.clone())
            .for_each(|(e1, e2)| env.assert_zero(e1 - e2));
        input_limbs_large_y_expected
            .into_iter()
            .zip(input_limbs_large_y.clone())
            .for_each(|(e1, e2)| env.assert_zero(e1 - e2));
    }

    let input_limbs_xlarge_x: [_; N_LIMBS_XLARGE] =
        read_column_array(env, IVCColumn::Block1InputRepacked150);
    let input_limbs_xlarge_y: [_; N_LIMBS_XLARGE] = read_column_array(env, |x| {
        IVCColumn::Block1InputRepacked150(N_LIMBS_XLARGE + x)
    });

    // Repacking to 150 bits
    {
        let input_limbs_xlarge_x_expected =
            combine_large_to_xlarge::<_, _, Env>(input_limbs_large_x.clone());
        let input_limbs_xlarge_y_expected =
            combine_large_to_xlarge::<_, _, Env>(input_limbs_large_y.clone());
        input_limbs_xlarge_x_expected
            .into_iter()
            .zip(input_limbs_xlarge_x.clone())
            .for_each(|(e1, e2)| env.assert_zero(e1 - e2));
        input_limbs_xlarge_y_expected
            .into_iter()
            .zip(input_limbs_xlarge_y.clone())
            .for_each(|(e1, e2)| env.assert_zero(e1 - e2));
    }
}

pub fn constrain_u<F, Env>(env: &mut Env)
where
    F: PrimeField,
    Env: ColAccessCap<F, IVCColumn>,
{
    // TODO constrain that r is read from the "hashes" block.
    // TODO constrain that the inputs are corresponding to public input (?).

    let r = env.read_column(IVCColumn::Block6ConstR);
    let u_l = env.read_column(IVCColumn::Block6ULeft);
    let u_o = env.read_column(IVCColumn::Block6UOutput);
    env.assert_zero(u_o - u_l - r);
}

pub fn constrain_challenges<F, Env>(env: &mut Env)
where
    F: PrimeField,
    Env: ColAccessCap<F, IVCColumn>,
{
    let _h_r = env.read_column(IVCColumn::Block5ConstHr);

    let r = env.read_column(IVCColumn::Block5ConstR);
    let alpha_l = env.read_column(IVCColumn::Block5ChalLeft);
    let alpha_r = env.read_column(IVCColumn::Block5ChalRight);
    let alpha_o = env.read_column(IVCColumn::Block5ChalOutput);
    env.assert_zero(alpha_o - alpha_l - r * alpha_r);

    // TODO constrain that α_l are public inputs
    // TODO constrain that α_{r,i} = α_{r,i-1} * h_R
    // TODO constrain that α_{r,1} = h_R (from hash table)
}

pub fn constrain_scalars<F, Ff, Env>(env: &mut Env)
where
    F: PrimeField,
    Ff: PrimeField,
    Env: ColAccessCap<F, IVCColumn> + LookupCap<F, IVCColumn, IVCLookupTable<Ff>>,
{
    let _phi = env.read_column(IVCColumn::Block3ConstPhi);
    let r = env.read_column(IVCColumn::Block3ConstR);
    let phi_i = env.read_column(IVCColumn::Block3PhiPow);
    let phi_i_r = env.read_column(IVCColumn::Block3PhiPowR);
    let phi_pow_limbs: [_; N_LIMBS_SMALL] = read_column_array(env, IVCColumn::Block3PhiPowLimbs);
    let phi_pow_r_limbs: [_; N_LIMBS_SMALL] = read_column_array(env, IVCColumn::Block3PhiPowRLimbs);

    let phi_pow_expected = combine_small_to_full::<_, _, Env>(phi_pow_limbs.clone());
    let phi_pow_r_expected = combine_small_to_full::<_, _, Env>(phi_pow_r_limbs.clone());

    {
        range_check_scalar_limbs::<F, Ff, Env>(env, &phi_pow_limbs);
        range_check_scalar_limbs::<F, Ff, Env>(env, &phi_pow_r_limbs);
    }

    // TODO Add expression asserting data with the next row. E.g.
    // let phi_i_next = env.read_column_(IVCColumn::Block3ConstR)
    // env.assert_zero(phi_i_next - phi_i * phi)
    env.assert_zero(phi_i_r.clone() - phi_i.clone() * r.clone());
    env.assert_zero(phi_pow_expected - phi_i);
    env.assert_zero(phi_pow_r_expected - phi_i_r);
}

pub fn constrain_ecadds<F, Ff, Env>(env: &mut Env)
where
    F: PrimeField,
    Ff: PrimeField,
    Env: ColAccessCap<F, IVCColumn> + LookupCap<F, IVCColumn, IVCLookupTable<Ff>>,
{
    constrain_ec_addition::<F, Ff, _>(&mut SubEnvLookup::new(
        &mut SubEnvColumn::new(env, IVCFECLens {}),
        IVCFECLookupLens(PhantomData),
    ));

    // Repacking to 75 bits

    let output_limbs_small_x: [_; N_LIMBS_SMALL] =
        read_column_array(env, |i| IVCColumn::Block4OutputRaw(FECColumnOutput::XR(i)));
    let output_limbs_small_y: [_; N_LIMBS_SMALL] =
        read_column_array(env, |i| IVCColumn::Block4OutputRaw(FECColumnOutput::YR(i)));

    let output_limbs_large_x: [_; N_LIMBS_LARGE] =
        read_column_array(env, IVCColumn::Block4OutputRepacked);
    let output_limbs_large_y: [_; N_LIMBS_LARGE] =
        read_column_array(env, |i| IVCColumn::Block4OutputRepacked(N_LIMBS_LARGE + i));

    {
        let output_limbs_large_x_expected =
            combine_small_to_large::<_, _, Env>(output_limbs_small_x);
        let output_limbs_large_y_expected =
            combine_small_to_large::<_, _, Env>(output_limbs_small_y);
        output_limbs_large_x_expected
            .into_iter()
            .zip(output_limbs_large_x.clone())
            .for_each(|(e1, e2)| env.assert_zero(e1 - e2));
        output_limbs_large_y_expected
            .into_iter()
            .zip(output_limbs_large_y.clone())
            .for_each(|(e1, e2)| env.assert_zero(e1 - e2));
    }
}

// We might not need to constrain selectors to be 0 or 1 if selectors
// are public values, and can be verified directly by the verifier.
// However we might need these constraints in folding, where public
// input needs to be checked.
/// This function generates constraints for the whole IVC circuit.
pub fn constrain_selectors<F, Env>(env: &mut Env)
where
    F: PrimeField,
    Env: ColAccessCap<F, IVCColumn>,
{
    for i in 0..N_BLOCKS {
        // Each selector must have value either 0 or 1.
        let sel = env.read_column(IVCColumn::BlockSel(i));
        env.assert_zero(sel.clone() * (sel.clone() - Env::constant(F::one())));
    }
}

/// This function generates constraints for the whole IVC circuit.
pub fn constrain_ivc<Ff, Env>(env: &mut Env)
where
    Ff: PrimeField,
    Env: ColAccessCap<Fp, IVCColumn>
        + LookupCap<Fp, IVCColumn, IVCLookupTable<Ff>>
        + HybridCopyCap<Fp, IVCColumn>,
{
    constrain_selectors(env);

    // The code below calls constraint method, and internally records
    // constraints for the corresponding blocks. Before the each call
    // we prefix the constraint with `selector(block_num)*` so that
    // the constraints that are created in the block block_num will have
    // the form selector(block_num)*C(X) and not just C(X).

    let fold_iteration = env.read_column(IVCColumn::FoldIteration);
    let s0 = env.read_column(IVCColumn::BlockSel(0));
    env.set_assert_mapper(Box::new(move |x| fold_iteration.clone() * s0.clone() * x));
    constrain_inputs(env);

    let fold_iteration = env.read_column(IVCColumn::FoldIteration);

    let s1 = env.read_column(IVCColumn::BlockSel(1));
    env.set_assert_mapper(Box::new(move |x| fold_iteration.clone() * s1.clone() * x));
    {
        let mut env = SubEnvColumn::new(env, IVCHashLens {});
        poseidon_8_56_5_3_2::interpreter::apply_permutation(&mut env, &PoseidonBN254Parameters);
    }

    let fold_iteration = env.read_column(IVCColumn::FoldIteration);
    let s2 = env.read_column(IVCColumn::BlockSel(2));
    env.set_assert_mapper(Box::new(move |x| fold_iteration.clone() * s2.clone() * x));
    constrain_scalars(env);

    let fold_iteration = env.read_column(IVCColumn::FoldIteration);
    let s3 = env.read_column(IVCColumn::BlockSel(3));
    env.set_assert_mapper(Box::new(move |x| fold_iteration.clone() * s3.clone() * x));
    constrain_ecadds(env);

    let fold_iteration = env.read_column(IVCColumn::FoldIteration);
    let s4 = env.read_column(IVCColumn::BlockSel(4));
    env.set_assert_mapper(Box::new(move |x| fold_iteration.clone() * s4.clone() * x));
    constrain_challenges(env);

    let fold_iteration = env.read_column(IVCColumn::FoldIteration);
    let s5 = env.read_column(IVCColumn::BlockSel(5));
    env.set_assert_mapper(Box::new(move |x| fold_iteration.clone() * s5.clone() * x));
    constrain_u(env);

    env.set_assert_mapper(Box::new(move |x| x));
}
