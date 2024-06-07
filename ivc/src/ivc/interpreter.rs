// Interpreter for IVC circuit (for folding).

use crate::{
    ivc::{
        columns::{
            block_height, IVCColumn, IVCFECLens, IVCHashLens, IVC_POSEIDON_NB_FULL_ROUND,
            IVC_POSEIDON_STATE_SIZE, N_BLOCKS,
        },
        lookups::{IVCFECLookupLens, IVCLookupTable},
    },
    poseidon::interpreter::{poseidon_circuit, PoseidonParams},
};
use ark_ff::PrimeField;
use kimchi_msm::{
    circuit_design::{
        capabilities::{read_column_array, write_column_array_const},
        composition::{SubEnvColumn, SubEnvLookup},
        ColAccessCap, ColWriteCap, DirectWitnessCap, HybridCopyCap, LookupCap, MultiRowReadCap,
    },
    columns::ColumnIndexer,
    fec::{
        columns::FECColumnOutput,
        interpreter::{constrain_ec_addition, ec_add_circuit},
    },
    serialization::{
        interpreter::{
            combine_limbs_m_to_n, combine_small_to_large, limb_decompose_ff, LIMB_BITSIZE_LARGE,
            LIMB_BITSIZE_SMALL, N_LIMBS_LARGE, N_LIMBS_SMALL,
        },
        lookups as serlookup,
    },
};
use num_bigint::BigUint;
use std::marker::PhantomData;

/// The biggest packing variant for foreign field. Used for hashing. 150-bit limbs.
pub const LIMB_BITSIZE_XLARGE: usize = 150;
/// The biggest packing format, 2 limbs.
pub const N_LIMBS_XLARGE: usize = 2;

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
            // If it's the highest limb, we need to check that it's representing a field element.
            env.lookup(
                IVCLookupTable::SerLookupTable(serlookup::LookupTable::RangeCheckFfHighest(
                    PhantomData,
                )),
                x,
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
            // If it's the highest limb, we need to check that it's representing a field element.
            env.lookup(
                IVCLookupTable::SerLookupTable(serlookup::LookupTable::RangeCheckFfHighest(
                    PhantomData,
                )),
                x,
            );
        } else {
            env.lookup(
                IVCLookupTable::SerLookupTable(serlookup::LookupTable::RangeCheck15),
                x,
            );
        }
    }
}

// TODO double-check it works
/// Helper. Combines large limbs into one element. Computation is over the field.
pub fn combine_large_to_full_field<Ff: PrimeField>(x: [Ff; N_LIMBS_LARGE]) -> Ff {
    let [res] =
        combine_limbs_m_to_n::<N_LIMBS_LARGE, 1, LIMB_BITSIZE_LARGE, 300, Ff, Ff, _>(|f| f, x);
    res
}

/// Helper. Combines small limbs into big limbs.
pub fn combine_large_to_xlarge<F: PrimeField, CIx: ColumnIndexer, Env: ColAccessCap<F, CIx>>(
    x: [Env::Variable; N_LIMBS_LARGE],
) -> [Env::Variable; N_LIMBS_XLARGE] {
    combine_limbs_m_to_n::<
        N_LIMBS_LARGE,
        N_LIMBS_XLARGE,
        LIMB_BITSIZE_LARGE,
        LIMB_BITSIZE_XLARGE,
        F,
        Env::Variable,
        _,
    >(|f| Env::constant(f), x)
}

/// Helper. Combines 17x15bit limbs into 1 native field element.
pub fn combine_small_to_full<F: PrimeField, CIx: ColumnIndexer, Env: ColAccessCap<F, CIx>>(
    x: [Env::Variable; N_LIMBS_SMALL],
) -> Env::Variable {
    let [res] =
        combine_limbs_m_to_n::<N_LIMBS_SMALL, 1, LIMB_BITSIZE_SMALL, 255, F, Env::Variable, _>(
            |f| Env::constant(f),
            x,
        );
    res
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

pub fn write_inputs_row<F, Ff, Env, const N_COL_TOTAL: usize>(
    env: &mut Env,
    target_comms: &[(Ff, Ff); N_COL_TOTAL],
    row_num_local: usize,
) -> (Vec<F>, Vec<F>, Vec<F>)
where
    F: PrimeField,
    Ff: PrimeField,
    Env: ColWriteCap<F, IVCColumn>,
{
    let small_limbs_1 = limb_decompose_ff::<F, Ff, LIMB_BITSIZE_SMALL, N_LIMBS_SMALL>(
        &target_comms[row_num_local].0,
    );
    let small_limbs_2 = limb_decompose_ff::<F, Ff, LIMB_BITSIZE_SMALL, N_LIMBS_SMALL>(
        &target_comms[row_num_local].1,
    );
    let small_limbs_1_2: [_; 2 * N_LIMBS_SMALL] = small_limbs_1
        .into_iter()
        .chain(small_limbs_2)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let large_limbs_1 = limb_decompose_ff::<F, Ff, LIMB_BITSIZE_LARGE, N_LIMBS_LARGE>(
        &target_comms[row_num_local].0,
    );
    let large_limbs_2 = limb_decompose_ff::<F, Ff, LIMB_BITSIZE_LARGE, N_LIMBS_LARGE>(
        &target_comms[row_num_local].1,
    );
    let large_limbs_1_2: [_; 2 * N_LIMBS_LARGE] = large_limbs_1
        .into_iter()
        .chain(large_limbs_2)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let xlarge_limbs_1 = limb_decompose_ff::<F, Ff, LIMB_BITSIZE_XLARGE, N_LIMBS_XLARGE>(
        &target_comms[row_num_local].0,
    );
    let xlarge_limbs_2 = limb_decompose_ff::<F, Ff, LIMB_BITSIZE_XLARGE, N_LIMBS_XLARGE>(
        &target_comms[row_num_local].1,
    );
    let xlarge_limbs_1_2: [_; 2 * N_LIMBS_XLARGE] = xlarge_limbs_1
        .into_iter()
        .chain(xlarge_limbs_2)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    write_column_array_const(env, &small_limbs_1_2, IVCColumn::Block1Input);
    write_column_array_const(env, &large_limbs_1_2, IVCColumn::Block1InputRepacked75);
    write_column_array_const(env, &xlarge_limbs_1_2, IVCColumn::Block1InputRepacked150);

    (
        small_limbs_1_2.to_vec(),
        large_limbs_1_2.to_vec(),
        xlarge_limbs_1_2.to_vec(),
    )
}

/// `comms` is lefts, rights, and outs. Returns the packed commitments
/// in three different representations.
#[allow(clippy::type_complexity)]
pub fn process_inputs<F, Ff, Env, const N_COL_TOTAL: usize, const N_CHALS: usize>(
    env: &mut Env,
    comms: [Box<[(Ff, Ff); N_COL_TOTAL]>; 3],
) -> (
    Box<[[[F; 2 * N_LIMBS_SMALL]; N_COL_TOTAL]; 3]>,
    Box<[[[F; 2 * N_LIMBS_LARGE]; N_COL_TOTAL]; 3]>,
    Box<[[[F; 2 * N_LIMBS_XLARGE]; N_COL_TOTAL]; 3]>,
)
where
    F: PrimeField,
    Ff: PrimeField,
    Env: MultiRowReadCap<F, IVCColumn> + LookupCap<F, IVCColumn, IVCLookupTable<Ff>>,
{
    let mut comms_limbs_s: [Vec<Vec<F>>; 3] = std::array::from_fn(|_| vec![]);
    let mut comms_limbs_l: [Vec<Vec<F>>; 3] = std::array::from_fn(|_| vec![]);
    let mut comms_limbs_xl: [Vec<Vec<F>>; 3] = std::array::from_fn(|_| vec![]);

    for _block_row_i in 0..block_height::<N_COL_TOTAL, N_CHALS>(0) {
        let row_num = env.curr_row();

        let (target_comms, row_num_local, comtype) = if row_num < N_COL_TOTAL {
            (&comms[0], row_num, 0)
        } else if row_num < 2 * N_COL_TOTAL {
            (&comms[1], row_num - N_COL_TOTAL, 1)
        } else {
            (&comms[2], row_num - 2 * N_COL_TOTAL, 2)
        };

        let (limbs_small, limbs_large, limbs_xlarge) =
            write_inputs_row(env, target_comms, row_num_local);

        comms_limbs_s[comtype].push(limbs_small);
        comms_limbs_l[comtype].push(limbs_large);
        comms_limbs_xl[comtype].push(limbs_xlarge);

        constrain_inputs(env);

        env.next_row();
    }

    (
        o1_utils::array::vec_to_boxed_array3(comms_limbs_s.to_vec()),
        o1_utils::array::vec_to_boxed_array3(comms_limbs_l.to_vec()),
        o1_utils::array::vec_to_boxed_array3(comms_limbs_xl.to_vec()),
    )
}

// TODO We need to have alpha
// TODO We need to hash i (or i+1)?
// TODO We need to hash T_0 and T_1?
// FIXME Highly (!!!!) POC! Not trying to make things work at this moment.
// FIXME: the sponge must be the environment Env. The environment must implement
// a trait like IVCCapability which contains methods to deal with different
// sponges.
// E.g. it should do a proper sponge, have proper init values, etc etc
/// Instantiates the IVC circuit for folding. N is the total number of columns
pub fn process_hashes<F, Env, PParams, const N_COL_TOTAL: usize, const N_CHALS: usize>(
    env: &mut Env,
    poseidon_params: &PParams,
    comms_xlarge: &[[[F; 2 * N_LIMBS_XLARGE]; N_COL_TOTAL]; 3],
) -> (Env::Variable, Env::Variable, Env::Variable)
where
    F: PrimeField,
    PParams: PoseidonParams<F, IVC_POSEIDON_STATE_SIZE, IVC_POSEIDON_NB_FULL_ROUND>,
    Env: MultiRowReadCap<F, IVCColumn> + HybridCopyCap<F, IVCColumn>,
{
    let n = N_COL_TOTAL;

    // These should be some proper seeds. Passed from the outside
    let sponge_l_init: F = F::zero();
    let sponge_r_init: F = F::zero();
    let sponge_o_init: F = F::zero();
    let sponge_lr_init: F = F::zero();
    let sponge_lro_init: F = F::zero();

    let mut prev_hash_output = Env::constant(F::zero());
    let mut hash_l = Env::constant(F::zero());
    let mut hash_r = Env::constant(F::zero());
    let mut hash_o = Env::constant(F::zero());
    let mut r = Env::constant(F::zero());
    let mut phi = Env::constant(F::zero());

    // Relative position in the hashing block
    for block_row_i in 0..block_height::<N_COL_TOTAL, N_CHALS>(1) {
        // Computing h_l, h_r, h_o independently
        if block_row_i < 6 * n {
            // Left, right, or output
            let comm_type = block_row_i / (2 * n);
            // The commitment we target. Commitment i is processed in hash rows 2*i and 2*i+1.
            let comm_i = (block_row_i % (2 * N_COL_TOTAL)) / 2;
            let (input1, input2) = if block_row_i % 2 == 0 {
                (
                    comms_xlarge[comm_type][comm_i][0],
                    comms_xlarge[comm_type][comm_i][1],
                )
            } else {
                (
                    comms_xlarge[comm_type][comm_i][2],
                    comms_xlarge[comm_type][comm_i][3],
                )
            };
            let input3 = if block_row_i == 0 {
                Env::constant(sponge_l_init)
            } else if block_row_i == 2 * n {
                Env::constant(sponge_r_init)
            } else if block_row_i == 4 * n {
                Env::constant(sponge_o_init)
            } else {
                prev_hash_output.clone()
            };

            let [_, _, output] = poseidon_circuit(
                &mut SubEnvColumn::new(env, IVCHashLens {}),
                poseidon_params,
                [Env::constant(input1), Env::constant(input2), input3],
            );

            if block_row_i == 2 * N_COL_TOTAL {
                // TODO we must somehow assert this hash_l is part of
                // the "right strict instance". This is H_i in Nova.
                hash_l = output;
            } else if block_row_i == 4 * N_COL_TOTAL {
                hash_r = output;
            } else if block_row_i == 6 * N_COL_TOTAL {
                // TODO we must somehow assert this hash_o is part of
                // the "output relaxed instance". This is H_{i+1} in Nova.
                // This one should be in the public input?
                hash_o = output;
            } else {
                prev_hash_output = output;
            }
        } else if block_row_i == 6 * n {
            // Computing r
            let [_, _, r_res] = poseidon_circuit(
                &mut SubEnvColumn::new(env, IVCHashLens {}),
                poseidon_params,
                [
                    hash_l.clone(),
                    hash_r.clone(),
                    Env::constant(sponge_lr_init),
                ],
            );
            r = r_res;
        } else if block_row_i == 6 * n + 1 {
            // Computing phi
            let [_, _, phi_res] = poseidon_circuit(
                &mut SubEnvColumn::new(env, IVCHashLens {}),
                poseidon_params,
                [hash_o.clone(), r.clone(), Env::constant(sponge_lro_init)],
            );
            phi = phi_res;
        }

        env.next_row();
    }

    (hash_r, r, phi)
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

pub fn write_scalars_row<F, Env>(
    env: &mut Env,
    r_f: F,
    phi_f: F,
    phi_prev_power_f: F,
) -> (
    F,
    [F; N_LIMBS_SMALL],
    [F; N_LIMBS_SMALL],
    [F; N_LIMBS_SMALL],
    [F; N_LIMBS_SMALL],
)
where
    F: PrimeField,
    Env: ColWriteCap<F, IVCColumn>,
{
    let phi_curr_power_f = phi_prev_power_f * phi_f;
    let phi_curr_power_r_f = phi_prev_power_f * phi_f * r_f;
    let phi_curr_power_r2_f = phi_prev_power_f * phi_f * r_f * r_f;
    let phi_curr_power_r3_f = phi_prev_power_f * phi_f * r_f * r_f * r_f;

    env.write_column(IVCColumn::Block3ConstPhi, &Env::constant(phi_f));
    env.write_column(IVCColumn::Block3ConstR, &Env::constant(r_f));
    env.write_column(IVCColumn::Block3PhiPow, &Env::constant(phi_curr_power_f));
    env.write_column(IVCColumn::Block3PhiPowR, &Env::constant(phi_curr_power_r_f));
    env.write_column(
        IVCColumn::Block3PhiPowR2,
        &Env::constant(phi_curr_power_r2_f),
    );
    env.write_column(
        IVCColumn::Block3PhiPowR3,
        &Env::constant(phi_curr_power_r3_f),
    );

    // TODO check that limb_decompose_ff works with <F,F,_,_>
    let phi_curr_power_f_limbs =
        limb_decompose_ff::<F, F, LIMB_BITSIZE_SMALL, N_LIMBS_SMALL>(&phi_curr_power_f);
    write_column_array_const(env, &phi_curr_power_f_limbs, IVCColumn::Block3PhiPowLimbs);

    let phi_curr_power_r_f_limbs =
        limb_decompose_ff::<F, F, LIMB_BITSIZE_SMALL, N_LIMBS_SMALL>(&phi_curr_power_r_f);
    write_column_array_const(
        env,
        &phi_curr_power_r_f_limbs,
        IVCColumn::Block3PhiPowRLimbs,
    );

    let phi_curr_power_r2_f_limbs =
        limb_decompose_ff::<F, F, LIMB_BITSIZE_SMALL, N_LIMBS_SMALL>(&phi_curr_power_r2_f);
    write_column_array_const(
        env,
        &phi_curr_power_r2_f_limbs,
        IVCColumn::Block3PhiPowR2Limbs,
    );

    let phi_curr_power_r3_f_limbs =
        limb_decompose_ff::<F, F, LIMB_BITSIZE_SMALL, N_LIMBS_SMALL>(&phi_curr_power_r3_f);
    write_column_array_const(
        env,
        &phi_curr_power_r3_f_limbs,
        IVCColumn::Block3PhiPowR3Limbs,
    );

    (
        phi_curr_power_f,
        phi_curr_power_f_limbs,
        phi_curr_power_r_f_limbs,
        phi_curr_power_r2_f_limbs,
        phi_curr_power_r3_f_limbs,
    )
}

/// Contains vectors of scalars in small limb representations.
/// Generic consts don't allow +1, so vectors not arrays. `N` is
/// `N_COL_TOTAL`.
pub struct ScalarLimbs<F> {
    /// ϕ^i,   i ∈ [N+1]
    pub phi_limbs: Vec<[F; N_LIMBS_SMALL]>,
    /// r·ϕ^i, i ∈ [N+1]
    pub phi_r_limbs: Vec<[F; N_LIMBS_SMALL]>,
    /// r^2·ϕ^{N+1}
    pub phi_np1_r2_limbs: [F; N_LIMBS_SMALL],
    /// r^3·ϕ^{N+1}
    pub phi_np1_r3_limbs: [F; N_LIMBS_SMALL],
}

/// Processes scalars. Returns a vector of limbs of (powers of) scalars produced.
pub fn process_scalars<F, Ff, Env, const N_COL_TOTAL: usize, const N_CHALS: usize>(
    env: &mut Env,
    r: F,
    phi: F,
) -> ScalarLimbs<F>
where
    F: PrimeField,
    Ff: PrimeField,
    Env: DirectWitnessCap<F, IVCColumn> + LookupCap<F, IVCColumn, IVCLookupTable<Ff>>,
{
    let mut phi_prev_power_f = F::one();
    let mut phi_limbs = vec![];
    let mut phi_r_limbs = vec![];

    // FIXME constrain these two, they are not in circuit yet
    let mut phi_np1_r2_limbs = [F::zero(); N_LIMBS_SMALL];
    let mut phi_np1_r3_limbs = [F::zero(); N_LIMBS_SMALL];

    for block_row_i in 0..block_height::<N_COL_TOTAL, N_CHALS>(2) {
        let (
            phi_prev_power_f_new,
            phi_curr_power_f_limbs,
            phi_curr_power_r_f_limbs,
            phi_curr_power_r2_f_limbs,
            phi_curr_power_r3_f_limbs,
        ) = write_scalars_row(env, r, phi, phi_prev_power_f);

        phi_prev_power_f = phi_prev_power_f_new;
        phi_limbs.push(phi_curr_power_f_limbs);
        phi_r_limbs.push(phi_curr_power_r_f_limbs);

        if block_row_i == N_COL_TOTAL + 1 {
            phi_np1_r2_limbs = phi_curr_power_r2_f_limbs;
            phi_np1_r3_limbs = phi_curr_power_r3_f_limbs;
        }

        // Checking our constraints
        constrain_scalars(env);

        env.next_row();
    }

    ScalarLimbs {
        phi_limbs,
        phi_r_limbs,
        phi_np1_r2_limbs,
        phi_np1_r3_limbs,
    }
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

pub fn process_ecadds<F, Ff, Env, const N_COL_TOTAL: usize, const N_CHALS: usize>(
    env: &mut Env,
    scalar_limbs: ScalarLimbs<F>,
    comms_large: &[[[F; 2 * N_LIMBS_LARGE]; N_COL_TOTAL]; 3],
    error_terms: [(Ff, Ff); 3], // E_L, E_R, E_O
    t_terms: [(Ff, Ff); 2],     // T_0, T_1
) where
    F: PrimeField,
    Ff: PrimeField,
    Env: DirectWitnessCap<F, IVCColumn> + LookupCap<F, IVCColumn, IVCLookupTable<Ff>>,
{
    // TODO FIXME multiply by r. For now these are just C_{R,i}, they must be {r * C_{R,i}}
    let r_hat_large: Box<[[F; 2 * N_LIMBS_LARGE]; N_COL_TOTAL]> = Box::new(comms_large[1]);

    // Compute error and t terms limbs.
    let error_terms_large: Box<[[F; 2 * N_LIMBS_LARGE]; 3]> = o1_utils::array::vec_to_boxed_array2(
        error_terms
            .iter()
            .map(|(x, y)| {
                limb_decompose_ff::<F, Ff, LIMB_BITSIZE_LARGE, N_LIMBS_LARGE>(x)
                    .into_iter()
                    .chain(limb_decompose_ff::<F, Ff, LIMB_BITSIZE_LARGE, N_LIMBS_LARGE>(y))
                    .collect()
            })
            .collect(),
    );
    let t_terms_large: Box<[[F; 2 * N_LIMBS_LARGE]; 2]> = o1_utils::array::vec_to_boxed_array2(
        t_terms
            .iter()
            .map(|(x, y)| {
                limb_decompose_ff::<F, Ff, LIMB_BITSIZE_LARGE, N_LIMBS_LARGE>(x)
                    .into_iter()
                    .chain(limb_decompose_ff::<F, Ff, LIMB_BITSIZE_LARGE, N_LIMBS_LARGE>(y))
                    .collect()
            })
            .collect(),
    );

    // E_R' = r·T_0 + r^2·T_1 + r^3·E_R
    // FIXME for now stubbed and just equal to E_L
    let error_term_rprime_large: [F; 2 * N_LIMBS_LARGE] = error_terms_large[0];

    for block_row_i in 0..block_height::<N_COL_TOTAL, N_CHALS>(3) {
        // Number of the commitment we're processing, ∈ [N]
        let com_i = block_row_i % N_COL_TOTAL;
        // Coefficient limb we're processing for C_L/C_R/C_O, ∈ [k = 17]
        let coeff_num_1 = (block_row_i / N_COL_TOTAL) % N_LIMBS_SMALL;
        // Coefficient limb we're processing for error terms, ∈ [k = 17]
        let coeff_num_2 = if block_row_i >= 35 * N_COL_TOTAL {
            (block_row_i - 35 * N_COL_TOTAL) % N_LIMBS_SMALL
        } else {
            0
        };

        // First FEC input point, P.
        let (xp_limbs, yp_limbs, coeff) = if block_row_i < 17 * N_COL_TOTAL {
            // R hat, with ϕ^i
            (
                r_hat_large[com_i][..N_LIMBS_LARGE].try_into().unwrap(),
                r_hat_large[com_i][N_LIMBS_LARGE..].try_into().unwrap(),
                scalar_limbs.phi_limbs[com_i][coeff_num_1],
            )
        } else if block_row_i < 34 * N_COL_TOTAL {
            // Our main C_R commitment input, with r·ϕ^i
            (
                comms_large[1][com_i][..N_LIMBS_LARGE].try_into().unwrap(),
                comms_large[1][com_i][N_LIMBS_LARGE..].try_into().unwrap(),
                scalar_limbs.phi_r_limbs[com_i][coeff_num_1],
            )
        } else if block_row_i < 35 * N_COL_TOTAL {
            // FIXME add a minus!
            // no bucketing, no coeffient, no RAM. Only -R hat
            (
                r_hat_large[com_i][..N_LIMBS_LARGE].try_into().unwrap(),
                r_hat_large[com_i][N_LIMBS_LARGE..].try_into().unwrap(),
                F::zero(),
            )
        } else if block_row_i < 35 * N_COL_TOTAL + 17 {
            // FIXME add a minus
            // -E_R', with coeff ϕ^{n+1}
            (
                error_term_rprime_large[..N_LIMBS_LARGE].try_into().unwrap(),
                error_term_rprime_large[N_LIMBS_LARGE..].try_into().unwrap(),
                scalar_limbs.phi_limbs[N_COL_TOTAL][coeff_num_2],
            )
        } else if block_row_i < 35 * N_COL_TOTAL + 2 * 17 {
            // T_0, with coeff r · ϕ^{n+1}
            (
                t_terms_large[0][..N_LIMBS_LARGE].try_into().unwrap(),
                t_terms_large[0][N_LIMBS_LARGE..].try_into().unwrap(),
                scalar_limbs.phi_r_limbs[N_COL_TOTAL][coeff_num_2],
            )
        } else if block_row_i < 35 * N_COL_TOTAL + 3 * 17 {
            // T_1, with coeff r^2 · ϕ^{n+1}
            (
                t_terms_large[1][..N_LIMBS_LARGE].try_into().unwrap(),
                t_terms_large[1][N_LIMBS_LARGE..].try_into().unwrap(),
                scalar_limbs.phi_np1_r2_limbs[coeff_num_2],
            )
        } else if block_row_i < 35 * N_COL_TOTAL + 4 * 17 {
            // E_R, with coeff r^3 · ϕ^{n+1}
            (
                error_terms_large[1][..N_LIMBS_LARGE].try_into().unwrap(),
                error_terms_large[1][N_LIMBS_LARGE..].try_into().unwrap(),
                scalar_limbs.phi_np1_r3_limbs[coeff_num_2],
            )
        } else if block_row_i == 35 * N_COL_TOTAL + 4 * 17 {
            // E_L, no bucketing, no coeff
            (
                error_terms_large[0][..N_LIMBS_LARGE].try_into().unwrap(),
                error_terms_large[0][N_LIMBS_LARGE..].try_into().unwrap(),
                F::zero(),
            )
        } else {
            panic!("Dead case");
        };

        // FIXME This is a STUB right now it uses C_{O,i} commitments.
        // Must use bucket input which is looked up.
        let stub_bucket = (
            comms_large[2][com_i][..N_LIMBS_LARGE].try_into().unwrap(),
            comms_large[2][com_i][N_LIMBS_LARGE..].try_into().unwrap(),
        );

        // Second FEC input point, Q.
        let (xq_limbs, yq_limbs) = if block_row_i < 34 * N_COL_TOTAL {
            stub_bucket
        } else if block_row_i < 35 * N_COL_TOTAL {
            // C_{L,i} commitments
            (
                comms_large[0][com_i][..N_LIMBS_LARGE].try_into().unwrap(),
                comms_large[0][com_i][N_LIMBS_LARGE..].try_into().unwrap(),
            )
        } else if block_row_i < 35 * N_COL_TOTAL + 4 * 17 {
            stub_bucket
        } else if block_row_i == 35 * N_COL_TOTAL + 4 * 17 {
            // E_R'
            (
                error_term_rprime_large[..N_LIMBS_LARGE].try_into().unwrap(),
                error_term_rprime_large[N_LIMBS_LARGE..].try_into().unwrap(),
            )
        } else {
            panic!("Dead case");
        };

        env.write_column(IVCColumn::Block4Coeff, &Env::constant(coeff));
        write_column_array_const(env, &xp_limbs, IVCColumn::Block4Input1);
        write_column_array_const(env, &yp_limbs, |i| IVCColumn::Block4Input1(i + 4));
        write_column_array_const(env, &xq_limbs, IVCColumn::Block4Input2);
        write_column_array_const(env, &yq_limbs, |i| IVCColumn::Block4Input2(i + 4));

        // TODO These two should be used when RAMLookups are enabled.
        env.write_column(IVCColumn::Block4Input2AccessTime, &Env::constant(F::zero()));
        env.write_column(IVCColumn::Block4OutputAccessTime, &Env::constant(F::zero()));

        let limbs_f_to_ff = |limbs: &[F; N_LIMBS_LARGE]| {
            limbs
                .iter()
                .map(|f| Ff::from(BigUint::try_from(*f).unwrap()))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap()
        };
        let xp_limbs_ff: [Ff; N_LIMBS_LARGE] = limbs_f_to_ff(&xp_limbs);
        let yp_limbs_ff: [Ff; N_LIMBS_LARGE] = limbs_f_to_ff(&yp_limbs);
        let xq_limbs_ff: [Ff; N_LIMBS_LARGE] = limbs_f_to_ff(&xq_limbs);
        let yq_limbs_ff: [Ff; N_LIMBS_LARGE] = limbs_f_to_ff(&yq_limbs);

        let xp = combine_large_to_full_field(xp_limbs_ff);
        let xq = combine_large_to_full_field(xq_limbs_ff);
        let yp = combine_large_to_full_field(yp_limbs_ff);
        let yq = combine_large_to_full_field(yq_limbs_ff);

        let (xr, yr) = ec_add_circuit(
            &mut SubEnvLookup::new(
                &mut SubEnvColumn::new(env, IVCFECLens {}),
                IVCFECLookupLens(PhantomData),
            ),
            xp,
            yp,
            xq,
            yq,
        );

        // repacking results into 75 bits.
        let xr_limbs_large: [F; N_LIMBS_LARGE] =
            limb_decompose_ff::<F, Ff, LIMB_BITSIZE_LARGE, N_LIMBS_LARGE>(&xr);
        let yr_limbs_large: [F; N_LIMBS_LARGE] =
            limb_decompose_ff::<F, Ff, LIMB_BITSIZE_LARGE, N_LIMBS_LARGE>(&yr);

        write_column_array_const(env, &xr_limbs_large, IVCColumn::Block4OutputRepacked);
        write_column_array_const(env, &yr_limbs_large, |i| {
            IVCColumn::Block4OutputRepacked(4 + i)
        });

        constrain_ecadds::<F, Ff, Env>(env);

        env.next_row();
    }
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

#[allow(clippy::needless_range_loop)]
pub fn process_challenges<F, Env, const N_COL_TOTAL: usize, const N_CHALS: usize>(
    env: &mut Env,
    h_r: F,
    chal_l: &[F; N_CHALS],
    r: F,
) where
    F: PrimeField,
    Env: MultiRowReadCap<F, IVCColumn>,
{
    let mut curr_alpha_r_pow: F = F::one();

    for block_row_i in 0..block_height::<N_COL_TOTAL, N_CHALS>(4) {
        curr_alpha_r_pow *= h_r;

        env.write_column(IVCColumn::Block5ConstHr, &Env::constant(h_r));
        env.write_column(IVCColumn::Block5ConstR, &Env::constant(r));
        env.write_column(
            IVCColumn::Block5ChalLeft,
            &Env::constant(chal_l[block_row_i]),
        );
        env.write_column(IVCColumn::Block5ChalRight, &Env::constant(curr_alpha_r_pow));
        env.write_column(
            IVCColumn::Block5ChalOutput,
            &Env::constant(curr_alpha_r_pow * r + chal_l[block_row_i]),
        );

        constrain_challenges(env);

        env.next_row()
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

#[allow(clippy::needless_range_loop)]
pub fn process_u<F, Env, const N_COL_TOTAL: usize>(env: &mut Env, u_l: F, r: F)
where
    F: PrimeField,
    Env: MultiRowReadCap<F, IVCColumn>,
{
    env.write_column(IVCColumn::Block6ConstR, &Env::constant(r));
    env.write_column(IVCColumn::Block6ULeft, &Env::constant(u_l));
    env.write_column(IVCColumn::Block6UOutput, &Env::constant(u_l + r));

    constrain_u(env);

    env.next_row();
}

/// Builds selectors for the IVC circuit.
#[allow(clippy::needless_range_loop)]
pub fn build_selectors<F, const N_COL_TOTAL: usize, const N_CHALS: usize>(
    domain_size: usize,
) -> [Vec<F>; N_BLOCKS]
where
    F: PrimeField,
{
    // 3*N + 6*N+2 + N+1 + 35*N + 5 + N_CHALS + 1 =
    // 45N + 9 + N_CHALS
    let mut selectors: [Vec<F>; N_BLOCKS] = core::array::from_fn(|_| vec![F::zero(); domain_size]);
    let mut curr_row = 0;
    for block_i in 0..N_BLOCKS {
        for _i in 0..block_height::<N_COL_TOTAL, N_CHALS>(block_i) {
            selectors[block_i][curr_row] = F::one();
            curr_row += 1;
        }
    }

    selectors
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
pub fn constrain_ivc<F, Ff, Env>(env: &mut Env)
where
    F: PrimeField,
    Ff: PrimeField,
    Env: ColAccessCap<F, IVCColumn> + LookupCap<F, IVCColumn, IVCLookupTable<Ff>>,
{
    constrain_selectors(env);

    // The code below calls constraint method, and internally records
    // constraints for the corresponding blocks. Before the each call
    // we prefix the constraint with `selector(block_num)*` so that
    // the constraints that are created in the block block_num will have
    // the form selector(block_num)*C(X) and not just C(X).

    let s0 = env.read_column(IVCColumn::BlockSel(0));
    env.set_assert_mapper(Box::new(move |x| s0.clone() * x));
    constrain_inputs(env);

    // TODO FIXME add constraints for hashes

    let s2 = env.read_column(IVCColumn::BlockSel(2));
    env.set_assert_mapper(Box::new(move |x| s2.clone() * x));
    constrain_scalars(env);

    let s3 = env.read_column(IVCColumn::BlockSel(3));
    env.set_assert_mapper(Box::new(move |x| s3.clone() * x));
    constrain_ecadds(env);

    let s4 = env.read_column(IVCColumn::BlockSel(4));
    env.set_assert_mapper(Box::new(move |x| s4.clone() * x));
    constrain_challenges(env);

    let s5 = env.read_column(IVCColumn::BlockSel(5));
    env.set_assert_mapper(Box::new(move |x| s5.clone() * x));
    constrain_u(env);

    env.set_assert_mapper(Box::new(move |x| x));
}

/// Instantiates the IVC circuit for folding. L is relaxed (folded)
/// instance, and R is strict (new) instance that is being relaxed at
/// this step. `N_COL_TOTAL` is the total number of columns for IVC + APP.
// FIXME: we must accept the scaled right commitments and the right instance
// commitments
#[allow(clippy::too_many_arguments)]
pub fn ivc_circuit<F, Ff, Env, PParams, const N_COL_TOTAL: usize, const N_CHALS: usize>(
    env: &mut Env,
    comms_left: Box<[(Ff, Ff); N_COL_TOTAL]>,
    comms_right: Box<[(Ff, Ff); N_COL_TOTAL]>,
    comms_out: Box<[(Ff, Ff); N_COL_TOTAL]>,
    error_terms: [(Ff, Ff); 3], // E_L, E_R, E_O
    t_terms: [(Ff, Ff); 2],     // T_0, T_1
    u_l: F,                     // part of the relaxed instance.
    chal_l: Box<[F; N_CHALS]>,  // challenges
    poseidon_params: &PParams,
    domain_size: usize,
) where
    F: PrimeField,
    Ff: PrimeField,
    PParams: PoseidonParams<F, IVC_POSEIDON_STATE_SIZE, IVC_POSEIDON_NB_FULL_ROUND>,
    Env: DirectWitnessCap<F, IVCColumn>
        + HybridCopyCap<F, IVCColumn>
        + LookupCap<F, IVCColumn, IVCLookupTable<Ff>>,
{
    // Total height of all blocks. Probably higher than this number. WIP
    assert!(45 * N_COL_TOTAL + 2 < domain_size);
    assert!(chal_l.len() == N_CHALS);

    let (_comms_small, comms_large, comms_xlarge) =
        process_inputs::<_, _, _, N_COL_TOTAL, N_CHALS>(env, [comms_left, comms_right, comms_out]);
    // FIXME: only right, out and right scaled must be absorbed, not left. We
    // can suppose that left has been absorbed before. It is only the new
    // instance that must be absorbed, with the output
    // FIXME: we do want to have different poseidon instances.
    // FIXME: do we want to pass the random folding combiner as a parameter of
    // the function and check here that the value is the same?
    let (hash_r_var, r_var, phi_var) =
        process_hashes::<_, _, _, N_COL_TOTAL, N_CHALS>(env, poseidon_params, &comms_xlarge);
    let r: F = Env::variable_to_field(r_var);
    let phi: F = Env::variable_to_field(phi_var);
    let hash_r: F = Env::variable_to_field(hash_r_var);
    let scalar_limbs = process_scalars::<_, Ff, _, N_COL_TOTAL, N_CHALS>(env, r, phi);
    process_ecadds::<_, Ff, _, N_COL_TOTAL, N_CHALS>(
        env,
        scalar_limbs,
        &comms_large,
        error_terms,
        t_terms,
    );
    process_challenges::<_, _, N_COL_TOTAL, N_CHALS>(env, hash_r, &chal_l, r);
    process_u::<_, _, N_COL_TOTAL>(env, u_l, r);
}
