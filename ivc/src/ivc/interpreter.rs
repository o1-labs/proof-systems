// Interpreter for IVC circuit (for folding).

use crate::{
    ivc::{
        columns::{
            IVCColumn, IVCFECLens, IVCHashLens, IVC_POSEIDON_NB_FULL_ROUND, IVC_POSEIDON_STATE_SIZE,
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
        columns::FECColumn,
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
    target_comms: [(Ff, Ff); N_COL_TOTAL],
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
pub fn process_inputs<F, Ff, Env, const N_COL_TOTAL: usize>(
    env: &mut Env,
    comms: [[(Ff, Ff); N_COL_TOTAL]; 3],
) -> (
    [[[F; 2 * N_LIMBS_SMALL]; N_COL_TOTAL]; 3],
    [[[F; 2 * N_LIMBS_LARGE]; N_COL_TOTAL]; 3],
    [[[F; 2 * N_LIMBS_XLARGE]; N_COL_TOTAL]; 3],
)
where
    F: PrimeField,
    Ff: PrimeField,
    Env: MultiRowReadCap<F, IVCColumn> + LookupCap<F, IVCColumn, IVCLookupTable<Ff>>,
{
    let mut comms_limbs: [[Vec<Vec<F>>; 3]; 3] =
        std::array::from_fn(|_| std::array::from_fn(|_| vec![]));

    for _block_row_i in 0..(3 * N_COL_TOTAL) {
        let row_num = env.curr_row();

        let (target_comms, row_num_local, comtype) = if row_num < N_COL_TOTAL {
            (comms[0], row_num, 0)
        } else if row_num < 2 * N_COL_TOTAL {
            (comms[1], row_num - N_COL_TOTAL, 1)
        } else {
            (comms[2], row_num - 2 * N_COL_TOTAL, 2)
        };

        let (limbs_small, limbs_large, limbs_xlarge) =
            write_inputs_row(env, target_comms, row_num_local);

        comms_limbs[0][comtype].push(limbs_small);
        comms_limbs[1][comtype].push(limbs_large);
        comms_limbs[2][comtype].push(limbs_xlarge);

        constrain_inputs(env);

        env.next_row();
    }

    // Transforms nested Vec<Vec<_>> into fixed-size arrays. Returns
    // Left-Right-Output for a given limb size.
    fn repack_output<F: PrimeField, const TWO_LIMB_SIZE: usize, const N_COL_TOTAL: usize>(
        input: [Vec<Vec<F>>; 3],
    ) -> [[[F; TWO_LIMB_SIZE]; N_COL_TOTAL]; 3] {
        input
            .into_iter()
            .map(|vector: Vec<Vec<_>>| {
                vector
                    .into_iter()
                    .map(|subvec: Vec<_>| subvec.try_into().unwrap())
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap()
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    (
        repack_output(comms_limbs[0].clone()),
        repack_output(comms_limbs[1].clone()),
        repack_output(comms_limbs[2].clone()),
    )
}

// FIXME Highly (!!!!) POC! Not trying to make things work at this moment.
// E.g. it should do a proper sponge, have proper init values, etc etc
/// Instantiates the IVC circuit for folding. N is the total number of columns
pub fn process_hashes<F, Env, PParams, const N_COL_TOTAL: usize>(
    env: &mut Env,
    poseidon_params: &PParams,
    comms_xlarge: &[[[F; 2 * N_LIMBS_XLARGE]; N_COL_TOTAL]; 3],
) -> (Env::Variable, Env::Variable)
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
    for block_row_i in 0..6 * N_COL_TOTAL + 2 {
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
                hash_l = output;
            } else if block_row_i == 4 * N_COL_TOTAL {
                hash_r = output;
            } else if block_row_i == 6 * N_COL_TOTAL {
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

    (r, phi)
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

pub fn write_scalars_row<F, Env>(env: &mut Env, r_f: F, phi_f: F, phi_prev_power_f: F) -> F
where
    F: PrimeField,
    Env: ColWriteCap<F, IVCColumn>,
{
    let phi_cur_power_f = phi_prev_power_f * phi_f;
    let phi_cur_power_r_f = phi_prev_power_f * phi_f * r_f;

    env.write_column(IVCColumn::Block3ConstPhi, &Env::constant(phi_f));
    env.write_column(IVCColumn::Block3ConstR, &Env::constant(r_f));
    env.write_column(IVCColumn::Block3PhiPow, &Env::constant(phi_cur_power_f));
    env.write_column(IVCColumn::Block3PhiPowR, &Env::constant(phi_cur_power_r_f));

    // TODO check that limb_decompose_ff works with <F,F,_,_>
    write_column_array_const(
        env,
        &limb_decompose_ff::<F, F, LIMB_BITSIZE_SMALL, N_LIMBS_SMALL>(&phi_cur_power_f),
        IVCColumn::Block3PhiPowLimbs,
    );
    write_column_array_const(
        env,
        &limb_decompose_ff::<F, F, LIMB_BITSIZE_SMALL, N_LIMBS_SMALL>(&phi_cur_power_r_f),
        IVCColumn::Block3PhiPowRLimbs,
    );

    phi_cur_power_f
}

pub fn process_scalars<F, Ff, Env, const N_COL_TOTAL: usize>(env: &mut Env, r: F, phi: F)
where
    F: PrimeField,
    Ff: PrimeField,
    Env: DirectWitnessCap<F, IVCColumn> + LookupCap<F, IVCColumn, IVCLookupTable<Ff>>,
{
    let mut phi_prev_power_f = F::one();
    for _block_row_i in 0..N_COL_TOTAL {
        phi_prev_power_f = write_scalars_row(env, r, phi, phi_prev_power_f);

        // Checking our constraints
        constrain_scalars(env);

        env.next_row();
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
}

pub fn process_ecadds<F, Ff, Env, const N_COL_TOTAL: usize>(
    env: &mut Env,
    _r: F,
    _phi: F,
    comms_large: &[[[F; 2 * N_LIMBS_LARGE]; N_COL_TOTAL]; 3],
) where
    F: PrimeField,
    Ff: PrimeField,
    Env: DirectWitnessCap<F, IVCColumn> + LookupCap<F, IVCColumn, IVCLookupTable<Ff>>,
{
    // TODO FIXME multiply by r. For now these are just C_{R,i}, they must be {r * C_{R,i}}
    let r_hat_large: Box<[[F; 2 * N_LIMBS_LARGE]; N_COL_TOTAL]> = Box::new(comms_large[1]);

    for block_row_i in 0..35 * N_COL_TOTAL {
        // Number of the commitment we're processing
        let com_i = block_row_i % N_COL_TOTAL;
        let (xp_limbs, yp_limbs) =
            if block_row_i < 17 * N_COL_TOTAL || block_row_i >= 34 * N_COL_TOTAL {
                // Our main commitment input
                (
                    comms_large[1][com_i][..N_LIMBS_LARGE].try_into().unwrap(),
                    comms_large[1][com_i][N_LIMBS_LARGE..].try_into().unwrap(),
                )
            } else {
                (
                    r_hat_large[com_i][..N_LIMBS_LARGE].try_into().unwrap(),
                    r_hat_large[com_i][N_LIMBS_LARGE..].try_into().unwrap(),
                )
            };
        write_column_array_const(env, &xp_limbs, |i| IVCColumn::Block4ECAdd(FECColumn::XP(i)));
        write_column_array_const(env, &yp_limbs, |i| IVCColumn::Block4ECAdd(FECColumn::YP(i)));

        // FIXME This is a STUB right now it uses C_{L,i} commitments.
        // Must use bucket input which is looked up.
        let xq_limbs: [F; N_LIMBS_LARGE] =
            comms_large[0][com_i][..N_LIMBS_LARGE].try_into().unwrap();
        let yq_limbs: [F; N_LIMBS_LARGE] =
            comms_large[0][com_i][..N_LIMBS_LARGE].try_into().unwrap();
        write_column_array_const(env, &xq_limbs, |i| IVCColumn::Block4ECAdd(FECColumn::XQ(i)));
        write_column_array_const(env, &yq_limbs, |i| IVCColumn::Block4ECAdd(FECColumn::YQ(i)));

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

        ec_add_circuit(
            &mut SubEnvLookup::new(
                &mut SubEnvColumn::new(env, IVCFECLens {}),
                IVCFECLookupLens(PhantomData),
            ),
            xp,
            yp,
            xq,
            yq,
        );

        constrain_ecadds::<F, Ff, Env>(env);
    }
}

pub fn process_misc<F, Env, const N_COL_TOTAL: usize>(_env: &mut Env)
where
    F: PrimeField,
    Env: MultiRowReadCap<F, IVCColumn>,
{
}

/// Instantiates the IVC circuit for folding. N is the total number of columns
pub fn ivc_circuit<F, Ff, Env, PParams, const N_COL_TOTAL: usize>(
    env: &mut Env,
    comms_left: [(Ff, Ff); N_COL_TOTAL],
    comms_right: [(Ff, Ff); N_COL_TOTAL],
    comms_out: [(Ff, Ff); N_COL_TOTAL],
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

    let (_comms_small, comms_large, comms_xlarge) =
        process_inputs(env, [comms_left, comms_right, comms_out]);
    let (r_var, phi_var) =
        process_hashes::<_, _, _, N_COL_TOTAL>(env, poseidon_params, &comms_xlarge);
    let r: F = Env::variable_to_field(r_var);
    let phi: F = Env::variable_to_field(phi_var);
    process_scalars::<_, Ff, _, N_COL_TOTAL>(env, r, phi);
    process_ecadds::<_, Ff, _, N_COL_TOTAL>(env, r, phi, &comms_large);
    process_misc::<_, _, N_COL_TOTAL>(env);
}
