// Interpreter for IVC circuit (for folding).

use crate::{
    ivc::{
        columns::{IVCColumn, IVCHashLens, IVC_POSEIDON_NB_FULL_ROUND, IVC_POSEIDON_STATE_SIZE},
        lookups::IVCLookupTable,
    },
    poseidon::{
        columns::PoseidonColumn,
        interpreter::{poseidon_circuit, PoseidonParams},
    },
};
use ark_ff::PrimeField;
use kimchi_msm::{
    circuit_design::{
        capabilities::{read_column_array, write_column_array_const},
        composition::SubEnvColumn,
        ColAccessCap, ColWriteCap, HybridCopyCap, LookupCap, MultiRowReadCap,
    },
    columns::ColumnIndexer,
    serialization::{
        interpreter::{
            combine_limbs_m_to_n, combine_small_to_large, limb_decompose_ff, LIMB_BITSIZE_LARGE,
            LIMB_BITSIZE_SMALL, N_LIMBS_LARGE, N_LIMBS_SMALL,
        },
        lookups as serlookup,
    },
};
use std::marker::PhantomData;

/// The biggest packing variant for foreign field. Used for hashing. 150-bit limbs.
pub const LIMB_BITSIZE_XLARGE: usize = 150;
/// The biggest packing format, 2 limbs.
pub const N_LIMBS_XLARGE: usize = 2;

pub fn process_inputs<F, Ff, Env, const N_COL_TOTAL: usize>(
    env: &mut Env,
    comms_left: [(Ff, Ff); N_COL_TOTAL],
    comms_right: [(Ff, Ff); N_COL_TOTAL],
    comms_out: [(Ff, Ff); N_COL_TOTAL],
    row_num: usize,
) where
    F: PrimeField,
    Ff: PrimeField,
    Env: ColWriteCap<F, IVCColumn>,
{
    let (target_comms, row_num_local) = if row_num < N_COL_TOTAL {
        (comms_left, row_num)
    } else if row_num < 2 * N_COL_TOTAL {
        (comms_right, row_num - N_COL_TOTAL)
    } else {
        (comms_out, row_num - 2 * N_COL_TOTAL)
    };
    write_column_array_const(
        env,
        limb_decompose_ff::<F, Ff, LIMB_BITSIZE_SMALL, N_LIMBS_SMALL>(
            &target_comms[row_num_local].0,
        ),
        IVCColumn::Block1Input,
    );
    write_column_array_const(
        env,
        limb_decompose_ff::<F, Ff, LIMB_BITSIZE_SMALL, N_LIMBS_SMALL>(
            &target_comms[row_num_local].1,
        ),
        |x| IVCColumn::Block1Input(N_LIMBS_SMALL + x),
    );
    write_column_array_const(
        env,
        limb_decompose_ff::<F, Ff, LIMB_BITSIZE_LARGE, N_LIMBS_LARGE>(
            &target_comms[row_num_local].0,
        ),
        IVCColumn::Block1InputRepacked75,
    );
    write_column_array_const(
        env,
        limb_decompose_ff::<F, Ff, LIMB_BITSIZE_LARGE, N_LIMBS_LARGE>(
            &target_comms[row_num_local].1,
        ),
        |x| IVCColumn::Block1InputRepacked75(N_LIMBS_LARGE + x),
    );
    write_column_array_const(
        env,
        limb_decompose_ff::<F, Ff, LIMB_BITSIZE_XLARGE, N_LIMBS_XLARGE>(
            &target_comms[row_num_local].0,
        ),
        IVCColumn::Block1InputRepacked150,
    );
    write_column_array_const(
        env,
        limb_decompose_ff::<F, Ff, LIMB_BITSIZE_XLARGE, N_LIMBS_XLARGE>(
            &target_comms[row_num_local].1,
        ),
        |x| IVCColumn::Block1InputRepacked150(N_LIMBS_XLARGE + x),
    );
}

// FIXME Highly (!!!!) POC! Not trying to make things work at this moment.
// E.g. it should do a proper sponge, have proper init values, etc etc
/// Instantiates the IVC circuit for folding. N is the total number of columns
pub fn process_hashes<F, Env, PParams, const N_COL_TOTAL: usize>(
    env: &mut Env,
    poseidon_params: &PParams,
    row_i: usize,
) where
    F: PrimeField,
    PParams: PoseidonParams<F, IVC_POSEIDON_STATE_SIZE, IVC_POSEIDON_NB_FULL_ROUND>,
    Env: MultiRowReadCap<F, IVCColumn> + HybridCopyCap<F, IVCColumn>,
{
    let n = N_COL_TOTAL;

    // These should be some proper seeds. Passed from the outside
    let sponge_l_init: F = F::one();
    let sponge_r_init: F = F::one();
    let sponge_o_init: F = F::one();
    let sponge_lr_init: F = F::one();
    let sponge_lro_init: F = F::one();

    // Relative position in the hashing block
    let block_row_i = row_i - 3 * n;

    // Computing h_l, h_r, h_o independently
    if block_row_i < 6 * n {
        // The block 1 row we target
        let block1_row_i = block_row_i / 2;
        let (input1, input2) = if block_row_i % 2 == 0 {
            (
                env.read_row_column(block1_row_i, IVCColumn::Block1InputRepacked150(0)),
                env.read_row_column(block1_row_i, IVCColumn::Block1InputRepacked150(1)),
            )
        } else {
            (
                env.read_row_column(block1_row_i, IVCColumn::Block1InputRepacked150(2)),
                env.read_row_column(block1_row_i, IVCColumn::Block1InputRepacked150(3)),
            )
        };
        let input3 = if block_row_i == 0 {
            Env::constant(sponge_l_init)
        } else if block_row_i == 2 * n {
            Env::constant(sponge_r_init)
        } else if block_row_i == 4 * n {
            Env::constant(sponge_o_init)
        } else {
            // otherwise read from the previous row
            env.read_row_column(
                row_i - 1,
                IVCColumn::Block2Hash(PoseidonColumn::Round(
                    IVC_POSEIDON_NB_FULL_ROUND - 1,
                    IVC_POSEIDON_STATE_SIZE - 1,
                )),
            )
        };

        poseidon_circuit(
            &mut SubEnvColumn::new(env, IVCHashLens {}),
            poseidon_params,
            (input1, input2, input3),
        );
    } else if block_row_i == 6 * n {
        let input1_hl = env.read_row_column(
            5 * n,
            IVCColumn::Block2Hash(PoseidonColumn::Round(
                IVC_POSEIDON_NB_FULL_ROUND - 1,
                IVC_POSEIDON_STATE_SIZE - 1,
            )),
        );
        let input2_hr = env.read_row_column(
            7 * n,
            IVCColumn::Block2Hash(PoseidonColumn::Round(
                IVC_POSEIDON_NB_FULL_ROUND - 1,
                IVC_POSEIDON_STATE_SIZE - 1,
            )),
        );
        let input3 = Env::constant(sponge_lr_init);

        // Computing r
        poseidon_circuit(
            &mut SubEnvColumn::new(env, IVCHashLens {}),
            poseidon_params,
            (input1_hl, input2_hr, input3),
        );
    } else if block_row_i == 6 * n + 1 {
        let input1_ho = env.read_row_column(
            9 * n,
            IVCColumn::Block2Hash(PoseidonColumn::Round(
                IVC_POSEIDON_NB_FULL_ROUND - 1,
                IVC_POSEIDON_STATE_SIZE - 1,
            )),
        );
        let input2_r = env.read_row_column(
            row_i - 1,
            IVCColumn::Block2Hash(PoseidonColumn::Round(
                IVC_POSEIDON_NB_FULL_ROUND - 1,
                IVC_POSEIDON_STATE_SIZE - 1,
            )),
        );
        let input3 = Env::constant(sponge_lro_init);

        // Computing phi
        poseidon_circuit(
            &mut SubEnvColumn::new(env, IVCHashLens {}),
            poseidon_params,
            (input1_ho, input2_r, input3),
        );
    }
}

pub fn process_scalars<F, Env, const N_COL_TOTAL: usize>(_env: &mut Env, _row_i: usize)
where
    F: PrimeField,
    Env: MultiRowReadCap<F, IVCColumn> + HybridCopyCap<F, IVCColumn>,
{
}

pub fn process_ecadds<F, Env, const N_COL_TOTAL: usize>(_env: &mut Env, _row_i: usize)
where
    F: PrimeField,
    Env: MultiRowReadCap<F, IVCColumn> + HybridCopyCap<F, IVCColumn>,
{
}

pub fn process_misc<F, Env, const N_COL_TOTAL: usize>(_env: &mut Env, _row_i: usize)
where
    F: PrimeField,
    Env: MultiRowReadCap<F, IVCColumn> + HybridCopyCap<F, IVCColumn>,
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
    Env: MultiRowReadCap<F, IVCColumn> + HybridCopyCap<F, IVCColumn>,
{
    let n = N_COL_TOTAL;

    let block2_offset = 3 * n;
    let block3_offset = block2_offset + 6 * n + 2;
    let block4_offset = block3_offset + n;
    let block5_offset = block4_offset + 35 * n;

    for row_i in 0..domain_size {
        if row_i < block2_offset {
            process_inputs(env, comms_left, comms_right, comms_out, row_i);
        } else if row_i < block3_offset {
            process_hashes::<_, _, _, N_COL_TOTAL>(env, poseidon_params, row_i);
        } else if row_i < block4_offset {
            process_scalars::<_, _, N_COL_TOTAL>(env, row_i);
        } else if row_i < block5_offset {
            process_ecadds::<_, _, N_COL_TOTAL>(env, row_i);
        } else {
            process_misc::<_, _, N_COL_TOTAL>(env, row_i);
        }

        env.next_row();
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

/// Helper function for limb recombination.
///
/// Combines small limbs into big limbs.
pub fn combine_large_to_xlarge<F: PrimeField, CIx: ColumnIndexer, Env: ColAccessCap<F, CIx>>(
    x: [Env::Variable; N_LIMBS_LARGE],
) -> [Env::Variable; N_LIMBS_XLARGE] {
    combine_limbs_m_to_n::<
        N_LIMBS_LARGE,
        N_LIMBS_XLARGE,
        LIMB_BITSIZE_LARGE,
        LIMB_BITSIZE_XLARGE,
        F,
        CIx,
        Env,
    >(x)
}

/// Provides constraints for the IVC circuit.
pub fn ivc_constraint<F, Ff, Env>(env: &mut Env)
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
