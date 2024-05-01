// Interpreter for IVC circuit (for folding).

use crate::ivc::{columns::IVCColumn, lookups::IVCLookupTable};
use ark_ff::PrimeField;
use kimchi_msm::{
    circuit_design::{
        capabilities::{read_column_array, write_column_array_const},
        ColAccessCap, ColWriteCap, HybridCopyCap, LookupCap,
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

/// Instantiates the IVC circuit for folding. N is the total number of columns
pub fn ivc_circuit<F: PrimeField, Ff: PrimeField, Env, const N_COL_TOTAL: usize>(
    env: &mut Env,
    comms_left: [(Ff, Ff); N_COL_TOTAL],
    comms_right: [(Ff, Ff); N_COL_TOTAL],
    comms_out: [(Ff, Ff); N_COL_TOTAL],
    row_num: usize,
) where
    F: PrimeField,
    Env: ColWriteCap<F, IVCColumn> + HybridCopyCap<F, IVCColumn>,
{
    let n = N_COL_TOTAL;

    // Filling out input limbs
    if row_num < 3 * n {
        let (target_comms, row_num_local) = if row_num < n {
            (comms_left, row_num)
        } else if row_num < 2 * n {
            (comms_right, row_num - n)
        } else {
            (comms_out, row_num - 2 * n)
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
