// Interpreter for IVC circuit (for folding).

use crate::{
    ivc::{
        columns::{block_height, IVCColumn, IVCFECLens, IVCHashLens, N_BLOCKS},
        constraints::{
            constrain_challenges, constrain_ecadds, constrain_inputs, constrain_scalars,
            constrain_u,
        },
        lookups::{IVCFECLookupLens, IVCLookupTable},
    },
    poseidon_8_56_5_3_2::{
        bn254::{
            NB_TOTAL_ROUND as IVC_POSEIDON_NB_TOTAL_ROUND, STATE_SIZE as IVC_POSEIDON_STATE_SIZE,
        },
        interpreter::{poseidon_circuit, PoseidonParams},
    },
};
use ark_ff::PrimeField;
use kimchi_msm::{
    circuit_design::{
        capabilities::write_column_array_const,
        composition::{SubEnvColumn, SubEnvLookup},
        ColWriteCap, DirectWitnessCap, HybridCopyCap, LookupCap, MultiRowReadCap,
    },
    fec::interpreter::ec_add_circuit,
    serialization::interpreter::{
        limb_decompose_ff, LIMB_BITSIZE_LARGE, LIMB_BITSIZE_SMALL, N_LIMBS_LARGE, N_LIMBS_SMALL,
    },
};
use num_bigint::BigUint;
use std::marker::PhantomData;

use super::{
    columns::IVC_NB_TOTAL_FIXED_SELECTORS, helpers::combine_large_to_full_field,
    LIMB_BITSIZE_XLARGE, N_LIMBS_XLARGE,
};

pub enum HashSide {
    Left,
    Right,
    RightScaled,
    Challenges,
}

/// A trait that defines methods an environment must have to be able to
/// incrementally verifying the computation.
pub trait IVCEnv<F: PrimeField, Ff: PrimeField>:
    MultiRowReadCap<F, IVCColumn>
    + ColWriteCap<F, IVCColumn>
    + HybridCopyCap<F, IVCColumn>
    + DirectWitnessCap<F, IVCColumn>
    + LookupCap<F, IVCColumn, IVCLookupTable<Ff>>
{
    /// Get the current iteration of the computation
    fn iteration(self) -> Self::Variable;

    /// Increment the iteration counter
    fn increment_iteration(&mut self);

    fn get_poseidon_state(&self, side: HashSide) -> [Self::Variable; IVC_POSEIDON_STATE_SIZE];

    fn update_poseidon_state(
        &mut self,
        side: HashSide,
        new_state: [Self::Variable; IVC_POSEIDON_STATE_SIZE],
    );
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
    fold_iteration: usize,
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

        env.write_column(
            IVCColumn::FoldIteration,
            &Env::constant(F::from(fold_iteration as u64)),
        );

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
// E.g. it should do a proper sponge, have proper init values, etc etc
/// Instantiates the IVC circuit for folding. N is the total number of columns
pub fn process_hashes<F, Env, PParams, const N_COL_TOTAL: usize, const N_CHALS: usize>(
    env: &mut Env,
    fold_iteration: usize,
    poseidon_params: &PParams,
    comms_xlarge: &[[[F; 2 * N_LIMBS_XLARGE]; N_COL_TOTAL]; 3],
) -> (Env::Variable, Env::Variable, Env::Variable)
where
    F: PrimeField,
    PParams: PoseidonParams<F, IVC_POSEIDON_STATE_SIZE, IVC_POSEIDON_NB_TOTAL_ROUND>,
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
        env.write_column(
            IVCColumn::FoldIteration,
            &Env::constant(F::from(fold_iteration as u64)),
        );

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
    fold_iteration: usize,
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
        env.write_column(
            IVCColumn::FoldIteration,
            &Env::constant(F::from(fold_iteration as u64)),
        );

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

pub fn process_ecadds<F, Ff, Env, const N_COL_TOTAL: usize, const N_CHALS: usize>(
    env: &mut Env,
    fold_iteration: usize,
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
        env.write_column(
            IVCColumn::FoldIteration,
            &Env::constant(F::from(fold_iteration as u64)),
        );

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

#[allow(clippy::needless_range_loop)]
pub fn process_challenges<F, Env, const N_COL_TOTAL: usize, const N_CHALS: usize>(
    env: &mut Env,
    fold_iteration: usize,
    h_r: F,
    chal_l: &[F; N_CHALS],
    r: F,
) where
    F: PrimeField,
    Env: MultiRowReadCap<F, IVCColumn>,
{
    let mut curr_alpha_r_pow: F = F::one();

    for block_row_i in 0..block_height::<N_COL_TOTAL, N_CHALS>(4) {
        env.write_column(
            IVCColumn::FoldIteration,
            &Env::constant(F::from(fold_iteration as u64)),
        );

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

#[allow(clippy::needless_range_loop)]
pub fn process_u<F, Env, const N_COL_TOTAL: usize>(
    env: &mut Env,
    fold_iteration: usize,
    u_l: F,
    r: F,
) where
    F: PrimeField,
    Env: MultiRowReadCap<F, IVCColumn>,
{
    env.write_column(
        IVCColumn::FoldIteration,
        &Env::constant(F::from(fold_iteration as u64)),
    );

    env.write_column(IVCColumn::Block6ConstR, &Env::constant(r));
    env.write_column(IVCColumn::Block6ULeft, &Env::constant(u_l));
    env.write_column(IVCColumn::Block6UOutput, &Env::constant(u_l + r));

    constrain_u(env);

    env.next_row();
}

/// Builds selectors for the IVC circuit.
/// The round constants for Poseidon are not added in this function, and must be
/// done separately.
/// The size of the array is the total number of public values required for the
/// IVC. Therefore, it includes the potential round constants required by
/// the hash function.
// FIXME: rc should be handled here or in the lens
#[allow(clippy::needless_range_loop)]
pub fn build_selectors<F, const N_COL_TOTAL: usize, const N_CHALS: usize>(
    domain_size: usize,
) -> [Vec<F>; IVC_NB_TOTAL_FIXED_SELECTORS]
where
    F: PrimeField,
{
    // 3*N + 6*N+2 + N+1 + 35*N + 5 + N_CHALS + 1 =
    // 45N + 9 + N_CHALS
    let mut selectors: [Vec<F>; IVC_NB_TOTAL_FIXED_SELECTORS] =
        core::array::from_fn(|_| vec![F::zero(); domain_size]);
    let mut curr_row = 0;
    for block_i in 0..N_BLOCKS {
        for _i in 0..block_height::<N_COL_TOTAL, N_CHALS>(block_i) {
            assert!(
                curr_row < domain_size,
                "The domain size is too small to handle the IVC circuit"
            );
            selectors[block_i][curr_row] = F::one();
            curr_row += 1;
        }
    }

    selectors
}

/// Instantiates the IVC circuit for folding. L is relaxed (folded)
/// instance, and R is strict (new) instance that is being relaxed at
/// this step. `N_COL_TOTAL` is the total number of columns for IVC + APP.
/// `N_CHALS` is the number of challenges, which contains also the alphas used
/// to combine constraints, see [top level documentation in
/// folding](folding::expressions).
/// The number of commitments is the total number, and it is expecting the
/// commitments to also the previous IVC columns
// FIXME: we must accept the scaled right commitments and the right instance
// commitments
// FIXME: Env should be implementing like a IVCCapability trait, which contains
// the sponge for instance, and the buckets for the MSM. All the data points
// used here should be saved inside it, and this function should only take as an
// argument the environment.
// FIXME: the fold_iteration variable should be inside the environment
#[allow(clippy::too_many_arguments)]
pub fn ivc_circuit<F, Ff, Env, PParams, const N_COL_TOTAL: usize, const N_CHALS: usize>(
    env: &mut Env,
    fold_iteration: usize,
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
    PParams: PoseidonParams<F, IVC_POSEIDON_STATE_SIZE, IVC_POSEIDON_NB_TOTAL_ROUND>,
    Env: DirectWitnessCap<F, IVCColumn>
        + HybridCopyCap<F, IVCColumn>
        + LookupCap<F, IVCColumn, IVCLookupTable<Ff>>,
{
    // Total height of all blocks. Probably higher than this number. WIP
    assert!(45 * N_COL_TOTAL + 2 < domain_size);
    assert!(chal_l.len() == N_CHALS);

    let (_comms_small, comms_large, comms_xlarge) = process_inputs::<_, _, _, N_COL_TOTAL, N_CHALS>(
        env,
        fold_iteration,
        [comms_left, comms_right, comms_out],
    );
    let (hash_r_var, r_var, phi_var) = process_hashes::<_, _, _, N_COL_TOTAL, N_CHALS>(
        env,
        fold_iteration,
        poseidon_params,
        &comms_xlarge,
    );
    let r: F = Env::variable_to_field(r_var);
    let phi: F = Env::variable_to_field(phi_var);
    let hash_r: F = Env::variable_to_field(hash_r_var);
    let scalar_limbs =
        process_scalars::<_, Ff, _, N_COL_TOTAL, N_CHALS>(env, fold_iteration, r, phi);
    process_ecadds::<_, Ff, _, N_COL_TOTAL, N_CHALS>(
        env,
        fold_iteration,
        scalar_limbs,
        &comms_large,
        error_terms,
        t_terms,
    );
    process_challenges::<_, _, N_COL_TOTAL, N_CHALS>(env, fold_iteration, hash_r, &chal_l, r);
    process_u::<_, _, N_COL_TOTAL>(env, fold_iteration, u_l, r);
}
