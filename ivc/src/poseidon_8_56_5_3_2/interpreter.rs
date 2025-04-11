//! Implement an interpreter for a specific instance of the Poseidon inner
//! permutation.
//!
//! The Poseidon construction is defined in the paper ["Poseidon: A New Hash
//! Function"](https://eprint.iacr.org/2019/458.pdf).
//!
//! The Poseidon instance works on a state of size `STATE_SIZE` and is designed
//! to work with full and partial rounds. As a reminder, the Poseidon
//! permutation is a mapping from `F^STATE_SIZE` to `F^STATE_SIZE`.
//!
//! The user is responsible to provide the correct number of full and partial
//! rounds for the given field and the state.
//!
//! Also, it is hard-coded that the substitution is `5`. The user must verify
//! that `5` is coprime with `p - 1` where `p` is the order the field.
//!
//! The constants and matrix can be generated the file
//! `poseidon/src/pasta/params.sage`

use crate::poseidon_8_56_5_3_2::columns::PoseidonColumn;
use ark_ff::PrimeField;
use kimchi_msm::circuit_design::{ColAccessCap, ColWriteCap, HybridCopyCap};
use num_bigint::BigUint;
use num_integer::Integer;

/// Represents the parameters of the instance of the Poseidon permutation.
///
/// Constants are the round constants for each round, and MDS is the matrix used
/// by the linear layer.
///
/// The type is parametrized by the field, the state size, and the total number
/// of rounds.
// IMPROVEME merge constants and mds in a flat array, to use the CPU cache
pub trait PoseidonParams<F: PrimeField, const STATE_SIZE: usize, const NB_TOTAL_ROUNDS: usize> {
    fn constants(&self) -> [[F; STATE_SIZE]; NB_TOTAL_ROUNDS];
    fn mds(&self) -> [[F; STATE_SIZE]; STATE_SIZE];
}

/// Populates and checks one poseidon invocation.
pub fn poseidon_circuit<
    F: PrimeField,
    const STATE_SIZE: usize,
    const NB_FULL_ROUND: usize,
    const NB_PARTIAL_ROUND: usize,
    const NB_TOTAL_ROUND: usize,
    PARAMETERS,
    Env,
>(
    env: &mut Env,
    param: &PARAMETERS,
    init_state: [Env::Variable; STATE_SIZE],
) -> [Env::Variable; STATE_SIZE]
where
    PARAMETERS: PoseidonParams<F, STATE_SIZE, NB_TOTAL_ROUND>,
    Env: ColWriteCap<F, PoseidonColumn<STATE_SIZE, NB_FULL_ROUND, NB_PARTIAL_ROUND>>
        + HybridCopyCap<F, PoseidonColumn<STATE_SIZE, NB_FULL_ROUND, NB_PARTIAL_ROUND>>,
{
    // Write inputs
    init_state.iter().enumerate().for_each(|(i, value)| {
        env.write_column(PoseidonColumn::Input(i), value);
    });

    // Create, write, and constrain all other columns.
    apply_permutation(env, param)
}

/// Apply the HADES-based Poseidon to the state.
/// The environment has to be initialized with the input values.
/// It mimics the version described in the paper ["Poseidon: A New Hash
/// Function"](https://eprint.iacr.org/2019/458.pdf), figure 2. The construction
/// first starts with `NB_FULL_ROUND/2` full rounds, then `NB_PARTIAL_ROUND`
/// partial rounds, and finally `NB_FULL_ROUND/2` full rounds.
///
/// Each full rounds consists of the following steps:
/// - adding the round constants on the whole state
/// - applying the sbox on the whole state
/// - applying the linear layer on the whole state
///
/// Each partial round consists of the following steps:
/// - adding the round constants on the whole state
/// - applying the sbox on the first element of the state (FIXME: the
///   specification mentions the last element - map the implementation provided in
///   [mina_poseidon])
/// - applying the linear layer on the whole state
pub fn apply_permutation<
    F: PrimeField,
    const STATE_SIZE: usize,
    const NB_FULL_ROUND: usize,
    const NB_PARTIAL_ROUND: usize,
    const NB_TOTAL_ROUND: usize,
    PARAMETERS,
    Env,
>(
    env: &mut Env,
    param: &PARAMETERS,
) -> [Env::Variable; STATE_SIZE]
where
    PARAMETERS: PoseidonParams<F, STATE_SIZE, NB_TOTAL_ROUND>,
    Env: ColAccessCap<F, PoseidonColumn<STATE_SIZE, NB_FULL_ROUND, NB_PARTIAL_ROUND>>
        + HybridCopyCap<F, PoseidonColumn<STATE_SIZE, NB_FULL_ROUND, NB_PARTIAL_ROUND>>,
{
    // Checking that p - 1 is coprime with 5 as it has to be the case for the sbox
    {
        let one = BigUint::from(1u64);
        let p: BigUint = TryFrom::try_from(<F as PrimeField>::MODULUS).unwrap();
        let p_minus_one = p - one.clone();
        let five = BigUint::from(5u64);
        assert_eq!(p_minus_one.gcd(&five), one);
    }

    let mut state: [Env::Variable; STATE_SIZE] =
        core::array::from_fn(|i| env.read_column(PoseidonColumn::Input(i)));

    // Full rounds
    for i in 0..(NB_FULL_ROUND / 2) {
        state = compute_one_full_round::<
            F,
            STATE_SIZE,
            NB_FULL_ROUND,
            NB_PARTIAL_ROUND,
            NB_TOTAL_ROUND,
            PARAMETERS,
            Env,
        >(env, param, i, &state);
    }

    // Partial rounds
    for i in 0..NB_PARTIAL_ROUND {
        state = compute_one_partial_round::<
            F,
            STATE_SIZE,
            NB_FULL_ROUND,
            NB_PARTIAL_ROUND,
            NB_TOTAL_ROUND,
            PARAMETERS,
            Env,
        >(env, param, i, &state);
    }

    // Remaining full rounds
    for i in (NB_FULL_ROUND / 2)..NB_FULL_ROUND {
        state = compute_one_full_round::<
            F,
            STATE_SIZE,
            NB_FULL_ROUND,
            NB_PARTIAL_ROUND,
            NB_TOTAL_ROUND,
            PARAMETERS,
            Env,
        >(env, param, i, &state);
    }

    state
}

/// Compute one full round the Poseidon permutation
fn compute_one_full_round<
    F: PrimeField,
    const STATE_SIZE: usize,
    const NB_FULL_ROUND: usize,
    const NB_PARTIAL_ROUND: usize,
    const NB_TOTAL_ROUND: usize,
    PARAMETERS,
    Env,
>(
    env: &mut Env,
    param: &PARAMETERS,
    round: usize,
    state: &[Env::Variable; STATE_SIZE],
) -> [Env::Variable; STATE_SIZE]
where
    PARAMETERS: PoseidonParams<F, STATE_SIZE, NB_TOTAL_ROUND>,
    Env: ColAccessCap<F, PoseidonColumn<STATE_SIZE, NB_FULL_ROUND, NB_PARTIAL_ROUND>>
        + HybridCopyCap<F, PoseidonColumn<STATE_SIZE, NB_FULL_ROUND, NB_PARTIAL_ROUND>>,
{
    // We start at round 0
    // This implementation mimics the version described in
    // poseidon_block_cipher in the mina_poseidon crate.
    assert!(
        round < NB_FULL_ROUND,
        "The round index {:} is higher than the number of full rounds encoded in the type",
        round
    );

    // Adding the round constants
    let state: Vec<Env::Variable> = state
        .iter()
        .enumerate()
        .map(|(i, var)| {
            let offset = {
                if round < NB_FULL_ROUND / 2 {
                    0
                } else {
                    NB_PARTIAL_ROUND
                }
            };
            let rc = env.read_column(PoseidonColumn::RoundConstant(offset + round, i));
            var.clone() + rc
        })
        .collect();

    // Applying sbox
    // For a state transition from (x, y, z) to (x', y', z'), we use the
    // following columns shape:
    // x^2, x^4, x^5, x', y^2, y^4, y^5, y', z^2, z^4, z^5, z')
    //  0    1    2   3    4    5    6   7    8    9   10   11
    let nb_red = 4;
    let state: Vec<Env::Variable> = state
        .iter()
        .enumerate()
        .map(|(i, var)| {
            // x^2
            let var_square_col = PoseidonColumn::FullRound(round, nb_red * i);
            let var_square = env.hcopy(&(var.clone() * var.clone()), var_square_col);
            // x^4
            let var_four_col = PoseidonColumn::FullRound(round, nb_red * i + 1);
            let var_four = env.hcopy(&(var_square.clone() * var_square.clone()), var_four_col);
            // x^5
            let var_five_col = PoseidonColumn::FullRound(round, nb_red * i + 2);
            env.hcopy(&(var_four.clone() * var.clone()), var_five_col)
        })
        .collect();

    // Applying the linear layer
    let mds = PoseidonParams::mds(param);
    let state: Vec<Env::Variable> = mds
        .into_iter()
        .map(|m| {
            state
                .clone()
                .into_iter()
                .zip(m)
                .fold(Env::constant(F::zero()), |acc, (s_i, mds_i_j)| {
                    Env::constant(mds_i_j) * s_i.clone() + acc.clone()
                })
        })
        .collect();

    let res_state: Vec<Env::Variable> = state
        .iter()
        .enumerate()
        .map(|(i, res)| env.hcopy(res, PoseidonColumn::FullRound(round, nb_red * i + 3)))
        .collect();

    res_state
        .try_into()
        .expect("Resulting state must be of state size (={STATE_SIZE}) length")
}

/// Compute one partial round of the Poseidon permutation
fn compute_one_partial_round<
    F: PrimeField,
    const STATE_SIZE: usize,
    const NB_FULL_ROUND: usize,
    const NB_PARTIAL_ROUND: usize,
    const NB_TOTAL_ROUND: usize,
    PARAMETERS,
    Env,
>(
    env: &mut Env,
    param: &PARAMETERS,
    round: usize,
    state: &[Env::Variable; STATE_SIZE],
) -> [Env::Variable; STATE_SIZE]
where
    PARAMETERS: PoseidonParams<F, STATE_SIZE, NB_TOTAL_ROUND>,
    Env: ColAccessCap<F, PoseidonColumn<STATE_SIZE, NB_FULL_ROUND, NB_PARTIAL_ROUND>>
        + HybridCopyCap<F, PoseidonColumn<STATE_SIZE, NB_FULL_ROUND, NB_PARTIAL_ROUND>>,
{
    // We start at round 0
    assert!(
        round < NB_PARTIAL_ROUND,
        "The round index {:} is higher than the number of partial rounds encoded in the type",
        round
    );

    // Adding the round constants
    let mut state: Vec<Env::Variable> = state
        .iter()
        .enumerate()
        .map(|(i, var)| {
            let offset = NB_FULL_ROUND / 2;
            let rc = env.read_column(PoseidonColumn::RoundConstant(offset + round, i));
            var.clone() + rc
        })
        .collect();

    // Applying the sbox
    // Apply on the first element of the state
    // FIXME: the specification mentions the last element. However, this version
    // maps the iimplementation in [poseidon].
    {
        let var = state[0].clone();
        let var_square_col = PoseidonColumn::PartialRound(round, 0);
        let var_square = env.hcopy(&(var.clone() * var.clone()), var_square_col);
        // x^4
        let var_four_col = PoseidonColumn::PartialRound(round, 1);
        let var_four = env.hcopy(&(var_square.clone() * var_square.clone()), var_four_col);
        // x^5
        let var_five_col = PoseidonColumn::PartialRound(round, 2);
        let var_five = env.hcopy(&(var_four.clone() * var.clone()), var_five_col);
        state[0] = var_five;
    }

    // Applying the linear layer
    let mds = PoseidonParams::mds(param);
    let state: Vec<Env::Variable> = mds
        .into_iter()
        .map(|m| {
            state
                .clone()
                .into_iter()
                .zip(m)
                .fold(Env::constant(F::zero()), |acc, (s_i, mds_i_j)| {
                    Env::constant(mds_i_j) * s_i.clone() + acc.clone()
                })
        })
        .collect();

    let res_state: Vec<Env::Variable> = state
        .iter()
        .enumerate()
        .map(|(i, res)| env.hcopy(res, PoseidonColumn::PartialRound(round, 3 + i)))
        .collect();

    res_state
        .try_into()
        .expect("Resulting state must be of state size (={STATE_SIZE}) length")
}
