//! Implement an interpreter for a specific instance of the Poseidon inner permutation.
//! The Poseidon construction is defined in the paper ["Poseidon: A New Hash
//! Function"](https://eprint.iacr.org/2019/458.pdf).
//! The Poseidon instance works on a state of size `STATE_SIZE` and is designed
//! to work only with full rounds. As a reminder, the Poseidon permutation is a
//! mapping from `F^STATE_SIZE` to `F^STATE_SIZE`.
//! The user is responsible to provide the correct number of full rounds for the
//! given field and the state.
//! Also, it is hard-coded that the substitution is `7`. The user must verify
//! that `7` is coprime with `p - 1` where `p` is the order the field.
//! The constants and matrix can be generated the file
//! `poseidon/src/pasta/params.sage`

use crate::poseidon_55_0_7_3_7::columns::PoseidonColumn;
use ark_ff::PrimeField;
use kimchi_msm::circuit_design::{ColAccessCap, ColWriteCap, HybridCopyCap};
use num_bigint::BigUint;
use num_integer::Integer;

/// Represents the parameters of the instance of the Poseidon permutation.
/// Constants are the round constants for each round, and MDS is the matrix used
/// by the linear layer.
/// The type is parametrized by the field, the state size, and the number of full rounds.
/// Note that the parameters are only for instances using full rounds.
// IMPROVEME merge constants and mds in a flat array, to use the CPU cache
// IMPROVEME generalise init_state for more than 3 elements
pub trait PoseidonParams<F: PrimeField, const STATE_SIZE: usize, const NB_FULL_ROUNDS: usize> {
    fn constants(&self) -> [[F; STATE_SIZE]; NB_FULL_ROUNDS];
    fn mds(&self) -> [[F; STATE_SIZE]; STATE_SIZE];
}

/// Populates and checks one poseidon invocation.
pub fn poseidon_circuit<
    F: PrimeField,
    const STATE_SIZE: usize,
    const NB_FULL_ROUND: usize,
    PARAMETERS,
    Env,
>(
    env: &mut Env,
    param: &PARAMETERS,
    init_state: [Env::Variable; STATE_SIZE],
) -> [Env::Variable; STATE_SIZE]
where
    PARAMETERS: PoseidonParams<F, STATE_SIZE, NB_FULL_ROUND>,
    Env: ColWriteCap<F, PoseidonColumn<STATE_SIZE, NB_FULL_ROUND>>
        + HybridCopyCap<F, PoseidonColumn<STATE_SIZE, NB_FULL_ROUND>>,
{
    // Write inputs
    init_state.iter().enumerate().for_each(|(i, value)| {
        env.write_column(PoseidonColumn::Input(i), value);
    });

    // Create, write, and constrain all other columns.
    apply_permutation(env, param)
}

/// Apply the whole permutation of Poseidon to the state.
/// The environment has to be initialized with the input values.
pub fn apply_permutation<
    F: PrimeField,
    const STATE_SIZE: usize,
    const NB_FULL_ROUND: usize,
    PARAMETERS,
    Env,
>(
    env: &mut Env,
    param: &PARAMETERS,
) -> [Env::Variable; STATE_SIZE]
where
    PARAMETERS: PoseidonParams<F, STATE_SIZE, NB_FULL_ROUND>,
    Env: ColAccessCap<F, PoseidonColumn<STATE_SIZE, NB_FULL_ROUND>>
        + HybridCopyCap<F, PoseidonColumn<STATE_SIZE, NB_FULL_ROUND>>,
{
    // Checking that p - 1 is coprime with 7 as it has to be the case for the sbox
    {
        let one = BigUint::from(1u64);
        let p: BigUint = TryFrom::try_from(<F as PrimeField>::MODULUS).unwrap();
        let p_minus_one = p - one.clone();
        let seven = BigUint::from(7u64);
        assert_eq!(p_minus_one.gcd(&seven), one);
    }

    let mut final_state: [Env::Variable; STATE_SIZE] =
        core::array::from_fn(|_| Env::constant(F::zero()));

    for i in 0..NB_FULL_ROUND {
        let state: [PoseidonColumn<STATE_SIZE, NB_FULL_ROUND>; STATE_SIZE] = {
            if i == 0 {
                core::array::from_fn(PoseidonColumn::Input)
            } else {
                core::array::from_fn(|j| PoseidonColumn::Round(i - 1, j))
            }
        };
        let round_res = compute_one_round::<F, STATE_SIZE, NB_FULL_ROUND, PARAMETERS, Env>(
            env, param, i, &state,
        );

        if i == NB_FULL_ROUND - 1 {
            final_state = round_res
        }
    }

    final_state
}

/// Compute one round the Poseidon permutation
fn compute_one_round<
    F: PrimeField,
    const STATE_SIZE: usize,
    const NB_FULL_ROUND: usize,
    PARAMETERS,
    Env,
>(
    env: &mut Env,
    param: &PARAMETERS,
    round: usize,
    elements: &[PoseidonColumn<STATE_SIZE, NB_FULL_ROUND>; STATE_SIZE],
) -> [Env::Variable; STATE_SIZE]
where
    PARAMETERS: PoseidonParams<F, STATE_SIZE, NB_FULL_ROUND>,
    Env: ColAccessCap<F, PoseidonColumn<STATE_SIZE, NB_FULL_ROUND>>
        + HybridCopyCap<F, PoseidonColumn<STATE_SIZE, NB_FULL_ROUND>>,
{
    // We start at round 0
    // This implementation mimics the version described in
    // poseidon_block_cipher in the mina_poseidon crate.
    assert!(
        round < NB_FULL_ROUND,
        "The round index {:} is higher than the number of full rounds encoded in the type",
        round
    );
    // Applying sbox
    let state: Vec<Env::Variable> = elements
        .iter()
        .map(|x| {
            let x_col = env.read_column(*x);
            let x_square = x_col.clone() * x_col.clone();
            let x_four = x_square.clone() * x_square.clone();
            x_four.clone() * x_square.clone() * x_col.clone()
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

    // Adding the round constants
    let state: Vec<Env::Variable> = state
        .iter()
        .enumerate()
        .map(|(i, x)| {
            let rc = env.read_column(PoseidonColumn::RoundConstant(round, i));
            x.clone() + rc
        })
        .collect();

    let res_state: Vec<Env::Variable> = state
        .iter()
        .enumerate()
        .map(|(i, res)| env.hcopy(res, PoseidonColumn::Round(round, i)))
        .collect();

    res_state
        .try_into()
        .expect("Resulting state must be of STATE_SIZE length")
}
