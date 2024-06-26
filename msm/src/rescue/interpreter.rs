//! Implement an interpreter for a specific instance of the Rescue inner permutation.
//! The Rescue inner permutation works on a state of size `STATE_SIZE`.
//! The user is responsible to provide the correct number of rounds for the
//! given field and the state size.
//! Also, it is hard-coded that the substitution is `7`. The user must verify
//! that `7` is coprime with `p - 1` where `p` is the order the field.

use ark_ff::{FpParameters, PrimeField};
use num_bigint::BigUint;
use num_integer::Integer;
use o1_utils::FieldHelpers;

use crate::{
    circuit_design::{ColAccessCap, HybridCopyCap},
    rescue::columns::RescueColumn,
};

/// Represents the parameters of the instance of the Rescue permutation.
/// Constants are the round constants for each round, and MDS is the matrix used
/// by the linear layer.
/// The type is parametrized by the field, the state size, and the number of rounds.
// IMPROVEME merge constants and mds in a flat array, to use the CPU cache
pub trait Params<F: PrimeField, const STATE_SIZE: usize, const NB_ROUNDS: usize> {
    fn constants(&self) -> [[[F; STATE_SIZE]; 2]; NB_ROUNDS];
    fn mds(&self) -> [[F; STATE_SIZE]; STATE_SIZE];
    fn get_alpha(&self) -> F;
    fn get_alpha_inv(&self) -> F;
}

/// Apply the whole permutation of the Rescue instance.

pub fn apply_permutation<
    F: PrimeField,
    P: Params<F, STATE_SIZE, NB_ROUND>,
    const STATE_SIZE: usize,
    const NB_ROUND: usize,
    Env,
>(
    env: &mut Env,
    state: &mut [F; STATE_SIZE],
    params: &P,
) where
    Env: ColAccessCap<F, RescueColumn<STATE_SIZE, NB_ROUND>>
        + HybridCopyCap<F, RescueColumn<STATE_SIZE, NB_ROUND>>,
{
    // Checking that p - 1 is coprime with 7 as it has to be the case for the sbox
    {
        let one = BigUint::from(1u64);
        let p: BigUint = TryFrom::try_from(<F as PrimeField>::Params::MODULUS).unwrap();
        let p_minus_one = p - one.clone();
        let alpha_biguint = params.get_alpha().to_biguint();
        assert_eq!(p_minus_one.gcd(&alpha_biguint), one);
    }

    for i in 0..NB_ROUND {
        let state: [RescueColumn<STATE_SIZE, NB_ROUND>; STATE_SIZE] = {
            if i == 0 {
                std::array::from_fn(RescueColumn::Input)
            } else {
                std::array::from_fn(|j| RescueColumn::Round(i - 1, STATE_SIZE + j))
            }
        };
        compute_one_round::<F, STATE_SIZE, NB_ROUND, P, Env>(env, &params, i, &state);
    }
}

/// Apply one round (sbox alpha + sbox alpha inv) of the Rescue permutation.

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
    elements: &[RescueColumn<STATE_SIZE, NB_FULL_ROUND>; STATE_SIZE],
) where
    F: PrimeField,
    PARAMETERS: Params<F, STATE_SIZE, NB_FULL_ROUND>,
    Env: ColAccessCap<F, RescueColumn<STATE_SIZE, NB_FULL_ROUND>>
        + HybridCopyCap<F, RescueColumn<STATE_SIZE, NB_FULL_ROUND>>,
{
    // We start at round 0
    // This implementation mimicks the version described in
    // poseidon_block_cipher in the mina_poseidon crate.
    assert!(
        round < NB_FULL_ROUND,
        "The round index {:} is higher than the number of full rounds encoded in the type",
        round
    );
    // // Applying sbox
    // let state: Vec<Env::Variable> = elements
    //     .iter()
    //     .map(|x| {
    //         let x_col = env.read_column(x.clone());
    //         let x_square = x_col.clone() * x_col.clone();
    //         let x_four = x_square.clone() * x_square.clone();
    //         x_four.clone() * x_square.clone() * x_col.clone()
    //     })
    //     .collect();

    // // Applying the linear layer
    // let mds = Params::mds(param);
    // let state: Vec<Env::Variable> = mds
    //     .into_iter()
    //     .map(|m| {
    //         state
    //             .clone()
    //             .into_iter()
    //             .zip(m)
    //             .fold(Env::constant(F::zero()), |acc, (s_i, mds_i_j)| {
    //                 Env::constant(mds_i_j) * s_i.clone() + acc.clone()
    //             })
    //     })
    //     .collect();

    // // Adding the round constants
    // let state: Vec<Env::Variable> = state
    //     .iter()
    //     .enumerate()
    //     .map(|(i, x)| {
    //         let rc = env.read_column(RescueColumn::RoundConstant(round, i));
    //         x.clone() + rc
    //     })
    //     .collect();

    // state.iter().enumerate().for_each(|(i, res)| {
    //     env.hcopy(res, RescueColumn::Round(round, i));
    // });
}
