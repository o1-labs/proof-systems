//! Hash circuit gadgets.
//!
//! This module contains circuit gadgets for cryptographic hash functions.
//!
//! ## Sponge Construction
//!
//! The [`Sponge`] trait provides an abstraction over the sponge construction,
//! allowing circuits like Schnorr signature verification to be generic over
//! the underlying permutation.
//!
//! A sponge has three operations:
//! - **absorb**: Add input values to the rate portion of the state
//! - **permute**: Apply the internal permutation (all rounds)
//! - **squeeze**: Extract output from the rate portion of the state
//!
//! Currently supported permutations:
//! - **Poseidon (x^5, 60 rounds)**: Arrabbiata's default Poseidon with x^5 S-box
//! - **Poseidon Kimchi (x^7, 55 rounds)**: Mina's Kimchi-compatible Poseidon with x^7 S-box

use ark_ff::PrimeField;
use core::fmt::Debug;

use crate::circuit::{CircuitEnv, SelectorEnv, StepCircuit};

mod poseidon;
mod poseidon_kimchi;

pub use poseidon::{
    PoseidonAbsorbCircuit, PoseidonPermutationCircuit, PoseidonRoundCircuit, NUMBER_FULL_ROUNDS,
    ROUNDS_PER_ROW, ROWS_FOR_PERMUTATION,
};
pub use poseidon_kimchi::{
    PoseidonKimchiPermutationCircuit, PoseidonKimchiRoundCircuit, KIMCHI_FULL_ROUNDS,
    KIMCHI_ROUNDS_PER_ROW, KIMCHI_ROWS_FOR_PERMUTATION,
};

/// A trait for sponge constructions in circuits.
///
/// The sponge construction is a mode of operation for cryptographic
/// permutations that enables variable-length input/output hashing.
///
/// ## Parameters
///
/// - `STATE_SIZE`: The total width of the sponge state (e.g., 3 for Poseidon)
/// - `RATE`: Number of elements absorbed per call (e.g., 2)
/// - Capacity is implicitly `STATE_SIZE - RATE` (e.g., 1)
///
/// ## Operations
///
/// - **absorb**: Add input values to the rate portion of the state
/// - **permute**: Apply the internal permutation (all rounds)
/// - **squeeze**: Extract output from the rate portion of the state
///
/// ## Usage Pattern
///
/// ```text
/// 1. Initialize state to zeros
/// 2. Absorb values (add to rate portion)
/// 3. Permute (apply full permutation)
/// 4. Repeat 2-3 as needed
/// 5. Squeeze (read from rate portion)
/// ```
///
/// # Type Parameters
///
/// - `F`: The prime field for circuit values
/// - `STATE_SIZE`: The total width of the sponge state
/// - `RATE`: Number of elements absorbed per call
///
/// # Example
///
/// ```ignore
/// // Create a sponge with state_size=3, rate=2
/// let sponge = PoseidonSponge::new(params);
///
/// // Initialize state
/// let zero = env.zero();
/// let state = [zero.clone(), zero.clone(), zero];
///
/// // Absorb-permute-squeeze cycle
/// let state = sponge.absorb(env, &state, [v1, v2]);
/// let state = sponge.permute(env, &state);
/// let output = sponge.squeeze(&state);
/// ```
pub trait Sponge<F: PrimeField, const STATE_SIZE: usize, const RATE: usize>:
    Clone + Debug + Send + Sync
{
    /// Absorb field elements into the sponge state.
    ///
    /// This adds the values to the rate portion of the state,
    /// leaving the capacity portion unchanged.
    ///
    /// Returns the new state after absorption.
    fn absorb<E: CircuitEnv<F>>(
        &self,
        env: &mut E,
        state: &[E::Variable; STATE_SIZE],
        values: [E::Variable; RATE],
    ) -> [E::Variable; STATE_SIZE];

    /// Apply the full internal permutation (all rounds).
    ///
    /// Returns the new state after permutation.
    fn permute<E: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        env: &mut E,
        state: &[E::Variable; STATE_SIZE],
    ) -> [E::Variable; STATE_SIZE];

    /// Squeeze a single field element from the sponge state.
    ///
    /// By default, returns the first rate element (state[0]).
    /// This matches mina-poseidon convention where rate is at indices [0..RATE)
    /// and capacity is at indices [RATE..STATE_SIZE).
    fn squeeze<E: CircuitEnv<F>>(&self, state: &[E::Variable; STATE_SIZE]) -> E::Variable {
        // Rate elements are at the beginning [0..RATE), capacity follows
        // For STATE_SIZE=3, RATE=2: state[0], state[1] are rate; state[2] is capacity
        state[0].clone()
    }

    /// Absorb field elements (for witness generation).
    fn absorb_witness(
        &self,
        state: &[F; STATE_SIZE],
        values: [F; RATE],
    ) -> [F; STATE_SIZE];

    /// Apply the full internal permutation (for witness generation).
    fn permute_witness(&self, state: &[F; STATE_SIZE]) -> [F; STATE_SIZE];

    /// Squeeze a single field element (for witness generation).
    ///
    /// By default, returns the first rate element (state[0]).
    fn squeeze_witness(&self, state: &[F; STATE_SIZE]) -> F {
        state[0]
    }

    /// Returns the number of rows needed for one permutation.
    fn permutation_rows(&self) -> usize;
}

// ============================================================================
// Poseidon x^5 Sponge (60 rounds) - Arrabbiata default
// ============================================================================

use mina_poseidon::poseidon::ArithmeticSpongeParams;

/// Poseidon state size (width of the sponge).
pub const POSEIDON_STATE_SIZE: usize = 3;

/// Poseidon rate (number of elements absorbed per call).
pub const POSEIDON_RATE: usize = 2;

/// Poseidon sponge circuit with x^5 S-box (Arrabbiata default).
///
/// This is the default hash function used in Arrabbiata with 60 full rounds.
/// State size is 3, rate is 2, capacity is 1.
///
/// # Type Parameters
///
/// - `F`: The prime field for circuit values
/// - `FULL_ROUNDS`: Number of full rounds (typically 60)
#[derive(Clone, Debug)]
pub struct PoseidonSponge<F: PrimeField, const FULL_ROUNDS: usize> {
    /// Poseidon parameters (MDS matrix and round constants)
    pub params: &'static ArithmeticSpongeParams<F, FULL_ROUNDS>,
}

impl<F: PrimeField, const FULL_ROUNDS: usize> PoseidonSponge<F, FULL_ROUNDS> {
    /// Create a new Poseidon sponge with the given parameters.
    pub fn new(params: &'static ArithmeticSpongeParams<F, FULL_ROUNDS>) -> Self {
        Self { params }
    }
}

impl<F: PrimeField, const FULL_ROUNDS: usize> Sponge<F, POSEIDON_STATE_SIZE, POSEIDON_RATE>
    for PoseidonSponge<F, FULL_ROUNDS>
{
    fn absorb<E: CircuitEnv<F>>(
        &self,
        env: &mut E,
        state: &[E::Variable; POSEIDON_STATE_SIZE],
        values: [E::Variable; POSEIDON_RATE],
    ) -> [E::Variable; POSEIDON_STATE_SIZE] {
        // Absorb by adding to the rate portion of the state
        // Rate is at indices [0, 1], capacity at index 2 (mina-poseidon convention)
        let absorbed_0 = state[0].clone() + values[0].clone();
        let state_0 = {
            let pos = env.allocate();
            env.write_column(pos, absorbed_0.clone())
        };
        env.assert_eq(&state_0, &absorbed_0);

        let absorbed_1 = state[1].clone() + values[1].clone();
        let state_1 = {
            let pos = env.allocate();
            env.write_column(pos, absorbed_1.clone())
        };
        env.assert_eq(&state_1, &absorbed_1);

        [state_0, state_1, state[2].clone()]
    }

    fn permute<E: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        env: &mut E,
        state: &[E::Variable; POSEIDON_STATE_SIZE],
    ) -> [E::Variable; POSEIDON_STATE_SIZE] {
        let perm = PoseidonPermutationCircuit::new(self.params);
        perm.synthesize(env, state)
    }

    fn absorb_witness(
        &self,
        state: &[F; POSEIDON_STATE_SIZE],
        values: [F; POSEIDON_RATE],
    ) -> [F; POSEIDON_STATE_SIZE] {
        // Absorb by adding to the rate portion (indices 0, 1)
        // Capacity at index 2 is unchanged (mina-poseidon convention)
        [state[0] + values[0], state[1] + values[1], state[2]]
    }

    fn permute_witness(&self, state: &[F; POSEIDON_STATE_SIZE]) -> [F; POSEIDON_STATE_SIZE] {
        let perm = PoseidonPermutationCircuit::new(self.params);
        perm.output(state)
    }

    fn permutation_rows(&self) -> usize {
        FULL_ROUNDS / ROUNDS_PER_ROW
    }
}

// ============================================================================
// Poseidon Kimchi x^7 Sponge (55 rounds) - Mina compatible
// ============================================================================

/// Poseidon Kimchi sponge circuit with x^7 S-box.
///
/// This is the Kimchi-compatible hash function used in Mina with 55 full rounds.
/// State size is 3, rate is 2, capacity is 1 (same as standard Poseidon).
///
/// # Type Parameters
///
/// - `F`: The prime field for circuit values
#[derive(Clone, Debug)]
pub struct PoseidonKimchiSponge<F: PrimeField> {
    /// Poseidon Kimchi parameters (MDS matrix and round constants)
    pub params: &'static ArithmeticSpongeParams<F, KIMCHI_FULL_ROUNDS>,
}

impl<F: PrimeField> PoseidonKimchiSponge<F> {
    /// Create a new Poseidon Kimchi sponge with the given parameters.
    pub fn new(params: &'static ArithmeticSpongeParams<F, KIMCHI_FULL_ROUNDS>) -> Self {
        Self { params }
    }
}

impl<F: PrimeField> Sponge<F, POSEIDON_STATE_SIZE, POSEIDON_RATE> for PoseidonKimchiSponge<F> {
    fn absorb<E: CircuitEnv<F>>(
        &self,
        env: &mut E,
        state: &[E::Variable; POSEIDON_STATE_SIZE],
        values: [E::Variable; POSEIDON_RATE],
    ) -> [E::Variable; POSEIDON_STATE_SIZE] {
        // Absorb by adding to the rate portion of the state
        // Rate is at indices [0, 1], capacity at index 2 (mina-poseidon convention)
        let absorbed_0 = state[0].clone() + values[0].clone();
        let state_0 = {
            let pos = env.allocate();
            env.write_column(pos, absorbed_0.clone())
        };
        env.assert_eq(&state_0, &absorbed_0);

        let absorbed_1 = state[1].clone() + values[1].clone();
        let state_1 = {
            let pos = env.allocate();
            env.write_column(pos, absorbed_1.clone())
        };
        env.assert_eq(&state_1, &absorbed_1);

        [state_0, state_1, state[2].clone()]
    }

    fn permute<E: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        env: &mut E,
        state: &[E::Variable; POSEIDON_STATE_SIZE],
    ) -> [E::Variable; POSEIDON_STATE_SIZE] {
        let perm = PoseidonKimchiPermutationCircuit::new(self.params);
        perm.synthesize(env, state)
    }

    fn absorb_witness(
        &self,
        state: &[F; POSEIDON_STATE_SIZE],
        values: [F; POSEIDON_RATE],
    ) -> [F; POSEIDON_STATE_SIZE] {
        // Absorb by adding to the rate portion (indices 0, 1)
        // Capacity at index 2 is unchanged (mina-poseidon convention)
        [state[0] + values[0], state[1] + values[1], state[2]]
    }

    fn permute_witness(&self, state: &[F; POSEIDON_STATE_SIZE]) -> [F; POSEIDON_STATE_SIZE] {
        let perm = PoseidonKimchiPermutationCircuit::new(self.params);
        perm.output(state)
    }

    fn permutation_rows(&self) -> usize {
        KIMCHI_ROWS_FOR_PERMUTATION
    }
}
