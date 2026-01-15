//! Poseidon hash function gadgets.
//!
//! This module implements the Poseidon hash function as typed gadgets that can be
//! composed to build the IVC verifier circuit.
//!
//! ## Gadgets
//!
//! - [`PoseidonRoundGadget`]: A single step processing 5 Poseidon rounds.
//! - [`PoseidonPermutationGadget`]: Full 60-round Poseidon permutation (chains 12 round gadgets).
//! - [`PoseidonAbsorbGadget`]: Absorbs 2 field elements into the sponge state.
//!
//! ## Layout
//!
//! The Poseidon gadget processes 5 full rounds per row:
//!
//! ```text
//! | C1 | C2 | C3 | C4 | C5 | C6 | C7 | C8 | C9 | C10 | C11 | C12 | C13 | C14 | C15 |
//! | -- | -- | -- | -- | -- | -- | -- | -- | -- | --- | --- | --- | --- | --- | --- |
//! | x  | y  | z  | a1 | a2 | a3 | b1 | b2 | b3 | c1  | c2  | c3  | d1  | d2  | d3  |
//! | o1 | o2 | o3 |
//! ```
//!
//! Where (x, y, z) is the input state and (o1, o2, o3) is the output after 5 rounds.
//!
//! ## Parameters
//!
//! Uses Poseidon with:
//! - State width: 3
//! - Full rounds: 60
//! - S-box: x^5
//! - MDS matrix and round constants from mina-poseidon

use ark_ff::PrimeField;
use mina_poseidon::poseidon::ArithmeticSpongeParams;

use crate::{
    circuit::{CircuitEnv, SelectorEnv},
    circuits::{
        gadget::{PoseidonState3, Position, Row, TypedGadget},
        selector::{QPoseidonAbsorb, QPoseidonRound},
    },
};

/// Poseidon state size (width of the sponge).
pub const STATE_SIZE: usize = 3;

/// Total number of full rounds in the Poseidon permutation.
pub const NUMBER_FULL_ROUNDS: usize = 60;

/// Number of Poseidon rounds processed per gadget step.
/// With 15 columns and width 3, we can fit 5 rounds per row.
pub const ROUNDS_PER_ROW: usize = 5;

/// Total number of rows needed for the full Poseidon permutation.
/// 60 rounds / 5 rounds per row = 12 rows
pub const ROWS_FOR_PERMUTATION: usize = NUMBER_FULL_ROUNDS / ROUNDS_PER_ROW;

// ============================================================================
// PoseidonRoundGadget - Single step of 5 rounds
// ============================================================================

/// Input positions for PoseidonRoundGadget: state at columns 0, 1, 2 on current row.
const POSEIDON_ROUND_INPUT_POSITIONS: &[Position] = &[
    Position {
        col: 0,
        row: Row::Curr,
    },
    Position {
        col: 1,
        row: Row::Curr,
    },
    Position {
        col: 2,
        row: Row::Curr,
    },
];

/// Output positions for PoseidonRoundGadget: state at columns 0, 1, 2 on next row.
const POSEIDON_ROUND_OUTPUT_POSITIONS: &[Position] = &[
    Position {
        col: 0,
        row: Row::Next,
    },
    Position {
        col: 1,
        row: Row::Next,
    },
    Position {
        col: 2,
        row: Row::Next,
    },
];

/// Poseidon round gadget processing 5 rounds starting at a specific round.
///
/// This gadget processes 5 Poseidon full rounds on a 3-element state.
/// It is designed to be chained: 12 gadgets complete the full 60-round permutation.
///
/// # Type Parameters
///
/// - `F`: The field type (must match the Poseidon parameters)
/// - `FULL_ROUNDS`: The total number of Poseidon rounds (typically 60)
/// - `STARTING_ROUND`: The round index to start from (must be multiple of 5: 0, 5, 10, ..., 55)
///
/// # Selector
///
/// Uses `QPoseidonRound<STARTING_ROUND>` which maps to index `11 + STARTING_ROUND / 5`.
#[derive(Clone, Debug)]
pub struct PoseidonRoundGadget<F: PrimeField, const FULL_ROUNDS: usize, const STARTING_ROUND: usize>
{
    /// Poseidon parameters (MDS matrix and round constants)
    pub params: &'static ArithmeticSpongeParams<F, FULL_ROUNDS>,
}

impl<F: PrimeField, const FULL_ROUNDS: usize, const STARTING_ROUND: usize>
    PoseidonRoundGadget<F, FULL_ROUNDS, STARTING_ROUND>
{
    /// Create a new Poseidon round gadget.
    ///
    /// # Panics
    ///
    /// Panics at compile time via const assertion if STARTING_ROUND is invalid.
    pub fn new(params: &'static ArithmeticSpongeParams<F, FULL_ROUNDS>) -> Self {
        // Compile-time checks via const evaluation
        const { assert!(STARTING_ROUND.is_multiple_of(ROUNDS_PER_ROW)) };
        const { assert!(STARTING_ROUND + ROUNDS_PER_ROW <= FULL_ROUNDS) };
        Self { params }
    }

    /// Compute one round of Poseidon: S-box -> MDS -> ARK
    fn round(&self, state: [F; STATE_SIZE], round: usize) -> [F; STATE_SIZE] {
        // S-box: x^5
        let state: [F; STATE_SIZE] = [state[0].pow([5]), state[1].pow([5]), state[2].pow([5])];

        // MDS matrix multiplication
        let mds = &self.params.mds;
        let mut new_state = [F::zero(); STATE_SIZE];
        for i in 0..STATE_SIZE {
            for j in 0..STATE_SIZE {
                new_state[i] += mds[i][j] * state[j];
            }
        }

        // Add round constants
        let rc = &self.params.round_constants[round];
        [
            new_state[0] + rc[0],
            new_state[1] + rc[1],
            new_state[2] + rc[2],
        ]
    }

    /// Internal synthesize method that can be called with runtime starting_round.
    fn synthesize_rounds<E: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        env: &mut E,
        input: &[E::Variable; STATE_SIZE],
        starting_round: usize,
    ) -> [E::Variable; STATE_SIZE] {
        let mut state = input.clone();

        // Process 5 rounds
        // Layout: | x | y | z | s0 | s1 | s2 | s3 | s4 | s5 | s6 | s7 | s8 | s9 | s10 | s11 |
        //         | o0| o1| o2|
        // Where (x,y,z) = input, (s0-s2) = after round 0, ..., (s9-s11) = after round 3
        // (o0-o2) = after round 4 (on next row)
        for round_offset in 0..ROUNDS_PER_ROW {
            let round = starting_round + round_offset;
            let is_last_round = round_offset == ROUNDS_PER_ROW - 1;

            // S-box: x^5 = x^4 * x = (x^2)^2 * x
            // We compute sbox inline (no separate allocation) to save columns.
            // The constraint degree is 5 from x^5 term.
            let mut sbox_exprs = [env.zero(), env.zero(), env.zero()];
            for i in 0..STATE_SIZE {
                let x2 = state[i].clone() * state[i].clone();
                let x4 = x2.clone() * x2;
                let x5 = x4 * state[i].clone();
                sbox_exprs[i] = x5;
            }

            // MDS matrix multiplication and add round constants
            let mds = &self.params.mds;
            let rc = &self.params.round_constants[round];

            for i in 0..STATE_SIZE {
                let c0 = env.constant(mds[i][0]);
                let c1 = env.constant(mds[i][1]);
                let c2 = env.constant(mds[i][2]);

                let term0 = c0 * sbox_exprs[0].clone();
                let term1 = c1 * sbox_exprs[1].clone();
                let term2 = c2 * sbox_exprs[2].clone();

                let acc = term0 + term1 + term2;
                let rc_const = env.constant(rc[i]);
                let mds_result = acc + rc_const;

                let new_state_witness = if is_last_round {
                    let pos = env.allocate_next_row();
                    let w = env.write_column(pos, mds_result.clone());
                    env.assert_eq(&w, &mds_result);
                    w
                } else {
                    let w = {
                        let pos = env.allocate();
                        env.write_column(pos, mds_result.clone())
                    };
                    env.assert_eq(&w, &mds_result);
                    w
                };

                state[i] = new_state_witness;
            }
        }

        state
    }

    /// Compute output for 5 rounds starting at starting_round.
    fn output_rounds(&self, state: [F; STATE_SIZE], starting_round: usize) -> [F; STATE_SIZE] {
        let mut result = state;
        for round_offset in 0..ROUNDS_PER_ROW {
            let round = starting_round + round_offset;
            result = self.round(result, round);
        }
        result
    }
}

impl<F: PrimeField, const FULL_ROUNDS: usize, const STARTING_ROUND: usize> TypedGadget<F>
    for PoseidonRoundGadget<F, FULL_ROUNDS, STARTING_ROUND>
{
    type Selector = QPoseidonRound<STARTING_ROUND>;
    type Input<V: Clone> = PoseidonState3<V>;
    type Output<V: Clone> = PoseidonState3<V>;

    const NAME: &'static str = "poseidon-round";
    const DESCRIPTION: &'static str = "Poseidon hash round";
    const ARITY: usize = 3;
    const ROWS: usize = 1;

    fn input_positions() -> &'static [Position] {
        POSEIDON_ROUND_INPUT_POSITIONS
    }

    fn output_positions() -> &'static [Position] {
        POSEIDON_ROUND_OUTPUT_POSITIONS
    }

    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        env: &mut E,
        input: Self::Input<E::Variable>,
    ) -> Self::Output<E::Variable> {
        let state = input.into_array();
        let result = self.synthesize_rounds(env, &state, STARTING_ROUND);
        PoseidonState3::new(result)
    }

    fn output(&self, input: &Self::Input<F>) -> Self::Output<F> {
        let result = self.output_rounds(*input.as_array(), STARTING_ROUND);
        PoseidonState3::new(result)
    }
}

// ============================================================================
// PoseidonPermutationGadget - Full 60-round permutation
// ============================================================================

/// Input positions for PoseidonPermutationGadget: state at columns 0, 1, 2 on current row.
const POSEIDON_PERMUTATION_INPUT_POSITIONS: &[Position] = &[
    Position {
        col: 0,
        row: Row::Curr,
    },
    Position {
        col: 1,
        row: Row::Curr,
    },
    Position {
        col: 2,
        row: Row::Curr,
    },
];

/// Output positions for PoseidonPermutationGadget: state at columns 0, 1, 2 on next row.
/// Note: The output is on the next row relative to the final (12th) round step.
const POSEIDON_PERMUTATION_OUTPUT_POSITIONS: &[Position] = &[
    Position {
        col: 0,
        row: Row::Next,
    },
    Position {
        col: 1,
        row: Row::Next,
    },
    Position {
        col: 2,
        row: Row::Next,
    },
];

/// Full Poseidon permutation gadget (60 rounds).
///
/// This gadget chains 12 `PoseidonRoundGadget` steps to complete
/// the full Poseidon permutation. Each step uses a different selector
/// (QPoseidonRound<0>, QPoseidonRound<5>, ..., QPoseidonRound<55>).
///
/// # Type Parameters
///
/// - `F`: The field type
/// - `FULL_ROUNDS`: Total number of rounds (typically 60)
///
/// # Selector
///
/// Uses `QPoseidonRound<0>` as the primary selector (first round's selector).
#[derive(Clone, Debug)]
pub struct PoseidonPermutationGadget<F: PrimeField, const FULL_ROUNDS: usize> {
    /// Poseidon parameters
    pub params: &'static ArithmeticSpongeParams<F, FULL_ROUNDS>,
}

impl<F: PrimeField, const FULL_ROUNDS: usize> PoseidonPermutationGadget<F, FULL_ROUNDS> {
    /// Create a new full Poseidon permutation gadget.
    pub fn new(params: &'static ArithmeticSpongeParams<F, FULL_ROUNDS>) -> Self {
        Self { params }
    }

    /// Number of rows needed for this permutation (FULL_ROUNDS / 5).
    pub const fn num_rows() -> usize {
        FULL_ROUNDS / ROUNDS_PER_ROW
    }
}

impl<F: PrimeField, const FULL_ROUNDS: usize> TypedGadget<F>
    for PoseidonPermutationGadget<F, FULL_ROUNDS>
{
    type Selector = QPoseidonRound<0>;
    type Input<V: Clone> = PoseidonState3<V>;
    type Output<V: Clone> = PoseidonState3<V>;

    const NAME: &'static str = "poseidon-permutation";
    const DESCRIPTION: &'static str = "Poseidon full permutation";
    const ARITY: usize = 3;
    const ROWS: usize = FULL_ROUNDS / ROUNDS_PER_ROW;

    fn input_positions() -> &'static [Position] {
        POSEIDON_PERMUTATION_INPUT_POSITIONS
    }

    fn output_positions() -> &'static [Position] {
        POSEIDON_PERMUTATION_OUTPUT_POSITIONS
    }

    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        env: &mut E,
        input: Self::Input<E::Variable>,
    ) -> Self::Output<E::Variable> {
        // Chain all 12 round gadgets explicitly to use correct selectors
        // Each round gadget has its own selector type (QPoseidonRound<0>, <5>, ..., <55>)
        let g0 = PoseidonRoundGadget::<F, FULL_ROUNDS, 0>::new(self.params);
        let g5 = PoseidonRoundGadget::<F, FULL_ROUNDS, 5>::new(self.params);
        let g10 = PoseidonRoundGadget::<F, FULL_ROUNDS, 10>::new(self.params);
        let g15 = PoseidonRoundGadget::<F, FULL_ROUNDS, 15>::new(self.params);
        let g20 = PoseidonRoundGadget::<F, FULL_ROUNDS, 20>::new(self.params);
        let g25 = PoseidonRoundGadget::<F, FULL_ROUNDS, 25>::new(self.params);
        let g30 = PoseidonRoundGadget::<F, FULL_ROUNDS, 30>::new(self.params);
        let g35 = PoseidonRoundGadget::<F, FULL_ROUNDS, 35>::new(self.params);
        let g40 = PoseidonRoundGadget::<F, FULL_ROUNDS, 40>::new(self.params);
        let g45 = PoseidonRoundGadget::<F, FULL_ROUNDS, 45>::new(self.params);
        let g50 = PoseidonRoundGadget::<F, FULL_ROUNDS, 50>::new(self.params);
        let g55 = PoseidonRoundGadget::<F, FULL_ROUNDS, 55>::new(self.params);

        let state = g0.synthesize(env, input);
        env.next_row();
        let state = g5.synthesize(env, state);
        env.next_row();
        let state = g10.synthesize(env, state);
        env.next_row();
        let state = g15.synthesize(env, state);
        env.next_row();
        let state = g20.synthesize(env, state);
        env.next_row();
        let state = g25.synthesize(env, state);
        env.next_row();
        let state = g30.synthesize(env, state);
        env.next_row();
        let state = g35.synthesize(env, state);
        env.next_row();
        let state = g40.synthesize(env, state);
        env.next_row();
        let state = g45.synthesize(env, state);
        env.next_row();
        let state = g50.synthesize(env, state);
        env.next_row();
        g55.synthesize(env, state)
    }

    fn output(&self, input: &Self::Input<F>) -> Self::Output<F> {
        let g0 = PoseidonRoundGadget::<F, FULL_ROUNDS, 0>::new(self.params);
        let g5 = PoseidonRoundGadget::<F, FULL_ROUNDS, 5>::new(self.params);
        let g10 = PoseidonRoundGadget::<F, FULL_ROUNDS, 10>::new(self.params);
        let g15 = PoseidonRoundGadget::<F, FULL_ROUNDS, 15>::new(self.params);
        let g20 = PoseidonRoundGadget::<F, FULL_ROUNDS, 20>::new(self.params);
        let g25 = PoseidonRoundGadget::<F, FULL_ROUNDS, 25>::new(self.params);
        let g30 = PoseidonRoundGadget::<F, FULL_ROUNDS, 30>::new(self.params);
        let g35 = PoseidonRoundGadget::<F, FULL_ROUNDS, 35>::new(self.params);
        let g40 = PoseidonRoundGadget::<F, FULL_ROUNDS, 40>::new(self.params);
        let g45 = PoseidonRoundGadget::<F, FULL_ROUNDS, 45>::new(self.params);
        let g50 = PoseidonRoundGadget::<F, FULL_ROUNDS, 50>::new(self.params);
        let g55 = PoseidonRoundGadget::<F, FULL_ROUNDS, 55>::new(self.params);

        let state = g0.output(input);
        let state = g5.output(&state);
        let state = g10.output(&state);
        let state = g15.output(&state);
        let state = g20.output(&state);
        let state = g25.output(&state);
        let state = g30.output(&state);
        let state = g35.output(&state);
        let state = g40.output(&state);
        let state = g45.output(&state);
        let state = g50.output(&state);
        g55.output(&state)
    }
}

// ============================================================================
// PoseidonAbsorbGadget - Sponge absorption
// ============================================================================

/// Input positions for PoseidonAbsorbGadget: state at columns 0, 1, 2 on current row.
const POSEIDON_ABSORB_INPUT_POSITIONS: &[Position] = &[
    Position {
        col: 0,
        row: Row::Curr,
    },
    Position {
        col: 1,
        row: Row::Curr,
    },
    Position {
        col: 2,
        row: Row::Curr,
    },
];

/// Output positions for PoseidonAbsorbGadget: state at columns 0, 3, 4 on current row.
/// Note: Column 0 (capacity) is unchanged, columns 3, 4 hold the absorbed values.
const POSEIDON_ABSORB_OUTPUT_POSITIONS: &[Position] = &[
    Position {
        col: 0,
        row: Row::Curr,
    },
    Position {
        col: 3,
        row: Row::Curr,
    },
    Position {
        col: 4,
        row: Row::Curr,
    },
];

/// Poseidon sponge absorb gadget implementing `TypedGadget`.
///
/// Absorbs 2 field elements into the Poseidon sponge state (rate = 2).
/// The capacity portion of the state (index 0) is unchanged.
///
/// # Layout
///
/// Capacity is at index 0, rate at indices [1, 2].
/// Input values are added to the rate portion.
///
/// # Selector
///
/// Uses `QPoseidonAbsorb` (index 10).
#[derive(Clone, Debug)]
pub struct PoseidonAbsorbGadget<F: PrimeField> {
    /// Values to absorb into the sponge
    pub values: [F; 2],
}

impl<F: PrimeField> PoseidonAbsorbGadget<F> {
    /// Create a new absorb gadget with the given values.
    pub fn new(values: [F; 2]) -> Self {
        Self { values }
    }
}

impl<F: PrimeField> TypedGadget<F> for PoseidonAbsorbGadget<F> {
    type Selector = QPoseidonAbsorb;
    type Input<V: Clone> = PoseidonState3<V>;
    type Output<V: Clone> = PoseidonState3<V>;

    const NAME: &'static str = "poseidon-absorb";
    const DESCRIPTION: &'static str = "Poseidon sponge absorption";
    const ARITY: usize = 3;
    const ROWS: usize = 1;

    fn input_positions() -> &'static [Position] {
        POSEIDON_ABSORB_INPUT_POSITIONS
    }

    fn output_positions() -> &'static [Position] {
        POSEIDON_ABSORB_OUTPUT_POSITIONS
    }

    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        env: &mut E,
        input: Self::Input<E::Variable>,
    ) -> Self::Output<E::Variable> {
        let state = input.into_array();

        // Capacity at index 0, rate at indices [1, 2]
        let capacity = state[0].clone();
        let absorbed_1 = state[1].clone() + env.constant(self.values[0]);
        let absorbed_2 = state[2].clone() + env.constant(self.values[1]);

        let new_state_1 = {
            let pos = env.allocate();
            env.write_column(pos, absorbed_1.clone())
        };
        env.assert_eq(&new_state_1, &absorbed_1);

        let new_state_2 = {
            let pos = env.allocate();
            env.write_column(pos, absorbed_2.clone())
        };
        env.assert_eq(&new_state_2, &absorbed_2);

        PoseidonState3::new([capacity, new_state_1, new_state_2])
    }

    fn output(&self, input: &Self::Input<F>) -> Self::Output<F> {
        let state = input.as_array();
        // Capacity at index 0 is unchanged
        // Rate at indices [1, 2] have values added
        PoseidonState3::new([
            state[0],
            state[1] + self.values[0],
            state[2] + self.values[1],
        ])
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit::ConstraintEnv, circuits::selector::SelectorTag, curve::PlonkSpongeConstants,
        poseidon_3_60_0_5_5_fp,
    };
    use mina_curves::pasta::Fp;
    use mina_poseidon::{constants::SpongeConstants, permutation::poseidon_block_cipher};

    fn fp_params() -> &'static ArithmeticSpongeParams<Fp, NUMBER_FULL_ROUNDS> {
        poseidon_3_60_0_5_5_fp::static_params()
    }

    // ========================================================================
    // PoseidonRoundGadget tests
    // ========================================================================

    #[test]
    fn test_poseidon_round_gadget_output() {
        let gadget = PoseidonRoundGadget::<Fp, NUMBER_FULL_ROUNDS, 0>::new(fp_params());
        let input = PoseidonState3::new([Fp::from(1u64), Fp::from(2u64), Fp::from(3u64)]);

        let output = gadget.output(&input);

        // Output should be different from input
        assert_ne!(output.into_array(), input.into_array());
    }

    #[test]
    fn test_poseidon_round_gadget_deterministic() {
        let gadget = PoseidonRoundGadget::<Fp, NUMBER_FULL_ROUNDS, 0>::new(fp_params());
        let input = PoseidonState3::new([Fp::from(1u64), Fp::from(2u64), Fp::from(3u64)]);

        let output1 = gadget.output(&input);
        let output2 = gadget.output(&input);

        assert_eq!(output1.into_array(), output2.into_array());
    }

    #[test]
    fn test_poseidon_round_gadget_selector() {
        // Verify each round gadget has the correct selector index
        assert_eq!(
            <PoseidonRoundGadget<Fp, NUMBER_FULL_ROUNDS, 0> as TypedGadget<Fp>>::Selector::INDEX,
            11
        );
        assert_eq!(
            <PoseidonRoundGadget<Fp, NUMBER_FULL_ROUNDS, 5> as TypedGadget<Fp>>::Selector::INDEX,
            12
        );
        assert_eq!(
            <PoseidonRoundGadget<Fp, NUMBER_FULL_ROUNDS, 10> as TypedGadget<Fp>>::Selector::INDEX,
            13
        );
        assert_eq!(
            <PoseidonRoundGadget<Fp, NUMBER_FULL_ROUNDS, 55> as TypedGadget<Fp>>::Selector::INDEX,
            22
        );
    }

    #[test]
    fn test_poseidon_round_gadget_constraints() {
        // Test different starting rounds
        for starting_round in [0usize, 5, 10, 55] {
            let mut env = ConstraintEnv::<Fp>::new();
            let z = env.make_input_vars::<3>();
            let input = PoseidonState3::new([z[0].clone(), z[1].clone(), z[2].clone()]);

            // Use runtime dispatch for testing different starting rounds
            match starting_round {
                0 => {
                    let g = PoseidonRoundGadget::<Fp, NUMBER_FULL_ROUNDS, 0>::new(fp_params());
                    let _ = g.synthesize(&mut env, input);
                }
                5 => {
                    let g = PoseidonRoundGadget::<Fp, NUMBER_FULL_ROUNDS, 5>::new(fp_params());
                    let _ = g.synthesize(&mut env, input);
                }
                10 => {
                    let g = PoseidonRoundGadget::<Fp, NUMBER_FULL_ROUNDS, 10>::new(fp_params());
                    let _ = g.synthesize(&mut env, input);
                }
                55 => {
                    let g = PoseidonRoundGadget::<Fp, NUMBER_FULL_ROUNDS, 55>::new(fp_params());
                    let _ = g.synthesize(&mut env, input);
                }
                _ => unreachable!(),
            }

            // Per round: 3 new_state witnesses (sbox is computed inline, no allocation)
            // But last round uses allocate_next_row which doesn't count in witness_idx
            // So: 4 rounds * 3 new_state = 12 on current row
            let expected_witnesses = (ROUNDS_PER_ROW - 1) * 3;
            assert_eq!(
                env.num_witness_allocations(),
                expected_witnesses,
                "PoseidonRoundGadget starting at round {} should have {} witness allocations",
                starting_round,
                expected_witnesses
            );

            // Per round: 3 MDS constraints (degree 5 from x^5 term)
            // 5 rounds = 15 constraints
            let expected_constraints = ROUNDS_PER_ROW * 3;
            assert_eq!(
                env.num_constraints(),
                expected_constraints,
                "PoseidonRoundGadget starting at round {} should have {} constraints",
                starting_round,
                expected_constraints
            );

            assert_eq!(env.max_degree(), 5, "Max degree should be 5");
            env.check_degrees()
                .expect("All constraints should have degree <= MAX_DEGREE");
        }
    }

    // ========================================================================
    // PoseidonPermutationGadget tests
    // ========================================================================

    #[test]
    fn test_poseidon_permutation_gadget_matches_mina() {
        use rand::{Rng, SeedableRng};

        let seed: u64 = rand::random();
        println!("test_poseidon_permutation_gadget_matches_mina seed: {seed}");
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

        let gadget = PoseidonPermutationGadget::<Fp, NUMBER_FULL_ROUNDS>::new(fp_params());

        let z = [
            Fp::from(rng.gen::<u64>()),
            Fp::from(rng.gen::<u64>()),
            Fp::from(rng.gen::<u64>()),
        ];

        let input = PoseidonState3::new(z);
        let gadget_output = gadget.output(&input);

        // Reference: mina_poseidon
        let mut ref_state = z;
        poseidon_block_cipher::<Fp, PlonkSpongeConstants, NUMBER_FULL_ROUNDS>(
            fp_params(),
            &mut ref_state,
        );

        assert_eq!(
            gadget_output.into_array(),
            ref_state,
            "PoseidonPermutationGadget should match mina_poseidon"
        );
    }

    #[test]
    fn test_poseidon_permutation_gadget_rows() {
        assert_eq!(
            PoseidonPermutationGadget::<Fp, NUMBER_FULL_ROUNDS>::ROWS,
            12,
            "60 rounds / 5 rounds per row = 12 rows"
        );
    }

    #[test]
    fn test_poseidon_permutation_gadget_synthesize_constraint() {
        let gadget = PoseidonPermutationGadget::<Fp, NUMBER_FULL_ROUNDS>::new(fp_params());

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<3>();
        let input = PoseidonState3::new([z[0].clone(), z[1].clone(), z[2].clone()]);

        let output = gadget.synthesize(&mut env, input);

        // Verify output is allocated
        let output_array = output.into_array();
        assert_eq!(output_array.len(), 3);

        // Check constraint count:
        // Each of 12 steps has: 5 rounds * 3 mds = 15 constraints
        // Total: 12 * 15 = 180 constraints
        let expected_constraints = 12 * 15;
        assert_eq!(
            env.num_constraints(),
            expected_constraints,
            "Full permutation should have {} constraints",
            expected_constraints
        );
    }

    #[test]
    fn test_poseidon_permutation_num_rows() {
        // 60 rounds / 5 rounds per row = 12 rows
        let expected_rows = PlonkSpongeConstants::PERM_ROUNDS_FULL / ROUNDS_PER_ROW;
        assert_eq!(
            PoseidonPermutationGadget::<Fp, NUMBER_FULL_ROUNDS>::num_rows(),
            expected_rows,
        );
    }

    // ========================================================================
    // PoseidonAbsorbGadget tests
    // ========================================================================

    #[test]
    fn test_poseidon_absorb_gadget_absorbs_correctly() {
        let values = [Fp::from(100u64), Fp::from(200u64)];
        let gadget = PoseidonAbsorbGadget::<Fp>::new(values);

        let input = PoseidonState3::new([Fp::from(1u64), Fp::from(2u64), Fp::from(3u64)]);
        let output = gadget.output(&input);
        let output_array = output.into_array();

        // Capacity at index 0 should be unchanged
        assert_eq!(
            output_array[0],
            Fp::from(1u64),
            "Capacity should be unchanged"
        );
        // Rate elements at indices [1, 2] should have values added
        assert_eq!(
            output_array[1],
            Fp::from(102u64),
            "First rate element should be 2 + 100"
        );
        assert_eq!(
            output_array[2],
            Fp::from(203u64),
            "Second rate element should be 3 + 200"
        );
    }

    #[test]
    fn test_poseidon_absorb_gadget_rows() {
        assert_eq!(
            PoseidonAbsorbGadget::<Fp>::ROWS,
            1,
            "Absorb is a single-row operation"
        );
    }

    #[test]
    fn test_poseidon_absorb_gadget_synthesize_constraint() {
        let gadget = PoseidonAbsorbGadget::<Fp>::new([Fp::from(10u64), Fp::from(20u64)]);

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<3>();
        let input = PoseidonState3::new([z[0].clone(), z[1].clone(), z[2].clone()]);

        let _output = gadget.synthesize(&mut env, input);

        assert_eq!(
            env.num_constraints(),
            2,
            "PoseidonAbsorbGadget should have 2 constraints"
        );
        assert_eq!(
            env.num_witness_allocations(),
            2,
            "PoseidonAbsorbGadget should have 2 witness allocations"
        );
    }

    #[test]
    fn test_poseidon_absorb_gadget_constraints() {
        use rand::{Rng, SeedableRng};

        let seed: u64 = rand::random();
        println!("test_poseidon_absorb_gadget_constraints seed: {seed}");
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

        let v1: u64 = rng.gen();
        let v2: u64 = rng.gen();
        let gadget = PoseidonAbsorbGadget::<Fp>::new([Fp::from(v1), Fp::from(v2)]);

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<3>();
        let input = PoseidonState3::new([z[0].clone(), z[1].clone(), z[2].clone()]);
        let _ = gadget.synthesize(&mut env, input);

        assert_eq!(env.num_constraints(), 2);

        let degrees = env.constraint_degrees();
        assert_eq!(degrees.len(), 2);
        assert_eq!(
            degrees[0], 1,
            "First absorb constraint should have degree 1"
        );
        assert_eq!(
            degrees[1], 1,
            "Second absorb constraint should have degree 1"
        );

        assert_eq!(env.max_degree(), 1);
        env.check_degrees()
            .expect("All constraints should have degree <= MAX_DEGREE");
    }
}

// ============================================================================
// Trace tests
// ============================================================================

#[cfg(test)]
mod trace_tests {
    use super::*;
    use crate::{
        circuit::{CircuitEnv, ConstraintEnv, Trace},
        curve::PlonkSpongeConstants,
        poseidon_3_60_0_5_5_fp,
    };
    use mina_curves::pasta::Fp;
    use mina_poseidon::permutation::poseidon_block_cipher;
    use rand::{Rng, SeedableRng};

    fn fp_params() -> &'static ArithmeticSpongeParams<Fp, NUMBER_FULL_ROUNDS> {
        poseidon_3_60_0_5_5_fp::static_params()
    }

    #[test]
    fn test_poseidon_absorb_trace() {
        let seed: u64 = rand::random();
        println!("test_poseidon_absorb_trace seed: {seed}");
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

        let v1 = Fp::from(rng.gen::<u64>());
        let v2 = Fp::from(rng.gen::<u64>());
        let gadget = PoseidonAbsorbGadget::<Fp>::new([v1, v2]);

        let s0 = Fp::from(rng.gen::<u64>());
        let s1 = Fp::from(rng.gen::<u64>());
        let s2 = Fp::from(rng.gen::<u64>());

        let mut env = Trace::<Fp>::new(16);
        let pos0 = env.allocate();
        let pos1 = env.allocate();
        let pos2 = env.allocate();
        let z0 = env.write_column(pos0, s0);
        let z1 = env.write_column(pos1, s1);
        let z2 = env.write_column(pos2, s2);

        let input = PoseidonState3::new([z0, z1, z2]);
        let output = gadget.synthesize(&mut env, input);
        let output_array = output.into_array();

        let expected = gadget.output(&PoseidonState3::new([s0, s1, s2]));
        let expected_array = expected.into_array();

        assert_eq!(
            output_array[0], expected_array[0],
            "Capacity should be unchanged"
        );
        assert_eq!(
            output_array[1], expected_array[1],
            "First rate element mismatch"
        );
        assert_eq!(
            output_array[2], expected_array[2],
            "Second rate element mismatch"
        );
    }

    #[test]
    fn test_poseidon_round_gadget_output_correctness() {
        let seed: u64 = rand::random();
        println!("test_poseidon_round_gadget_output_correctness seed: {seed}");
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

        // Test a random starting round
        let starting_rounds = [0usize, 5, 10, 55];
        let starting_round = starting_rounds[rng.gen_range(0..starting_rounds.len())];

        let z = [
            Fp::from(rng.gen::<u64>()),
            Fp::from(rng.gen::<u64>()),
            Fp::from(rng.gen::<u64>()),
        ];

        let input = PoseidonState3::new(z);

        let (output1, output2) = match starting_round {
            0 => {
                let g = PoseidonRoundGadget::<Fp, NUMBER_FULL_ROUNDS, 0>::new(fp_params());
                (g.output(&input), g.output(&input))
            }
            5 => {
                let g = PoseidonRoundGadget::<Fp, NUMBER_FULL_ROUNDS, 5>::new(fp_params());
                (g.output(&input), g.output(&input))
            }
            10 => {
                let g = PoseidonRoundGadget::<Fp, NUMBER_FULL_ROUNDS, 10>::new(fp_params());
                (g.output(&input), g.output(&input))
            }
            55 => {
                let g = PoseidonRoundGadget::<Fp, NUMBER_FULL_ROUNDS, 55>::new(fp_params());
                (g.output(&input), g.output(&input))
            }
            _ => unreachable!(),
        };

        assert_eq!(
            output1.into_array(),
            output2.into_array(),
            "Output should be deterministic for starting round {}",
            starting_round
        );
    }

    #[test]
    fn test_poseidon_round_chain_matches_mina() {
        let seed: u64 = rand::random();
        println!("test_poseidon_round_chain_matches_mina seed: {seed}");
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

        let z = [
            Fp::from(rng.gen::<u64>()),
            Fp::from(rng.gen::<u64>()),
            Fp::from(rng.gen::<u64>()),
        ];

        // Chain all 12 round gadgets
        let g0 = PoseidonRoundGadget::<Fp, NUMBER_FULL_ROUNDS, 0>::new(fp_params());
        let g5 = PoseidonRoundGadget::<Fp, NUMBER_FULL_ROUNDS, 5>::new(fp_params());
        let g10 = PoseidonRoundGadget::<Fp, NUMBER_FULL_ROUNDS, 10>::new(fp_params());
        let g15 = PoseidonRoundGadget::<Fp, NUMBER_FULL_ROUNDS, 15>::new(fp_params());
        let g20 = PoseidonRoundGadget::<Fp, NUMBER_FULL_ROUNDS, 20>::new(fp_params());
        let g25 = PoseidonRoundGadget::<Fp, NUMBER_FULL_ROUNDS, 25>::new(fp_params());
        let g30 = PoseidonRoundGadget::<Fp, NUMBER_FULL_ROUNDS, 30>::new(fp_params());
        let g35 = PoseidonRoundGadget::<Fp, NUMBER_FULL_ROUNDS, 35>::new(fp_params());
        let g40 = PoseidonRoundGadget::<Fp, NUMBER_FULL_ROUNDS, 40>::new(fp_params());
        let g45 = PoseidonRoundGadget::<Fp, NUMBER_FULL_ROUNDS, 45>::new(fp_params());
        let g50 = PoseidonRoundGadget::<Fp, NUMBER_FULL_ROUNDS, 50>::new(fp_params());
        let g55 = PoseidonRoundGadget::<Fp, NUMBER_FULL_ROUNDS, 55>::new(fp_params());

        let input = PoseidonState3::new(z);
        let state = g0.output(&input);
        let state = g5.output(&state);
        let state = g10.output(&state);
        let state = g15.output(&state);
        let state = g20.output(&state);
        let state = g25.output(&state);
        let state = g30.output(&state);
        let state = g35.output(&state);
        let state = g40.output(&state);
        let state = g45.output(&state);
        let state = g50.output(&state);
        let our_state = g55.output(&state);

        // Reference: mina_poseidon
        let mut ref_state = z;
        poseidon_block_cipher::<Fp, PlonkSpongeConstants, NUMBER_FULL_ROUNDS>(
            fp_params(),
            &mut ref_state,
        );

        assert_eq!(
            our_state.into_array(),
            ref_state,
            "Chained PoseidonRoundGadgets should match mina_poseidon block cipher"
        );
    }

    #[test]
    fn test_poseidon_permutation_output_correctness() {
        let seed: u64 = rand::random();
        println!("test_poseidon_permutation_output_correctness seed: {seed}");
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

        let gadget = PoseidonPermutationGadget::<Fp, NUMBER_FULL_ROUNDS>::new(fp_params());

        let z = [
            Fp::from(rng.gen::<u64>()),
            Fp::from(rng.gen::<u64>()),
            Fp::from(rng.gen::<u64>()),
        ];

        let input = PoseidonState3::new(z);
        let output1 = gadget.output(&input);
        let output2 = gadget.output(&input);
        assert_eq!(
            output1.into_array(),
            output2.into_array(),
            "Output should be deterministic"
        );

        // Verify output is different from input
        assert_ne!(
            gadget.output(&input).into_array(),
            z,
            "Full permutation should change all elements"
        );
    }

    #[test]
    fn test_poseidon_round_last_output_on_next_row() {
        let gadget = PoseidonRoundGadget::<Fp, NUMBER_FULL_ROUNDS, 0>::new(fp_params());

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<3>();
        let input = PoseidonState3::new([z[0].clone(), z[1].clone(), z[2].clone()]);
        let output = gadget.synthesize(&mut env, input);

        let output_str = format!("{:?}", output);
        assert!(
            output_str.contains("Next"),
            "Output should reference next row, got: {}",
            output_str
        );
    }

    /// Verify that output positions correctly describe where outputs are written in the trace.
    #[test]
    fn test_poseidon_round_gadget_output_positions_match_trace() {
        use crate::circuits::gadget::{test_utils::verify_trace_positions, TypedGadget};

        let gadget = PoseidonRoundGadget::<Fp, NUMBER_FULL_ROUNDS, 0>::new(fp_params());
        let mut env = Trace::<Fp>::new(16);

        // Input state
        let z = [Fp::from(1u64), Fp::from(2u64), Fp::from(3u64)];

        // Allocate and write inputs
        let z0 = {
            let pos = env.allocate();
            env.write_column(pos, z[0])
        };
        let z1 = {
            let pos = env.allocate();
            env.write_column(pos, z[1])
        };
        let z2 = {
            let pos = env.allocate();
            env.write_column(pos, z[2])
        };

        let input = PoseidonState3::new([z0, z1, z2]);
        let current_row = env.current_row();

        // Synthesize
        let _output = gadget.synthesize(&mut env, input);

        // Compute expected output
        let expected_output = gadget.output(&PoseidonState3::new([z[0], z[1], z[2]]));

        // Verify input positions
        verify_trace_positions(
            &env,
            current_row,
            <PoseidonRoundGadget<Fp, NUMBER_FULL_ROUNDS, 0> as TypedGadget<Fp>>::input_positions(),
            &z,
            "input",
        );

        // Verify output positions (on next row)
        verify_trace_positions(
            &env,
            current_row,
            <PoseidonRoundGadget<Fp, NUMBER_FULL_ROUNDS, 0> as TypedGadget<Fp>>::output_positions(),
            expected_output.as_array(),
            "output",
        );
    }

    /// Verify that PoseidonAbsorbGadget output positions match trace.
    #[test]
    fn test_poseidon_absorb_gadget_output_positions_match_trace() {
        use crate::circuits::gadget::{test_utils::verify_trace_positions, TypedGadget};

        let values = [Fp::from(100u64), Fp::from(200u64)];
        let gadget = PoseidonAbsorbGadget::<Fp>::new(values);
        let mut env = Trace::<Fp>::new(16);

        // Input state
        let z = [Fp::from(1u64), Fp::from(2u64), Fp::from(3u64)];

        // Allocate and write inputs
        let z0 = {
            let pos = env.allocate();
            env.write_column(pos, z[0])
        };
        let z1 = {
            let pos = env.allocate();
            env.write_column(pos, z[1])
        };
        let z2 = {
            let pos = env.allocate();
            env.write_column(pos, z[2])
        };

        let input = PoseidonState3::new([z0, z1, z2]);
        let current_row = env.current_row();

        // Synthesize
        let _output = gadget.synthesize(&mut env, input);

        // Compute expected output
        let expected_output = gadget.output(&PoseidonState3::new([z[0], z[1], z[2]]));

        // Verify input positions
        verify_trace_positions(
            &env,
            current_row,
            <PoseidonAbsorbGadget<Fp> as TypedGadget<Fp>>::input_positions(),
            &z,
            "input",
        );

        // Verify output positions
        verify_trace_positions(
            &env,
            current_row,
            <PoseidonAbsorbGadget<Fp> as TypedGadget<Fp>>::output_positions(),
            expected_output.as_array(),
            "output",
        );
    }
}
