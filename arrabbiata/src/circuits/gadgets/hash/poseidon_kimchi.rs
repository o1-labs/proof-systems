//! Poseidon Kimchi hash function gadgets.
//!
//! This module implements the Poseidon hash function with Kimchi-compatible
//! parameters (x^7 S-box, 55 full rounds) as TypedGadgets.
//!
//! ## Differences from Standard Poseidon (x^5)
//!
//! - **S-box**: x^7 instead of x^5 (higher security margin)
//! - **Rounds**: 55 full rounds instead of 60
//! - **Parameters**: Uses Kimchi-specific MDS matrix and round constants
//!
//! ## S-box Decomposition for Max Degree 5
//!
//! To achieve max degree 5 in constraints, we decompose x^7 as:
//! - w2 = x^2 (constraint degree 2)
//! - w4 = w2^2 = x^4 (constraint degree 2)
//! - w7 = w4 * w2 * x = x^7 (constraint degree 3)
//!
//! This requires 3 intermediate witnesses per state element (9 total for state width 3).
//!
//! ## Layout (1 round per row)
//!
//! With 15 columns, state width 3, and x^7 S-box needing 9 columns for intermediates,
//! we can only fit 1 round per row. 55 rounds / 1 round per row = 55 rows for full permutation.

use ark_ff::PrimeField;
use mina_poseidon::poseidon::ArithmeticSpongeParams;

use crate::{
    circuit::{CircuitEnv, SelectorEnv},
    circuits::{
        gadget::{PoseidonState3, Position, Row, TypedGadget},
        selector::QPoseidonKimchiRound,
    },
};

/// Poseidon state size (width of the sponge).
pub const STATE_SIZE: usize = 3;

/// Total number of full rounds in the Kimchi Poseidon permutation.
pub const KIMCHI_FULL_ROUNDS: usize = 55;

/// Number of Poseidon rounds processed per circuit step.
/// With x^7 S-box requiring 3 intermediate witnesses per element (w2, w4, w7),
/// each round needs 9 columns for S-box. With 3 input columns, only 1 round fits per row.
pub const KIMCHI_ROUNDS_PER_ROW: usize = 1;

/// Total number of rows needed for the full Kimchi Poseidon permutation.
/// 55 rounds / 1 round per row = 55 rows
pub const KIMCHI_ROWS_FOR_PERMUTATION: usize = KIMCHI_FULL_ROUNDS / KIMCHI_ROUNDS_PER_ROW;

// ============================================================================
// PoseidonKimchiRoundGadget
// ============================================================================

/// Input positions for PoseidonKimchiRoundGadget: state at columns 0, 1, 2 on current row.
const POSEIDON_KIMCHI_ROUND_INPUT_POSITIONS: &[Position] = &[
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

/// Output positions for PoseidonKimchiRoundGadget: state at columns 0, 1, 2 on next row.
const POSEIDON_KIMCHI_ROUND_OUTPUT_POSITIONS: &[Position] = &[
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

/// Poseidon Kimchi round gadget processing 1 round at a specific round index.
///
/// This gadget processes 1 Poseidon Kimchi full round on a 3-element state
/// using the x^7 S-box.
///
/// # Type Parameters
///
/// - `F`: The field type (must match the Poseidon parameters)
/// - `STARTING_ROUND`: The round index to process (0, 1, 2, ..., 54)
///
/// # Selector
///
/// Uses `QPoseidonKimchiRound<STARTING_ROUND>` which maps to index `23 + STARTING_ROUND`.
#[derive(Clone, Debug)]
pub struct PoseidonKimchiRoundGadget<F: PrimeField, const STARTING_ROUND: usize> {
    /// Poseidon parameters (MDS matrix and round constants)
    pub params: &'static ArithmeticSpongeParams<F, KIMCHI_FULL_ROUNDS>,
}

impl<F: PrimeField, const STARTING_ROUND: usize> PoseidonKimchiRoundGadget<F, STARTING_ROUND> {
    /// Create a new Poseidon Kimchi round gadget.
    ///
    /// # Panics
    ///
    /// Panics at compile time via const assertion if STARTING_ROUND is invalid.
    pub fn new(params: &'static ArithmeticSpongeParams<F, KIMCHI_FULL_ROUNDS>) -> Self {
        // Compile-time check: round must be within valid range
        const { assert!(STARTING_ROUND < KIMCHI_FULL_ROUNDS) };
        Self { params }
    }

    /// Compute one round of Poseidon Kimchi: S-box (x^7) -> MDS -> ARK
    fn round(&self, state: [F; STATE_SIZE], round: usize) -> [F; STATE_SIZE] {
        // S-box: x^7
        let state: [F; STATE_SIZE] = [state[0].pow([7]), state[1].pow([7]), state[2].pow([7])];

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

    /// Internal synthesize method.
    fn synthesize_rounds<E: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        env: &mut E,
        input: &[E::Variable; STATE_SIZE],
    ) -> [E::Variable; STATE_SIZE] {
        let mut state = input.clone();

        // Process rounds (1 round per row due to x^7 S-box needing 9 columns)
        for round_offset in 0..KIMCHI_ROUNDS_PER_ROW {
            let round = STARTING_ROUND + round_offset;
            let is_last_round = round_offset == KIMCHI_ROUNDS_PER_ROW - 1;

            // S-box: x^7 = x^4 * x^2 * x
            let mut sbox_state = [env.zero(), env.zero(), env.zero()];

            for i in 0..STATE_SIZE {
                let x = &state[i];

                // Compute x^2
                let x2_expr = x.clone() * x.clone();
                let w2 = {
                    let pos = env.allocate();
                    env.write_column(pos, x2_expr.clone())
                };
                env.assert_eq(&w2, &x2_expr);

                // Compute x^4 = w2^2
                let x4_expr = w2.clone() * w2.clone();
                let w4 = {
                    let pos = env.allocate();
                    env.write_column(pos, x4_expr.clone())
                };
                env.assert_eq(&w4, &x4_expr);

                // Compute x^7 = w4 * w2 * x
                let x7_expr = w4 * w2 * x.clone();
                let w7 = {
                    let pos = env.allocate();
                    env.write_column(pos, x7_expr.clone())
                };
                env.assert_eq(&w7, &x7_expr);

                sbox_state[i] = w7;
            }

            // MDS matrix multiplication and add round constants
            let mds = &self.params.mds;
            let rc = &self.params.round_constants[round];

            for i in 0..STATE_SIZE {
                let c0 = env.constant(mds[i][0]);
                let c1 = env.constant(mds[i][1]);
                let c2 = env.constant(mds[i][2]);

                let term0 = c0 * sbox_state[0].clone();
                let term1 = c1 * sbox_state[1].clone();
                let term2 = c2 * sbox_state[2].clone();

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
}

impl<F: PrimeField, const STARTING_ROUND: usize> TypedGadget<F>
    for PoseidonKimchiRoundGadget<F, STARTING_ROUND>
{
    type Selector = QPoseidonKimchiRound<STARTING_ROUND>;
    type Input<V: Clone> = PoseidonState3<V>;
    type Output<V: Clone> = PoseidonState3<V>;

    const NAME: &'static str = "poseidon-kimchi-round";
    const DESCRIPTION: &'static str = "Poseidon round (Kimchi style)";
    const ARITY: usize = 3;
    const ROWS: usize = 1;

    fn input_positions() -> &'static [Position] {
        POSEIDON_KIMCHI_ROUND_INPUT_POSITIONS
    }

    fn output_positions() -> &'static [Position] {
        POSEIDON_KIMCHI_ROUND_OUTPUT_POSITIONS
    }

    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        env: &mut E,
        input: Self::Input<E::Variable>,
    ) -> Self::Output<E::Variable> {
        let arr = input.into_array();
        let result = self.synthesize_rounds(env, &arr);
        PoseidonState3::new(result)
    }

    fn output(&self, input: &Self::Input<F>) -> Self::Output<F> {
        let state = input.clone().into_array();
        // Apply just this one round
        let state = self.round(state, STARTING_ROUND);
        PoseidonState3::new(state)
    }
}

// ============================================================================
// PoseidonKimchiPermutationGadget
// ============================================================================

/// Input positions for PoseidonKimchiPermutationGadget: state at columns 0, 1, 2 on current row.
const POSEIDON_KIMCHI_PERMUTATION_INPUT_POSITIONS: &[Position] = &[
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

/// Output positions for PoseidonKimchiPermutationGadget: state at columns 0, 1, 2 on next row.
/// Note: The output is on the next row relative to the final (11th) round step.
const POSEIDON_KIMCHI_PERMUTATION_OUTPUT_POSITIONS: &[Position] = &[
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

/// Full Poseidon Kimchi permutation gadget (55 rounds).
///
/// This gadget runs all 55 Poseidon Kimchi rounds to complete
/// the full permutation, using 1 round per row.
///
/// # Selector
///
/// Uses `QPoseidonKimchiRound<0>` as the primary selector (first round's selector).
#[derive(Clone, Debug)]
pub struct PoseidonKimchiPermutationGadget<F: PrimeField> {
    /// Poseidon parameters
    pub params: &'static ArithmeticSpongeParams<F, KIMCHI_FULL_ROUNDS>,
}

impl<F: PrimeField> PoseidonKimchiPermutationGadget<F> {
    /// Create a new full Poseidon Kimchi permutation gadget.
    pub fn new(params: &'static ArithmeticSpongeParams<F, KIMCHI_FULL_ROUNDS>) -> Self {
        Self { params }
    }

    /// Number of rows needed for this permutation (55 rounds / 1 round per row = 55).
    pub const fn num_rows() -> usize {
        KIMCHI_ROWS_FOR_PERMUTATION
    }

    /// Compute one round of Poseidon Kimchi: S-box (x^7) -> MDS -> ARK
    fn round(&self, state: [F; STATE_SIZE], round: usize) -> [F; STATE_SIZE] {
        // S-box: x^7
        let state: [F; STATE_SIZE] = [state[0].pow([7]), state[1].pow([7]), state[2].pow([7])];

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

    /// Synthesize one round of Poseidon Kimchi with constraints.
    fn synthesize_round<E: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        env: &mut E,
        state: &[E::Variable; STATE_SIZE],
        round: usize,
        is_last_round: bool,
    ) -> [E::Variable; STATE_SIZE] {
        // S-box: x^7 = x^4 * x^2 * x
        let mut sbox_state = [env.zero(), env.zero(), env.zero()];

        for i in 0..STATE_SIZE {
            let x = &state[i];

            // Compute x^2
            let x2_expr = x.clone() * x.clone();
            let w2 = {
                let pos = env.allocate();
                env.write_column(pos, x2_expr.clone())
            };
            env.assert_eq(&w2, &x2_expr);

            // Compute x^4 = w2^2
            let x4_expr = w2.clone() * w2.clone();
            let w4 = {
                let pos = env.allocate();
                env.write_column(pos, x4_expr.clone())
            };
            env.assert_eq(&w4, &x4_expr);

            // Compute x^7 = w4 * w2 * x
            let x7_expr = w4 * w2 * x.clone();
            let w7 = {
                let pos = env.allocate();
                env.write_column(pos, x7_expr.clone())
            };
            env.assert_eq(&w7, &x7_expr);

            sbox_state[i] = w7;
        }

        // MDS matrix multiplication and add round constants
        let mds = &self.params.mds;
        let rc = &self.params.round_constants[round];
        let mut new_state = [env.zero(), env.zero(), env.zero()];

        for i in 0..STATE_SIZE {
            let c0 = env.constant(mds[i][0]);
            let c1 = env.constant(mds[i][1]);
            let c2 = env.constant(mds[i][2]);

            let term0 = c0 * sbox_state[0].clone();
            let term1 = c1 * sbox_state[1].clone();
            let term2 = c2 * sbox_state[2].clone();

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

            new_state[i] = new_state_witness;
        }

        new_state
    }
}

impl<F: PrimeField> TypedGadget<F> for PoseidonKimchiPermutationGadget<F> {
    type Selector = QPoseidonKimchiRound<0>;
    type Input<V: Clone> = PoseidonState3<V>;
    type Output<V: Clone> = PoseidonState3<V>;

    const NAME: &'static str = "poseidon-kimchi";
    const DESCRIPTION: &'static str = "Poseidon permutation (Kimchi style)";
    const ARITY: usize = 3;
    const ROWS: usize = KIMCHI_ROWS_FOR_PERMUTATION;

    fn input_positions() -> &'static [Position] {
        POSEIDON_KIMCHI_PERMUTATION_INPUT_POSITIONS
    }

    fn output_positions() -> &'static [Position] {
        POSEIDON_KIMCHI_PERMUTATION_OUTPUT_POSITIONS
    }

    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        env: &mut E,
        input: Self::Input<E::Variable>,
    ) -> Self::Output<E::Variable> {
        let mut state = input.into_array();

        // Process all 55 rounds
        for round in 0..KIMCHI_FULL_ROUNDS {
            let is_last_round = round == KIMCHI_FULL_ROUNDS - 1;
            state = self.synthesize_round(env, &state, round, is_last_round);
            if !is_last_round {
                env.next_row();
            }
        }

        PoseidonState3::new(state)
    }

    fn output(&self, input: &Self::Input<F>) -> Self::Output<F> {
        let mut state = input.clone().into_array();

        // Apply all 55 rounds
        for round in 0..KIMCHI_FULL_ROUNDS {
            state = self.round(state, round);
        }

        PoseidonState3::new(state)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{circuit::ConstraintEnv, circuits::selector::SelectorTag};
    use mina_curves::pasta::Fp;
    use mina_poseidon::{
        constants::PlonkSpongeConstantsKimchi, pasta::fp_kimchi, permutation::poseidon_block_cipher,
    };

    fn kimchi_params() -> &'static ArithmeticSpongeParams<Fp, KIMCHI_FULL_ROUNDS> {
        fp_kimchi::static_params()
    }

    // ========================================================================
    // Output tests
    // ========================================================================

    #[test]
    fn test_poseidon_kimchi_round_gadget_output() {
        let gadget = PoseidonKimchiRoundGadget::<Fp, 0>::new(kimchi_params());
        let input = PoseidonState3::new([Fp::from(1u64), Fp::from(2u64), Fp::from(3u64)]);

        // Compute 5 rounds
        let output = gadget.output(&input);

        // Output should be different from input
        assert_ne!(output, input);
    }

    #[test]
    fn test_poseidon_kimchi_round_gadget_deterministic() {
        let gadget = PoseidonKimchiRoundGadget::<Fp, 0>::new(kimchi_params());
        let input = PoseidonState3::new([Fp::from(1u64), Fp::from(2u64), Fp::from(3u64)]);

        let output1 = gadget.output(&input);
        let output2 = gadget.output(&input);

        assert_eq!(output1, output2, "Same inputs should give same outputs");
    }

    #[test]
    fn test_poseidon_kimchi_permutation_matches_mina() {
        let gadget = PoseidonKimchiPermutationGadget::<Fp>::new(kimchi_params());
        let input = PoseidonState3::new([Fp::from(0u64), Fp::from(0u64), Fp::from(0u64)]);

        // Our implementation
        let our_output = gadget.output(&input);

        // Use mina_poseidon's block cipher with Kimchi constants (x^7)
        let mut mina_state = [Fp::from(0u64), Fp::from(0u64), Fp::from(0u64)];
        poseidon_block_cipher::<Fp, PlonkSpongeConstantsKimchi, KIMCHI_FULL_ROUNDS>(
            kimchi_params(),
            &mut mina_state,
        );

        let our_arr = our_output.into_array();
        assert_eq!(
            our_arr, mina_state,
            "Our Poseidon Kimchi permutation should match mina_poseidon"
        );
    }

    #[test]
    fn test_poseidon_kimchi_permutation_rows() {
        // Verify the number of rows matches the expected value
        assert_eq!(
            PoseidonKimchiPermutationGadget::<Fp>::ROWS,
            KIMCHI_ROWS_FOR_PERMUTATION
        );
        assert_eq!(KIMCHI_ROWS_FOR_PERMUTATION, 55); // 55 rounds / 1 round per row = 55
    }

    // ========================================================================
    // Selector tests
    // ========================================================================

    #[test]
    fn test_poseidon_kimchi_round_gadget_selector() {
        // Round 0 -> index 23
        assert_eq!(
            <PoseidonKimchiRoundGadget<Fp, 0> as TypedGadget<Fp>>::Selector::INDEX,
            23
        );
        // Round 5 -> index 28
        assert_eq!(
            <PoseidonKimchiRoundGadget<Fp, 5> as TypedGadget<Fp>>::Selector::INDEX,
            28
        );
        // Round 50 -> index 73
        assert_eq!(
            <PoseidonKimchiRoundGadget<Fp, 50> as TypedGadget<Fp>>::Selector::INDEX,
            73
        );
        // Round 54 (last) -> index 77
        assert_eq!(
            <PoseidonKimchiRoundGadget<Fp, 54> as TypedGadget<Fp>>::Selector::INDEX,
            77
        );
    }

    // ========================================================================
    // Constraint tests
    // ========================================================================

    #[test]
    fn test_poseidon_kimchi_round_gadget_constraints() {
        let gadget = PoseidonKimchiRoundGadget::<Fp, 0>::new(kimchi_params());
        let mut env = ConstraintEnv::<Fp>::new();

        // Create input
        let input = {
            let pos0 = env.allocate();
            let pos1 = env.allocate();
            let pos2 = env.allocate();
            PoseidonState3::new([
                env.read_position(pos0),
                env.read_position(pos1),
                env.read_position(pos2),
            ])
        };

        let _ = gadget.synthesize(&mut env, input);

        // Each round has 3 state elements, each needing:
        // - x^2 constraint: 1
        // - x^4 constraint: 1
        // - x^7 constraint: 1
        // - MDS output constraint: 1
        // Total per round: 3 * 4 = 12 constraints
        // For 1 round per gadget: 12 constraints
        assert_eq!(
            env.num_constraints(),
            12,
            "Expected 12 constraints (1 round * 3 elements * 4 constraints)"
        );

        // All constraints should be degree <= MAX_DEGREE
        env.check_degrees()
            .expect("All constraints should have degree <= MAX_DEGREE");
    }

    // ========================================================================
    // Position verification tests
    // ========================================================================

    #[test]
    fn test_poseidon_kimchi_round_gadget_output_positions_match_trace() {
        use crate::circuits::{
            gadget::{test_utils::verify_trace_positions, TypedGadget},
            Trace,
        };

        let gadget = PoseidonKimchiRoundGadget::<Fp, 0>::new(kimchi_params());
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
            PoseidonKimchiRoundGadget::<Fp, 0>::input_positions(),
            &z,
            "input",
        );

        // Verify output positions
        verify_trace_positions(
            &env,
            current_row,
            PoseidonKimchiRoundGadget::<Fp, 0>::output_positions(),
            &expected_output.into_array(),
            "output",
        );
    }

    #[test]
    fn test_poseidon_kimchi_permutation_gadget_output_positions_match_trace() {
        use crate::circuits::{
            gadget::{test_utils::verify_trace_positions, TypedGadget},
            Trace,
        };

        let gadget = PoseidonKimchiPermutationGadget::<Fp>::new(kimchi_params());
        let mut env = Trace::<Fp>::new(100); // Need 55+ rows for full permutation

        // Input state
        let z = [Fp::from(0u64), Fp::from(0u64), Fp::from(0u64)];

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
        let start_row = env.current_row();

        // Synthesize
        let _output = gadget.synthesize(&mut env, input);

        // Compute expected output
        let expected_output = gadget.output(&PoseidonState3::new([z[0], z[1], z[2]]));

        // Verify input positions
        verify_trace_positions(
            &env,
            start_row,
            PoseidonKimchiPermutationGadget::<Fp>::input_positions(),
            &z,
            "input",
        );

        // For permutation, output is on the last row's next row
        // The gadget spans 55 rows (start_row through start_row + 54)
        // Output positions are relative to final row (start_row + 54)
        let final_row = start_row + KIMCHI_FULL_ROUNDS - 1;
        verify_trace_positions(
            &env,
            final_row,
            PoseidonKimchiPermutationGadget::<Fp>::output_positions(),
            &expected_output.into_array(),
            "output",
        );
    }
}
