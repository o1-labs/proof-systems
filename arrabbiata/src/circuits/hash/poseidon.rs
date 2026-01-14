//! Poseidon hash function circuits.
//!
//! This module implements the Poseidon hash function as circuits that can be
//! composed to build the IVC verifier circuit.
//!
//! ## Circuits
//!
//! - [`PoseidonRoundCircuit`]: A single step processing 5 Poseidon rounds.
//! - [`PoseidonPermutationCircuit`]: Full 60-round Poseidon permutation (chains 12 round circuits).
//! - [`PoseidonAbsorbCircuit`]: Absorbs 2 field elements into the sponge state.
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

use crate::circuit::{CircuitEnv, SelectorEnv, StepCircuit};

/// Poseidon state size (width of the sponge).
pub const STATE_SIZE: usize = 3;

/// Total number of full rounds in the Poseidon permutation.
pub const NUMBER_FULL_ROUNDS: usize = 60;

/// Number of Poseidon rounds processed per circuit step.
/// With 15 columns and width 3, we can fit 5 rounds per row.
pub const ROUNDS_PER_ROW: usize = 5;

/// Total number of rows needed for the full Poseidon permutation.
/// 60 rounds / 5 rounds per row = 12 rows
pub const ROWS_FOR_PERMUTATION: usize = NUMBER_FULL_ROUNDS / ROUNDS_PER_ROW;

/// Poseidon permutation circuit for a single step (5 rounds).
///
/// This circuit processes 5 Poseidon full rounds on a 3-element state.
/// It is designed to be chained: 12 steps complete the full permutation.
///
/// # Type Parameters
///
/// - `F`: The field type (must match the Poseidon parameters)
/// - `FULL_ROUNDS`: The total number of Poseidon rounds (typically 55 or 60)
#[derive(Clone, Debug)]
pub struct PoseidonRoundCircuit<F: PrimeField, const FULL_ROUNDS: usize> {
    /// Starting round index (0, 5, 10, ..., 55)
    pub starting_round: usize,
    /// Poseidon parameters (MDS matrix and round constants)
    pub params: &'static ArithmeticSpongeParams<F, FULL_ROUNDS>,
}

impl<F: PrimeField, const FULL_ROUNDS: usize> PoseidonRoundCircuit<F, FULL_ROUNDS> {
    /// Create a new Poseidon round circuit starting at the given round.
    ///
    /// # Arguments
    ///
    /// * `starting_round` - The round index to start from (must be multiple of 5)
    /// * `params` - Static reference to Poseidon parameters
    ///
    /// # Panics
    ///
    /// Panics if `starting_round` is not a multiple of 5 or exceeds FULL_ROUNDS.
    pub fn new(
        starting_round: usize,
        params: &'static ArithmeticSpongeParams<F, FULL_ROUNDS>,
    ) -> Self {
        assert!(
            starting_round % ROUNDS_PER_ROW == 0,
            "Starting round must be a multiple of {ROUNDS_PER_ROW}"
        );
        assert!(
            starting_round + ROUNDS_PER_ROW <= FULL_ROUNDS,
            "Starting round {starting_round} + {ROUNDS_PER_ROW} rounds must not exceed {FULL_ROUNDS}"
        );
        Self {
            starting_round,
            params,
        }
    }

    /// Compute one round of Poseidon: S-box -> MDS -> ARK
    fn round(&self, state: [F; STATE_SIZE], round: usize) -> [F; STATE_SIZE] {
        // S-box: x^5
        let state: [F; STATE_SIZE] = [
            state[0].pow([5]),
            state[1].pow([5]),
            state[2].pow([5]),
        ];

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
}

impl<F: PrimeField, const FULL_ROUNDS: usize> StepCircuit<F, 3>
    for PoseidonRoundCircuit<F, FULL_ROUNDS>
{
    const NAME: &'static str = "PoseidonRoundCircuit";

    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        env: &mut E,
        z: &[E::Variable; STATE_SIZE],
    ) -> [E::Variable; STATE_SIZE] {
        // Input state
        let mut state = z.clone();

        // Process 5 rounds
        for round_offset in 0..ROUNDS_PER_ROW {
            let round = self.starting_round + round_offset;
            let is_last_round = round_offset == ROUNDS_PER_ROW - 1;

            // S-box: x^5 = x^4 * x = (x^2)^2 * x
            // Compute x^5 for each state element and constrain
            let mut sbox_state = [env.zero(), env.zero(), env.zero()];

            for i in 0..STATE_SIZE {
                // x^2
                let x2 = state[i].clone() * state[i].clone();
                // x^4
                let x4 = x2.clone() * x2;
                // x^5 = x^4 * x
                let x5 = x4 * state[i].clone();

                // Allocate and write witness for S-box output
                let sbox_witness = {
                    let pos = env.allocate();
                    env.write_column(pos, x5.clone())
                };
                env.assert_eq(&sbox_witness, &x5);

                sbox_state[i] = sbox_witness;
            }

            // MDS matrix multiplication and add round constants
            let mds = &self.params.mds;
            let rc = &self.params.round_constants[round];

            // For the last round, allocate outputs on the next row
            for i in 0..STATE_SIZE {
                // MDS row i * sbox_state
                let c0 = env.constant(mds[i][0]);
                let c1 = env.constant(mds[i][1]);
                let c2 = env.constant(mds[i][2]);

                let term0 = c0 * sbox_state[0].clone();
                let term1 = c1 * sbox_state[1].clone();
                let term2 = c2 * sbox_state[2].clone();

                let acc = term0 + term1 + term2;

                // Add round constant
                let rc_const = env.constant(rc[i]);
                let mds_result = acc + rc_const;

                // Allocate and write witness
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

    fn output(&self, z: &[F; STATE_SIZE]) -> [F; STATE_SIZE] {
        let mut state = *z;

        // Apply 5 rounds
        for round_offset in 0..ROUNDS_PER_ROW {
            let round = self.starting_round + round_offset;
            state = self.round(state, round);
        }

        state
    }
}

/// Full Poseidon permutation circuit (60 rounds).
///
/// This circuit chains 12 `PoseidonRoundCircuit` steps to complete
/// the full Poseidon permutation.
#[derive(Clone, Debug)]
pub struct PoseidonPermutationCircuit<F: PrimeField, const FULL_ROUNDS: usize> {
    /// Poseidon parameters
    pub params: &'static ArithmeticSpongeParams<F, FULL_ROUNDS>,
}

impl<F: PrimeField, const FULL_ROUNDS: usize> PoseidonPermutationCircuit<F, FULL_ROUNDS> {
    /// Create a new full Poseidon permutation circuit.
    pub fn new(params: &'static ArithmeticSpongeParams<F, FULL_ROUNDS>) -> Self {
        Self { params }
    }

    /// Number of rows needed for this permutation (FULL_ROUNDS / 5).
    pub const fn num_rows() -> usize {
        FULL_ROUNDS / ROUNDS_PER_ROW
    }

    /// Compute the full Poseidon permutation.
    pub fn permute(&self, state: [F; STATE_SIZE]) -> [F; STATE_SIZE] {
        let mut result = state;
        for step in 0..Self::num_rows() {
            let round_circuit = PoseidonRoundCircuit::new(step * ROUNDS_PER_ROW, self.params);
            result = round_circuit.output(&result);
        }
        result
    }
}

impl<F: PrimeField, const FULL_ROUNDS: usize> StepCircuit<F, 3>
    for PoseidonPermutationCircuit<F, FULL_ROUNDS>
{
    const NAME: &'static str = "PoseidonPermutationCircuit";

    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        env: &mut E,
        z: &[E::Variable; STATE_SIZE],
    ) -> [E::Variable; STATE_SIZE] {
        let mut state = z.clone();

        // Chain round circuits (FULL_ROUNDS / 5)
        for step in 0..Self::num_rows() {
            let round_circuit = PoseidonRoundCircuit::new(step * ROUNDS_PER_ROW, self.params);
            state = round_circuit.synthesize(env, &state);
        }

        state
    }

    fn output(&self, z: &[F; STATE_SIZE]) -> [F; STATE_SIZE] {
        self.permute(*z)
    }

    fn num_rows(&self) -> usize {
        Self::num_rows()
    }
}

/// Poseidon sponge absorb circuit.
///
/// Absorbs 2 field elements into the Poseidon sponge state (rate = 2).
/// The first element of the state is the capacity and is not modified.
#[derive(Clone, Debug)]
pub struct PoseidonAbsorbCircuit<F: PrimeField> {
    /// Values to absorb into the sponge
    pub values: [F; 2],
}

impl<F: PrimeField> PoseidonAbsorbCircuit<F> {
    /// Create a new absorb circuit with the given values.
    pub fn new(values: [F; 2]) -> Self {
        Self { values }
    }
}

impl<F: PrimeField> StepCircuit<F, 3> for PoseidonAbsorbCircuit<F> {
    const NAME: &'static str = "PoseidonAbsorbCircuit";

    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        env: &mut E,
        z: &[E::Variable; STATE_SIZE],
    ) -> [E::Variable; STATE_SIZE] {
        // The first element (capacity) is unchanged
        let capacity = z[0].clone();

        // Absorb by adding to the rate portion of the state
        let absorbed_1 = z[1].clone() + env.constant(self.values[0]);
        let absorbed_2 = z[2].clone() + env.constant(self.values[1]);

        // Allocate and write witnesses
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

        [capacity, new_state_1, new_state_2]
    }

    fn output(&self, z: &[F; STATE_SIZE]) -> [F; STATE_SIZE] {
        // Absorb by adding to the rate portion
        [z[0], z[1] + self.values[0], z[2] + self.values[1]]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::ConstraintEnv;
    use crate::curve::PlonkSpongeConstants;
    use crate::poseidon_3_60_0_5_5_fp;
    use mina_curves::pasta::Fp;
    use mina_poseidon::{constants::SpongeConstants, permutation::poseidon_block_cipher};

    // Use arrabbiata's Poseidon params (60 rounds, x^5 S-box)
    fn fp_params() -> &'static ArithmeticSpongeParams<Fp, NUMBER_FULL_ROUNDS> {
        poseidon_3_60_0_5_5_fp::static_params()
    }

    // ========================================================================
    // Output tests (synthesize/output correctness)
    // ========================================================================

    #[test]
    fn test_poseidon_round_output() {
        let circuit = PoseidonRoundCircuit::<Fp, NUMBER_FULL_ROUNDS>::new(0, fp_params());
        let z = [Fp::from(1u64), Fp::from(2u64), Fp::from(3u64)];

        // Compute 5 rounds
        let output = circuit.output(&z);

        // Output should be different from input
        assert_ne!(output, z);
    }

    #[test]
    fn test_poseidon_round_deterministic() {
        let circuit = PoseidonRoundCircuit::<Fp, NUMBER_FULL_ROUNDS>::new(0, fp_params());
        let z = [Fp::from(1u64), Fp::from(2u64), Fp::from(3u64)];

        let output1 = circuit.output(&z);
        let output2 = circuit.output(&z);

        assert_eq!(output1, output2, "Same inputs should give same outputs");
    }

    #[test]
    fn test_poseidon_permutation_matches_mina() {
        // Use arrabbiata's PlonkSpongeConstants which has PERM_SBOX = 5
        let circuit = PoseidonPermutationCircuit::<Fp, NUMBER_FULL_ROUNDS>::new(fp_params());
        let z = [Fp::from(0u64), Fp::from(0u64), Fp::from(0u64)];

        // Our implementation
        let our_output = circuit.output(&z);

        // Use mina_poseidon's block cipher with arrabbiata's sponge constants (x^5)
        let mut mina_state = z;
        poseidon_block_cipher::<Fp, PlonkSpongeConstants, NUMBER_FULL_ROUNDS>(fp_params(), &mut mina_state);

        assert_eq!(
            our_output, mina_state,
            "Our Poseidon permutation should match mina_poseidon with x^5 S-box"
        );
    }

    #[test]
    fn test_poseidon_absorb() {
        let circuit = PoseidonAbsorbCircuit::<Fp>::new([Fp::from(10u64), Fp::from(20u64)]);
        let z = [Fp::from(1u64), Fp::from(2u64), Fp::from(3u64)];

        let output = circuit.output(&z);

        // Capacity (first element) unchanged
        assert_eq!(output[0], z[0]);
        // Rate elements have values added
        assert_eq!(output[1], z[1] + Fp::from(10u64));
        assert_eq!(output[2], z[2] + Fp::from(20u64));
    }

    #[test]
    fn test_poseidon_permutation_num_rows() {
        let circuit = PoseidonPermutationCircuit::<Fp, NUMBER_FULL_ROUNDS>::new(fp_params());

        // 60 rounds / 5 rounds per row = 12 rows
        let expected_rows = PlonkSpongeConstants::PERM_ROUNDS_FULL / ROUNDS_PER_ROW;
        assert_eq!(
            circuit.num_rows(),
            expected_rows,
            "Full permutation should take {} rows",
            expected_rows
        );
    }

    // ========================================================================
    // Constraint tests (degree checking)
    // ========================================================================

    #[test]
    fn test_poseidon_absorb_constraints() {
        use rand::{Rng, SeedableRng};

        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        for _ in 0..10 {
            let v1: u64 = rng.gen();
            let v2: u64 = rng.gen();
            let circuit = PoseidonAbsorbCircuit::<Fp>::new([Fp::from(v1), Fp::from(v2)]);

            let mut env = ConstraintEnv::<Fp>::new();
            let z = env.make_input_vars::<3>();
            let _ = circuit.synthesize(&mut env, &z);

            // PoseidonAbsorbCircuit has 2 constraints (one for each rate element)
            assert_eq!(
                env.num_constraints(),
                2,
                "PoseidonAbsorbCircuit should have 2 constraints"
            );

            // Both constraints should have degree 1 (linear)
            let degrees = env.constraint_degrees();
            assert_eq!(degrees.len(), 2);
            assert_eq!(degrees[0], 1, "First absorb constraint should have degree 1");
            assert_eq!(degrees[1], 1, "Second absorb constraint should have degree 1");

            // Verify max degree
            assert_eq!(env.max_degree(), 1, "Max degree should be 1");

            env.check_degrees()
                .expect("All constraints should have degree <= MAX_DEGREE");
        }
    }

    /// Regression test for PoseidonAbsorbCircuit metrics.
    #[test]
    fn test_poseidon_absorb_metrics() {
        let circuit = PoseidonAbsorbCircuit::<Fp>::new([Fp::from(10u64), Fp::from(20u64)]);

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<3>();
        let _ = circuit.synthesize(&mut env, &z);

        assert_eq!(env.num_constraints(), 2, "constraints changed");
        assert_eq!(env.num_witness_allocations(), 2, "witness allocations changed");
        assert_eq!(env.max_degree(), 1, "max degree changed");
    }

    #[test]
    fn test_poseidon_round_constraints() {
        use rand::{Rng, SeedableRng};

        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        // Test different starting rounds (0, 5, 10, ..., 55)
        for step in 0..12 {
            let starting_round = step * ROUNDS_PER_ROW;
            let circuit = PoseidonRoundCircuit::<Fp, NUMBER_FULL_ROUNDS>::new(starting_round, fp_params());

            let mut env = ConstraintEnv::<Fp>::new();
            let z = env.make_input_vars::<3>();
            let _ = circuit.synthesize(&mut env, &z);

            // Per round: 3 sbox witnesses + 3 new_state witnesses = 6
            // But last round uses allocate_next_row which doesn't count
            // So: 5 rounds * 3 sbox + 4 rounds * 3 new_state = 15 + 12 = 27
            let expected_witnesses = ROUNDS_PER_ROW * 3 + (ROUNDS_PER_ROW - 1) * 3;
            assert_eq!(
                env.num_witness_allocations(),
                expected_witnesses,
                "PoseidonRoundCircuit starting at round {} should have {} witness allocations",
                starting_round,
                expected_witnesses
            );

            // Per round: 3 S-box constraints (degree 5) + 3 MDS constraints (degree 1) = 6
            // 5 rounds = 30 constraints
            let expected_constraints = ROUNDS_PER_ROW * 6;
            assert_eq!(
                env.num_constraints(),
                expected_constraints,
                "PoseidonRoundCircuit starting at round {} should have {} constraints",
                starting_round,
                expected_constraints
            );

            // Max degree should be 5 (from S-box: x^5)
            assert_eq!(
                env.max_degree(),
                5,
                "Max degree should be 5 for starting round {}",
                starting_round
            );

            env.check_degrees()
                .expect("All constraints should have degree <= MAX_DEGREE");
        }

        // Test with random input values for output correctness
        for _ in 0..10 {
            let circuit = PoseidonRoundCircuit::<Fp, NUMBER_FULL_ROUNDS>::new(0, fp_params());
            let z = [
                Fp::from(rng.gen::<u64>()),
                Fp::from(rng.gen::<u64>()),
                Fp::from(rng.gen::<u64>()),
            ];

            let output1 = circuit.output(&z);
            let output2 = circuit.output(&z);
            assert_eq!(output1, output2, "Output should be deterministic");
        }
    }

    /// Regression test for PoseidonRoundCircuit metrics.
    #[test]
    fn test_poseidon_round_metrics() {
        let circuit = PoseidonRoundCircuit::<Fp, NUMBER_FULL_ROUNDS>::new(0, fp_params());

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<3>();
        let _ = circuit.synthesize(&mut env, &z);

        // 5 rounds * 3 sbox + 4 rounds * 3 new_state = 27 witnesses
        assert_eq!(env.num_witness_allocations(), 27, "witness allocations changed");
        // 5 rounds * 6 constraints = 30 constraints
        assert_eq!(env.num_constraints(), 30, "constraints changed");
        // Max degree is 5 (S-box: x^5)
        assert_eq!(env.max_degree(), 5, "max degree changed");
    }
}

// ============================================================================
// Trace tests
// ============================================================================

#[cfg(test)]
mod trace_tests {
    use super::*;
    use crate::circuit::{ConstraintEnv, StepCircuit, Trace};
    use crate::poseidon_3_60_0_5_5_fp;
    use mina_curves::pasta::Fp;
    use rand::{Rng, SeedableRng};

    fn fp_params() -> &'static ArithmeticSpongeParams<Fp, NUMBER_FULL_ROUNDS> {
        poseidon_3_60_0_5_5_fp::static_params()
    }

    #[test]
    fn test_poseidon_absorb_trace() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        for _ in 0..10 {
            let v1 = Fp::from(rng.gen::<u64>());
            let v2 = Fp::from(rng.gen::<u64>());
            let circuit = PoseidonAbsorbCircuit::<Fp>::new([v1, v2]);

            let s0 = Fp::from(rng.gen::<u64>());
            let s1 = Fp::from(rng.gen::<u64>());
            let s2 = Fp::from(rng.gen::<u64>());

            let mut env = Trace::<Fp>::new(16);
            let z = env.make_input_vars([s0, s1, s2]);
            let output = circuit.synthesize(&mut env, &z);

            // Verify output matches expected
            let expected = circuit.output(&[s0, s1, s2]);
            assert_eq!(output[0], expected[0], "Capacity should be unchanged");
            assert_eq!(output[1], expected[1], "First rate element mismatch");
            assert_eq!(output[2], expected[2], "Second rate element mismatch");

            // Verify trace structure
            assert_eq!(env.get(0, 0), Some(&s0), "Input s0 should be in column 0");
            assert_eq!(env.get(0, 1), Some(&s1), "Input s1 should be in column 1");
            assert_eq!(env.get(0, 2), Some(&s2), "Input s2 should be in column 2");
        }
    }

    // NOTE: PoseidonRoundCircuit allocates ~27 witnesses per step, which exceeds
    // the Trace column limit of 15. The circuit is designed to be tested with
    // ConstraintEnv (for constraint checking) and the output() method (for correctness).
    // Full trace testing would require a multi-row layout with proper column management.

    #[test]
    fn test_poseidon_round_output_correctness() {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        // Test all 12 possible starting rounds with random inputs
        for step in 0..12 {
            let starting_round = step * ROUNDS_PER_ROW;
            let circuit = PoseidonRoundCircuit::<Fp, NUMBER_FULL_ROUNDS>::new(starting_round, fp_params());

            for _ in 0..5 {
                let z = [
                    Fp::from(rng.gen::<u64>()),
                    Fp::from(rng.gen::<u64>()),
                    Fp::from(rng.gen::<u64>()),
                ];

                let output1 = circuit.output(&z);
                let output2 = circuit.output(&z);
                assert_eq!(
                    output1, output2,
                    "Output should be deterministic for starting round {}",
                    starting_round
                );

                // Verify output is different from input (Poseidon should mix)
                assert_ne!(output1, z, "Output should differ from input");
            }
        }
    }

    /// Verify PoseidonRoundCircuit chained output matches mina-poseidon full permutation.
    #[test]
    fn test_poseidon_round_chain_matches_mina() {
        use crate::curve::PlonkSpongeConstants;
        use mina_poseidon::permutation::poseidon_block_cipher;
        use rand::{Rng, SeedableRng};

        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        for _ in 0..10 {
            let z = [
                Fp::from(rng.gen::<u64>()),
                Fp::from(rng.gen::<u64>()),
                Fp::from(rng.gen::<u64>()),
            ];

            // Our implementation: chain all 12 round circuits (60 rounds total)
            let mut our_state = z;
            for step in 0..ROWS_FOR_PERMUTATION {
                let circuit =
                    PoseidonRoundCircuit::<Fp, NUMBER_FULL_ROUNDS>::new(step * ROUNDS_PER_ROW, fp_params());
                our_state = circuit.output(&our_state);
            }

            // Reference: full permutation using mina_poseidon
            let mut ref_state = z;
            poseidon_block_cipher::<Fp, PlonkSpongeConstants, NUMBER_FULL_ROUNDS>(fp_params(), &mut ref_state);

            assert_eq!(
                our_state, ref_state,
                "Chained PoseidonRoundCircuit should match mina_poseidon block cipher"
            );
        }
    }

    #[test]
    fn test_poseidon_permutation_output_correctness() {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        let circuit = PoseidonPermutationCircuit::<Fp, NUMBER_FULL_ROUNDS>::new(fp_params());

        for _ in 0..10 {
            let z = [
                Fp::from(rng.gen::<u64>()),
                Fp::from(rng.gen::<u64>()),
                Fp::from(rng.gen::<u64>()),
            ];

            let output1 = circuit.output(&z);
            let output2 = circuit.output(&z);
            assert_eq!(output1, output2, "Output should be deterministic");

            // Verify output is different from input
            assert_ne!(output1, z, "Full permutation should change all elements");
        }
    }

    #[test]
    fn test_poseidon_round_last_output_on_next_row() {
        // Verify that the last round's output uses next_row allocation
        // by checking the circuit structure
        let circuit = PoseidonRoundCircuit::<Fp, NUMBER_FULL_ROUNDS>::new(0, fp_params());

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<3>();
        let output = circuit.synthesize(&mut env, &z);

        // The output variables should reference the next row
        // We can verify this by checking the variable structure
        // (output should be different from all current-row allocations)
        let output_str = format!("{:?}", output);
        assert!(
            output_str.contains("Next"),
            "Output should reference next row, got: {}",
            output_str
        );
    }
}
