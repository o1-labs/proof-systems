//! Poseidon Kimchi hash function circuits.
//!
//! This module implements the Poseidon hash function with Kimchi-compatible
//! parameters (x^7 S-box, 55 full rounds) as circuits.
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
//! - x^7 = w2^3 * x = w2 * w2 * w2 * x (inline into MDS, degree 4)
//!
//! This requires only 1 intermediate witness (w2) per state element.
//!
//! ## Layout (4 rounds per row)
//!
//! With the optimized S-box, we fit 4 rounds per row:
//!
//! ```text
//! | C0-C2  | C3-C5  | C6-C8  | C9-C11 | C12-C14 |
//! | ------ | ------ | ------ | ------ | ------- |
//! | w2     | m      | w2'    | m'     | w2''    |
//! | m'' (next row)  | w2'''  | m'''   | ...     |
//! ```
//!
//! - w2_i = x_i^2 (S-box intermediate, 3 values)
//! - m_i = MDS(w2^3 * x) + rc (round output, 3 values)
//!
//! With 4 rounds per row: 4 * 3 w2 + 3 * 3 m = 12 + 9 = 15 columns (last m on next row)
//!
//! Note: With 55 rounds and 4 rounds per row, we need 14 rows (55 / 4 = 13.75).

use ark_ff::PrimeField;
use mina_poseidon::poseidon::ArithmeticSpongeParams;

use crate::circuit::{CircuitEnv, SelectorEnv, StepCircuit};

/// Poseidon state size (width of the sponge).
pub const STATE_SIZE: usize = 3;

/// Total number of full rounds in the Kimchi Poseidon permutation.
pub const KIMCHI_FULL_ROUNDS: usize = 55;

/// Number of Poseidon rounds processed per circuit step.
/// With 15 columns and width 3, we can fit 5 rounds per row.
pub const KIMCHI_ROUNDS_PER_ROW: usize = 5;

/// Total number of rows needed for the full Kimchi Poseidon permutation.
/// 55 rounds / 5 rounds per row = 11 rows
pub const KIMCHI_ROWS_FOR_PERMUTATION: usize = KIMCHI_FULL_ROUNDS / KIMCHI_ROUNDS_PER_ROW;

/// Poseidon Kimchi permutation circuit for a single step (5 rounds).
///
/// This circuit processes 5 Poseidon full rounds on a 3-element state
/// using the x^7 S-box (Kimchi-compatible).
///
/// It is designed to be chained: 11 steps complete the full 55-round permutation.
#[derive(Clone, Debug)]
pub struct PoseidonKimchiRoundCircuit<F: PrimeField> {
    /// Starting round index (0, 5, 10, ..., 50)
    pub starting_round: usize,
    /// Poseidon parameters (MDS matrix and round constants)
    pub params: &'static ArithmeticSpongeParams<F, KIMCHI_FULL_ROUNDS>,
}

impl<F: PrimeField> PoseidonKimchiRoundCircuit<F> {
    /// Create a new Poseidon Kimchi round circuit starting at the given round.
    ///
    /// # Arguments
    ///
    /// * `starting_round` - The round index to start from (must be multiple of 5)
    /// * `params` - Static reference to Poseidon parameters
    ///
    /// # Panics
    ///
    /// Panics if `starting_round` is not a multiple of 5 or exceeds 55.
    pub fn new(
        starting_round: usize,
        params: &'static ArithmeticSpongeParams<F, KIMCHI_FULL_ROUNDS>,
    ) -> Self {
        assert!(
            starting_round % KIMCHI_ROUNDS_PER_ROW == 0,
            "Starting round must be a multiple of {KIMCHI_ROUNDS_PER_ROW}"
        );
        assert!(
            starting_round + KIMCHI_ROUNDS_PER_ROW <= KIMCHI_FULL_ROUNDS,
            "Starting round {starting_round} + {KIMCHI_ROUNDS_PER_ROW} rounds must not exceed {KIMCHI_FULL_ROUNDS}"
        );
        Self {
            starting_round,
            params,
        }
    }

    /// Compute one round of Poseidon Kimchi: S-box (x^7) -> MDS -> ARK
    fn round(&self, state: [F; STATE_SIZE], round: usize) -> [F; STATE_SIZE] {
        // S-box: x^7 = x^4 * x^2 * x
        let state: [F; STATE_SIZE] = [
            state[0].pow([7]),
            state[1].pow([7]),
            state[2].pow([7]),
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

impl<F: PrimeField> StepCircuit<F, 3> for PoseidonKimchiRoundCircuit<F> {
    const NAME: &'static str = "PoseidonKimchiRoundCircuit";

    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        env: &mut E,
        z: &[E::Variable; STATE_SIZE],
    ) -> [E::Variable; STATE_SIZE] {
        // Input state
        let mut state = z.clone();

        // Process 5 rounds
        for round_offset in 0..KIMCHI_ROUNDS_PER_ROW {
            let round = self.starting_round + round_offset;
            let is_last_round = round_offset == KIMCHI_ROUNDS_PER_ROW - 1;

            // S-box: x^7 = x^4 * x^2 * x
            // Decomposed into intermediate witnesses for max degree 5:
            // - w2 = x^2 (constraint degree 2)
            // - w4 = w2^2 = x^4 (constraint degree 2)
            // - w7 = w4 * w2 * x = x^7 (constraint degree 3)
            let mut sbox_state = [env.zero(), env.zero(), env.zero()];

            for i in 0..STATE_SIZE {
                let x = &state[i];

                // Compute x^2 and allocate witness
                let x2_expr = x.clone() * x.clone();
                let w2 = {
                    let pos = env.allocate();
                    env.write_column(pos, x2_expr.clone())
                };
                env.assert_eq(&w2, &x2_expr);

                // Compute x^4 = w2^2 and allocate witness
                let x4_expr = w2.clone() * w2.clone();
                let w4 = {
                    let pos = env.allocate();
                    env.write_column(pos, x4_expr.clone())
                };
                env.assert_eq(&w4, &x4_expr);

                // Compute x^7 = w4 * w2 * x and allocate witness
                // This is degree 3 (three witness variables multiplied)
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
        for round_offset in 0..KIMCHI_ROUNDS_PER_ROW {
            let round = self.starting_round + round_offset;
            state = self.round(state, round);
        }

        state
    }
}

/// Full Poseidon Kimchi permutation circuit (55 rounds).
///
/// This circuit chains 11 `PoseidonKimchiRoundCircuit` steps to complete
/// the full Poseidon Kimchi permutation.
#[derive(Clone, Debug)]
pub struct PoseidonKimchiPermutationCircuit<F: PrimeField> {
    /// Poseidon parameters
    pub params: &'static ArithmeticSpongeParams<F, KIMCHI_FULL_ROUNDS>,
}

impl<F: PrimeField> PoseidonKimchiPermutationCircuit<F> {
    /// Create a new full Poseidon Kimchi permutation circuit.
    pub fn new(params: &'static ArithmeticSpongeParams<F, KIMCHI_FULL_ROUNDS>) -> Self {
        Self { params }
    }

    /// Number of rows needed for this permutation (55 / 5 = 11).
    pub const fn num_rows() -> usize {
        KIMCHI_ROWS_FOR_PERMUTATION
    }

    /// Compute the full Poseidon Kimchi permutation.
    pub fn permute(&self, state: [F; STATE_SIZE]) -> [F; STATE_SIZE] {
        let mut result = state;
        for step in 0..Self::num_rows() {
            let round_circuit =
                PoseidonKimchiRoundCircuit::new(step * KIMCHI_ROUNDS_PER_ROW, self.params);
            result = round_circuit.output(&result);
        }
        result
    }
}

impl<F: PrimeField> StepCircuit<F, 3> for PoseidonKimchiPermutationCircuit<F> {
    const NAME: &'static str = "PoseidonKimchiPermutationCircuit";

    fn synthesize<E: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        env: &mut E,
        z: &[E::Variable; STATE_SIZE],
    ) -> [E::Variable; STATE_SIZE] {
        let mut state = z.clone();

        // Chain round circuits (55 / 5 = 11)
        for step in 0..Self::num_rows() {
            let round_circuit =
                PoseidonKimchiRoundCircuit::new(step * KIMCHI_ROUNDS_PER_ROW, self.params);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::ConstraintEnv;
    use mina_curves::pasta::Fp;
    use mina_poseidon::{
        constants::PlonkSpongeConstantsKimchi,
        pasta::fp_kimchi,
        permutation::poseidon_block_cipher,
    };

    fn kimchi_params() -> &'static ArithmeticSpongeParams<Fp, KIMCHI_FULL_ROUNDS> {
        fp_kimchi::static_params()
    }

    // ========================================================================
    // Output tests (synthesize/output correctness)
    // ========================================================================

    #[test]
    fn test_poseidon_kimchi_round_output() {
        let circuit = PoseidonKimchiRoundCircuit::<Fp>::new(0, kimchi_params());
        let z = [Fp::from(1u64), Fp::from(2u64), Fp::from(3u64)];

        // Compute 5 rounds
        let output = circuit.output(&z);

        // Output should be different from input
        assert_ne!(output, z);
    }

    #[test]
    fn test_poseidon_kimchi_round_deterministic() {
        let circuit = PoseidonKimchiRoundCircuit::<Fp>::new(0, kimchi_params());
        let z = [Fp::from(1u64), Fp::from(2u64), Fp::from(3u64)];

        let output1 = circuit.output(&z);
        let output2 = circuit.output(&z);

        assert_eq!(output1, output2, "Same inputs should give same outputs");
    }

    #[test]
    fn test_poseidon_kimchi_permutation_matches_mina() {
        let circuit = PoseidonKimchiPermutationCircuit::<Fp>::new(kimchi_params());
        let z = [Fp::from(0u64), Fp::from(0u64), Fp::from(0u64)];

        // Our implementation
        let our_output = circuit.output(&z);

        // Use mina_poseidon's block cipher with Kimchi constants (x^7)
        let mut mina_state = z;
        poseidon_block_cipher::<Fp, PlonkSpongeConstantsKimchi, KIMCHI_FULL_ROUNDS>(
            kimchi_params(),
            &mut mina_state,
        );

        assert_eq!(
            our_output, mina_state,
            "Our Poseidon Kimchi permutation should match mina_poseidon with x^7 S-box"
        );
    }

    #[test]
    fn test_poseidon_kimchi_permutation_num_rows() {
        let circuit = PoseidonKimchiPermutationCircuit::<Fp>::new(kimchi_params());

        // 55 rounds / 5 rounds per row = 11 rows
        let expected_rows = KIMCHI_FULL_ROUNDS / KIMCHI_ROUNDS_PER_ROW;
        assert_eq!(
            circuit.num_rows(),
            expected_rows,
            "Full Kimchi permutation should take {} rows",
            expected_rows
        );
    }

    // ========================================================================
    // Constraint tests (degree checking)
    // ========================================================================

    #[test]
    fn test_poseidon_kimchi_round_constraints() {
        // Test different starting rounds (0, 5, 10, ..., 50)
        for step in 0..11 {
            let starting_round = step * KIMCHI_ROUNDS_PER_ROW;
            let circuit = PoseidonKimchiRoundCircuit::<Fp>::new(starting_round, kimchi_params());

            // Use default max degree from lib.rs (MAX_DEGREE = 5)
            let mut env = ConstraintEnv::<Fp>::new();
            let z = env.make_input_vars::<3>();
            let _ = circuit.synthesize(&mut env, &z);

            // Per round: 9 sbox witnesses (3 per state element: w2, w4, w7) + 3 new_state witnesses
            // But last round uses allocate_next_row which doesn't count
            // So: 5 rounds * 9 sbox + 4 rounds * 3 new_state = 45 + 12 = 57
            let expected_witnesses = KIMCHI_ROUNDS_PER_ROW * 9 + (KIMCHI_ROUNDS_PER_ROW - 1) * 3;
            assert_eq!(
                env.num_witness_allocations(),
                expected_witnesses,
                "PoseidonKimchiRoundCircuit starting at round {} should have {} witness allocations",
                starting_round,
                expected_witnesses
            );

            // Per round: 9 S-box constraints (3 per state element) + 3 MDS constraints = 12
            // 5 rounds = 60 constraints
            let expected_constraints = KIMCHI_ROUNDS_PER_ROW * 12;
            assert_eq!(
                env.num_constraints(),
                expected_constraints,
                "PoseidonKimchiRoundCircuit starting at round {} should have {} constraints",
                starting_round,
                expected_constraints
            );

            // Max degree should be 3 (from decomposed S-box: w4 * w2 * x)
            assert_eq!(
                env.max_degree(),
                3,
                "Max degree should be 3 for starting round {}",
                starting_round
            );

            env.check_degrees()
                .expect("All constraints should have degree <= 5");
        }
    }

    /// Regression test for PoseidonKimchiRoundCircuit metrics.
    #[test]
    fn test_poseidon_kimchi_round_metrics() {
        let circuit = PoseidonKimchiRoundCircuit::<Fp>::new(0, kimchi_params());

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<3>();
        let _ = circuit.synthesize(&mut env, &z);

        // 5 rounds * 9 sbox + 4 rounds * 3 new_state = 57 witnesses
        assert_eq!(env.num_witness_allocations(), 57, "witness allocations changed");
        // 5 rounds * 12 constraints = 60 constraints
        assert_eq!(env.num_constraints(), 60, "constraints changed");
        // Max degree is 3 (decomposed S-box: w4 * w2 * x)
        assert_eq!(env.max_degree(), 3, "max degree changed");
    }

    #[test]
    fn test_poseidon_kimchi_chain_matches_mina() {
        use rand::{Rng, SeedableRng};

        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        for _ in 0..10 {
            let z = [
                Fp::from(rng.gen::<u64>()),
                Fp::from(rng.gen::<u64>()),
                Fp::from(rng.gen::<u64>()),
            ];

            // Our implementation: chain all 11 round circuits (55 rounds total)
            let mut our_state = z;
            for step in 0..KIMCHI_ROWS_FOR_PERMUTATION {
                let circuit = PoseidonKimchiRoundCircuit::<Fp>::new(
                    step * KIMCHI_ROUNDS_PER_ROW,
                    kimchi_params(),
                );
                our_state = circuit.output(&our_state);
            }

            // Reference: full permutation using mina_poseidon
            let mut ref_state = z;
            poseidon_block_cipher::<Fp, PlonkSpongeConstantsKimchi, KIMCHI_FULL_ROUNDS>(
                kimchi_params(),
                &mut ref_state,
            );

            assert_eq!(
                our_state, ref_state,
                "Chained PoseidonKimchiRoundCircuit should match mina_poseidon block cipher"
            );
        }
    }

    // ========================================================================
    // Sponge tests (PoseidonKimchiSponge trait implementation)
    // ========================================================================

    #[test]
    fn test_poseidon_kimchi_sponge_absorb() {
        use crate::circuits::hash::{PoseidonKimchiSponge, Sponge};

        let sponge = PoseidonKimchiSponge::<Fp>::new(kimchi_params());
        let state = [Fp::from(1u64), Fp::from(2u64), Fp::from(3u64)];
        let values = [Fp::from(10u64), Fp::from(20u64)];

        let output = sponge.absorb_witness(&state, values);

        // Rate elements (indices 0, 1) have values added
        assert_eq!(output[0], state[0] + values[0], "First rate element mismatch");
        assert_eq!(output[1], state[1] + values[1], "Second rate element mismatch");
        // Capacity (index 2) unchanged (mina-poseidon convention)
        assert_eq!(output[2], state[2], "Capacity should be unchanged");
    }

    #[test]
    fn test_poseidon_kimchi_sponge_permute_matches_mina() {
        use crate::circuits::hash::{PoseidonKimchiSponge, Sponge};
        use rand::{Rng, SeedableRng};

        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let sponge = PoseidonKimchiSponge::<Fp>::new(kimchi_params());

        for _ in 0..10 {
            let state = [
                Fp::from(rng.gen::<u64>()),
                Fp::from(rng.gen::<u64>()),
                Fp::from(rng.gen::<u64>()),
            ];

            // Our sponge implementation
            let our_output = sponge.permute_witness(&state);

            // Reference: mina_poseidon
            let mut ref_state = state;
            poseidon_block_cipher::<Fp, PlonkSpongeConstantsKimchi, KIMCHI_FULL_ROUNDS>(
                kimchi_params(),
                &mut ref_state,
            );

            assert_eq!(
                our_output, ref_state,
                "Sponge permute_witness should match mina_poseidon"
            );
        }
    }

    #[test]
    fn test_poseidon_kimchi_sponge_squeeze() {
        use crate::circuits::hash::{PoseidonKimchiSponge, Sponge};

        let sponge = PoseidonKimchiSponge::<Fp>::new(kimchi_params());
        let state = [Fp::from(1u64), Fp::from(2u64), Fp::from(3u64)];

        // Squeeze returns the first rate element (state[0] per mina-poseidon convention)
        let squeezed = sponge.squeeze_witness(&state);

        assert_eq!(
            squeezed, state[0],
            "Squeeze should return the first rate element (state[0])"
        );
    }

    #[test]
    fn test_poseidon_kimchi_sponge_full_cycle() {
        use ark_ff::Zero;
        use crate::circuits::hash::{PoseidonKimchiSponge, Sponge};
        use mina_poseidon::poseidon::{ArithmeticSponge, Sponge as MinaSponge};
        use rand::{Rng, SeedableRng};

        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        for _ in 0..10 {
            let v1 = Fp::from(rng.gen::<u64>());
            let v2 = Fp::from(rng.gen::<u64>());

            // Our sponge implementation: absorb -> permute -> squeeze
            let sponge = PoseidonKimchiSponge::<Fp>::new(kimchi_params());
            let state = [Fp::zero(), Fp::zero(), Fp::zero()];
            let state = sponge.absorb_witness(&state, [v1, v2]);
            let state = sponge.permute_witness(&state);
            let our_output = sponge.squeeze_witness(&state);

            // Reference: mina_poseidon ArithmeticSponge
            let mut ref_sponge =
                ArithmeticSponge::<Fp, PlonkSpongeConstantsKimchi, KIMCHI_FULL_ROUNDS>::new(
                    kimchi_params(),
                );
            ref_sponge.absorb(&[v1, v2]);
            let ref_output = ref_sponge.squeeze();

            assert_eq!(
                our_output, ref_output,
                "Full sponge cycle should match mina_poseidon ArithmeticSponge"
            );
        }
    }

    #[test]
    fn test_poseidon_kimchi_sponge_permutation_rows() {
        use crate::circuits::hash::{PoseidonKimchiSponge, Sponge};

        let sponge = PoseidonKimchiSponge::<Fp>::new(kimchi_params());

        assert_eq!(
            sponge.permutation_rows(),
            KIMCHI_ROWS_FOR_PERMUTATION,
            "Sponge permutation_rows should return 11"
        );
    }

    #[test]
    fn test_poseidon_kimchi_sponge_absorb_constraints() {
        use crate::circuits::hash::{PoseidonKimchiSponge, Sponge, POSEIDON_STATE_SIZE};

        let sponge = PoseidonKimchiSponge::<Fp>::new(kimchi_params());

        let mut env = ConstraintEnv::<Fp>::new();
        let state = env.make_input_vars::<POSEIDON_STATE_SIZE>();
        let values = [env.make_input_vars::<1>()[0].clone(), env.make_input_vars::<1>()[0].clone()];

        let _ = sponge.absorb(&mut env, &state, values);

        // Absorb creates 2 constraints (one for each rate element)
        assert_eq!(
            env.num_constraints(),
            2,
            "Sponge absorb should have 2 constraints"
        );

        // Both constraints should have degree 1 (linear additions)
        let degrees = env.constraint_degrees();
        assert!(
            degrees.iter().all(|&d| d <= 1),
            "Absorb constraints should all have degree <= 1"
        );
    }

    #[test]
    fn test_poseidon_kimchi_sponge_permute_constraints() {
        use crate::circuits::hash::{PoseidonKimchiSponge, Sponge, POSEIDON_STATE_SIZE};

        let sponge = PoseidonKimchiSponge::<Fp>::new(kimchi_params());

        let mut env = ConstraintEnv::<Fp>::new();
        let state = env.make_input_vars::<POSEIDON_STATE_SIZE>();

        let _ = sponge.permute(&mut env, &state);

        // 11 rows * 60 constraints per row (5 rounds * 12 constraints) = 660 constraints
        let expected_constraints = KIMCHI_ROWS_FOR_PERMUTATION * KIMCHI_ROUNDS_PER_ROW * 12;
        assert_eq!(
            env.num_constraints(),
            expected_constraints,
            "Sponge permute should have {} constraints",
            expected_constraints
        );

        // Max degree should be 3 (from decomposed S-box: w4 * w2 * x)
        assert_eq!(env.max_degree(), 3, "Permute max degree should be 3");
    }

    #[test]
    fn test_poseidon_kimchi_sponge_multi_absorb() {
        use ark_ff::Zero;
        use crate::circuits::hash::{PoseidonKimchiSponge, Sponge};
        use mina_poseidon::poseidon::{ArithmeticSponge, Sponge as MinaSponge};
        use rand::{Rng, SeedableRng};

        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        // Test absorbing multiple pairs of values
        let v1 = Fp::from(rng.gen::<u64>());
        let v2 = Fp::from(rng.gen::<u64>());
        let v3 = Fp::from(rng.gen::<u64>());
        let v4 = Fp::from(rng.gen::<u64>());

        // Our sponge: absorb [v1, v2] -> permute -> absorb [v3, v4] -> permute -> squeeze
        let sponge = PoseidonKimchiSponge::<Fp>::new(kimchi_params());
        let state = [Fp::zero(), Fp::zero(), Fp::zero()];
        let state = sponge.absorb_witness(&state, [v1, v2]);
        let state = sponge.permute_witness(&state);
        let state = sponge.absorb_witness(&state, [v3, v4]);
        let state = sponge.permute_witness(&state);
        let our_output = sponge.squeeze_witness(&state);

        // Reference: mina_poseidon ArithmeticSponge
        let mut ref_sponge =
            ArithmeticSponge::<Fp, PlonkSpongeConstantsKimchi, KIMCHI_FULL_ROUNDS>::new(kimchi_params());
        ref_sponge.absorb(&[v1, v2]);
        ref_sponge.absorb(&[v3, v4]);
        let ref_output = ref_sponge.squeeze();

        assert_eq!(
            our_output, ref_output,
            "Multi-absorb sponge should match mina_poseidon"
        );
    }
}

// ============================================================================
// Fq field tests (scalar field - the larger field for native circuit operation)
// ============================================================================

#[cfg(test)]
mod tests_fq {
    use super::*;
    use crate::circuit::ConstraintEnv;
    use mina_curves::pasta::Fq;
    use mina_poseidon::{
        constants::PlonkSpongeConstantsKimchi,
        pasta::fq_kimchi,
        permutation::poseidon_block_cipher,
    };

    fn kimchi_params_fq() -> &'static ArithmeticSpongeParams<Fq, KIMCHI_FULL_ROUNDS> {
        fq_kimchi::static_params()
    }

    // ========================================================================
    // Output tests (synthesize/output correctness)
    // ========================================================================

    #[test]
    fn test_poseidon_kimchi_round_output_fq() {
        let circuit = PoseidonKimchiRoundCircuit::<Fq>::new(0, kimchi_params_fq());
        let z = [Fq::from(1u64), Fq::from(2u64), Fq::from(3u64)];

        let output = circuit.output(&z);
        assert_ne!(output, z);
    }

    #[test]
    fn test_poseidon_kimchi_round_deterministic_fq() {
        let circuit = PoseidonKimchiRoundCircuit::<Fq>::new(0, kimchi_params_fq());
        let z = [Fq::from(1u64), Fq::from(2u64), Fq::from(3u64)];

        let output1 = circuit.output(&z);
        let output2 = circuit.output(&z);

        assert_eq!(output1, output2, "Same inputs should give same outputs");
    }

    #[test]
    fn test_poseidon_kimchi_permutation_matches_mina_fq() {
        let circuit = PoseidonKimchiPermutationCircuit::<Fq>::new(kimchi_params_fq());
        let z = [Fq::from(0u64), Fq::from(0u64), Fq::from(0u64)];

        let our_output = circuit.output(&z);

        let mut mina_state = z;
        poseidon_block_cipher::<Fq, PlonkSpongeConstantsKimchi, KIMCHI_FULL_ROUNDS>(
            kimchi_params_fq(),
            &mut mina_state,
        );

        assert_eq!(
            our_output, mina_state,
            "Our Poseidon Kimchi permutation (Fq) should match mina_poseidon with x^7 S-box"
        );
    }

    // ========================================================================
    // Constraint tests (degree checking)
    // ========================================================================

    #[test]
    fn test_poseidon_kimchi_round_constraints_fq() {
        for step in 0..11 {
            let starting_round = step * KIMCHI_ROUNDS_PER_ROW;
            let circuit = PoseidonKimchiRoundCircuit::<Fq>::new(starting_round, kimchi_params_fq());

            let mut env = ConstraintEnv::<Fq>::new();
            let z = env.make_input_vars::<3>();
            let _ = circuit.synthesize(&mut env, &z);

            let expected_witnesses = KIMCHI_ROUNDS_PER_ROW * 9 + (KIMCHI_ROUNDS_PER_ROW - 1) * 3;
            assert_eq!(
                env.num_witness_allocations(),
                expected_witnesses,
                "Fq: PoseidonKimchiRoundCircuit starting at round {} should have {} witness allocations",
                starting_round,
                expected_witnesses
            );

            let expected_constraints = KIMCHI_ROUNDS_PER_ROW * 12;
            assert_eq!(
                env.num_constraints(),
                expected_constraints,
                "Fq: PoseidonKimchiRoundCircuit starting at round {} should have {} constraints",
                starting_round,
                expected_constraints
            );

            assert_eq!(
                env.max_degree(),
                3,
                "Max degree should be 3 for starting round {}",
                starting_round
            );

            env.check_degrees()
                .expect("All constraints should have degree <= 5");
        }
    }

    #[test]
    fn test_poseidon_kimchi_chain_matches_mina_fq() {
        use rand::{Rng, SeedableRng};

        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        for _ in 0..10 {
            let z = [
                Fq::from(rng.gen::<u64>()),
                Fq::from(rng.gen::<u64>()),
                Fq::from(rng.gen::<u64>()),
            ];

            let mut our_state = z;
            for step in 0..KIMCHI_ROWS_FOR_PERMUTATION {
                let circuit = PoseidonKimchiRoundCircuit::<Fq>::new(
                    step * KIMCHI_ROUNDS_PER_ROW,
                    kimchi_params_fq(),
                );
                our_state = circuit.output(&our_state);
            }

            let mut ref_state = z;
            poseidon_block_cipher::<Fq, PlonkSpongeConstantsKimchi, KIMCHI_FULL_ROUNDS>(
                kimchi_params_fq(),
                &mut ref_state,
            );

            assert_eq!(
                our_state, ref_state,
                "Fq: Chained PoseidonKimchiRoundCircuit should match mina_poseidon block cipher"
            );
        }
    }

    // ========================================================================
    // Sponge tests (PoseidonKimchiSponge trait implementation)
    // ========================================================================

    #[test]
    fn test_poseidon_kimchi_sponge_absorb_fq() {
        use crate::circuits::hash::{PoseidonKimchiSponge, Sponge};

        let sponge = PoseidonKimchiSponge::<Fq>::new(kimchi_params_fq());
        let state = [Fq::from(1u64), Fq::from(2u64), Fq::from(3u64)];
        let values = [Fq::from(10u64), Fq::from(20u64)];

        let output = sponge.absorb_witness(&state, values);

        assert_eq!(output[0], state[0] + values[0], "First rate element mismatch");
        assert_eq!(output[1], state[1] + values[1], "Second rate element mismatch");
        assert_eq!(output[2], state[2], "Capacity should be unchanged");
    }

    #[test]
    fn test_poseidon_kimchi_sponge_permute_matches_mina_fq() {
        use crate::circuits::hash::{PoseidonKimchiSponge, Sponge};
        use rand::{Rng, SeedableRng};

        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let sponge = PoseidonKimchiSponge::<Fq>::new(kimchi_params_fq());

        for _ in 0..10 {
            let state = [
                Fq::from(rng.gen::<u64>()),
                Fq::from(rng.gen::<u64>()),
                Fq::from(rng.gen::<u64>()),
            ];

            let our_output = sponge.permute_witness(&state);

            let mut ref_state = state;
            poseidon_block_cipher::<Fq, PlonkSpongeConstantsKimchi, KIMCHI_FULL_ROUNDS>(
                kimchi_params_fq(),
                &mut ref_state,
            );

            assert_eq!(
                our_output, ref_state,
                "Fq: Sponge permute_witness should match mina_poseidon"
            );
        }
    }

    #[test]
    fn test_poseidon_kimchi_sponge_full_cycle_fq() {
        use ark_ff::Zero;
        use crate::circuits::hash::{PoseidonKimchiSponge, Sponge};
        use mina_poseidon::poseidon::{ArithmeticSponge, Sponge as MinaSponge};
        use rand::{Rng, SeedableRng};

        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        for _ in 0..10 {
            let v1 = Fq::from(rng.gen::<u64>());
            let v2 = Fq::from(rng.gen::<u64>());

            let sponge = PoseidonKimchiSponge::<Fq>::new(kimchi_params_fq());
            let state = [Fq::zero(), Fq::zero(), Fq::zero()];
            let state = sponge.absorb_witness(&state, [v1, v2]);
            let state = sponge.permute_witness(&state);
            let our_output = sponge.squeeze_witness(&state);

            let mut ref_sponge =
                ArithmeticSponge::<Fq, PlonkSpongeConstantsKimchi, KIMCHI_FULL_ROUNDS>::new(
                    kimchi_params_fq(),
                );
            ref_sponge.absorb(&[v1, v2]);
            let ref_output = ref_sponge.squeeze();

            assert_eq!(
                our_output, ref_output,
                "Fq: Full sponge cycle should match mina_poseidon ArithmeticSponge"
            );
        }
    }

    #[test]
    fn test_poseidon_kimchi_sponge_multi_absorb_fq() {
        use ark_ff::Zero;
        use crate::circuits::hash::{PoseidonKimchiSponge, Sponge};
        use mina_poseidon::poseidon::{ArithmeticSponge, Sponge as MinaSponge};
        use rand::{Rng, SeedableRng};

        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        let v1 = Fq::from(rng.gen::<u64>());
        let v2 = Fq::from(rng.gen::<u64>());
        let v3 = Fq::from(rng.gen::<u64>());
        let v4 = Fq::from(rng.gen::<u64>());

        let sponge = PoseidonKimchiSponge::<Fq>::new(kimchi_params_fq());
        let state = [Fq::zero(), Fq::zero(), Fq::zero()];
        let state = sponge.absorb_witness(&state, [v1, v2]);
        let state = sponge.permute_witness(&state);
        let state = sponge.absorb_witness(&state, [v3, v4]);
        let state = sponge.permute_witness(&state);
        let our_output = sponge.squeeze_witness(&state);

        let mut ref_sponge =
            ArithmeticSponge::<Fq, PlonkSpongeConstantsKimchi, KIMCHI_FULL_ROUNDS>::new(kimchi_params_fq());
        ref_sponge.absorb(&[v1, v2]);
        ref_sponge.absorb(&[v3, v4]);
        let ref_output = ref_sponge.squeeze();

        assert_eq!(
            our_output, ref_output,
            "Fq: Multi-absorb sponge should match mina_poseidon"
        );
    }
}

// ============================================================================
// Trace tests (Fp)
// ============================================================================

#[cfg(test)]
mod trace_tests {
    use super::*;
    use crate::circuit::{ConstraintEnv, StepCircuit, Trace};
    use crate::circuits::hash::{PoseidonKimchiSponge, Sponge};
    use ark_ff::Zero;
    use mina_curves::pasta::Fp;
    use mina_poseidon::{
        constants::SpongeConstants,
        pasta::fp_kimchi,
        permutation::poseidon_block_cipher,
        poseidon::{ArithmeticSponge, Sponge as MinaSponge},
    };
    use rand::{Rng, SeedableRng};

    // Kimchi sponge constants for testing
    #[derive(Clone)]
    pub struct PlonkSpongeConstantsKimchi;

    impl SpongeConstants for PlonkSpongeConstantsKimchi {
        const SPONGE_CAPACITY: usize = 1;
        const SPONGE_WIDTH: usize = 3;
        const SPONGE_RATE: usize = 2;
        const PERM_ROUNDS_FULL: usize = 55;
        const PERM_ROUNDS_PARTIAL: usize = 0;
        const PERM_HALF_ROUNDS_FULL: usize = 0;
        const PERM_SBOX: u32 = 7;
        const PERM_FULL_MDS: bool = true;
        const PERM_INITIAL_ARK: bool = false;
    }

    fn kimchi_params() -> &'static ArithmeticSpongeParams<Fp, KIMCHI_FULL_ROUNDS> {
        fp_kimchi::static_params()
    }

    #[test]
    fn test_poseidon_kimchi_round_output_correctness() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        // Test all 11 possible starting rounds with random inputs
        for step in 0..KIMCHI_ROWS_FOR_PERMUTATION {
            let starting_round = step * KIMCHI_ROUNDS_PER_ROW;
            let circuit = PoseidonKimchiRoundCircuit::<Fp>::new(starting_round, kimchi_params());

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

    #[test]
    fn test_poseidon_kimchi_permutation_output_correctness() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let circuit = PoseidonKimchiPermutationCircuit::<Fp>::new(kimchi_params());

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
    fn test_poseidon_kimchi_round_last_output_on_next_row() {
        // Verify that the last round's output uses next_row allocation
        let circuit = PoseidonKimchiRoundCircuit::<Fp>::new(0, kimchi_params());

        let mut env = ConstraintEnv::<Fp>::new();
        let z = env.make_input_vars::<3>();
        let output = circuit.synthesize(&mut env, &z);

        // The output variables should reference the next row
        let output_str = format!("{:?}", output);
        assert!(
            output_str.contains("Next"),
            "Output should reference next row, got: {}",
            output_str
        );
    }

    #[test]
    fn test_poseidon_kimchi_permutation_random_inputs_match_mina() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let circuit = PoseidonKimchiPermutationCircuit::<Fp>::new(kimchi_params());

        for _ in 0..20 {
            let z = [
                Fp::from(rng.gen::<u64>()),
                Fp::from(rng.gen::<u64>()),
                Fp::from(rng.gen::<u64>()),
            ];

            // Our implementation
            let our_output = circuit.output(&z);

            // Reference: mina_poseidon
            let mut ref_state = z;
            poseidon_block_cipher::<Fp, PlonkSpongeConstantsKimchi, KIMCHI_FULL_ROUNDS>(
                kimchi_params(),
                &mut ref_state,
            );

            assert_eq!(
                our_output, ref_state,
                "Random input permutation should match mina_poseidon"
            );
        }
    }

    #[test]
    fn test_poseidon_kimchi_sponge_trace_absorb() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        for _ in 0..10 {
            let v1 = Fp::from(rng.gen::<u64>());
            let v2 = Fp::from(rng.gen::<u64>());

            let s0 = Fp::from(rng.gen::<u64>());
            let s1 = Fp::from(rng.gen::<u64>());
            let s2 = Fp::from(rng.gen::<u64>());

            let sponge = PoseidonKimchiSponge::<Fp>::new(kimchi_params());

            let mut env = Trace::<Fp>::new(16);
            let state = env.make_input_vars([s0, s1, s2]);
            let values = [env.make_input_vars([v1])[0].clone(), env.make_input_vars([v2])[0].clone()];

            let output = sponge.absorb(&mut env, &state, values);

            // Verify output matches expected
            let expected = sponge.absorb_witness(&[s0, s1, s2], [v1, v2]);
            assert_eq!(output[0], expected[0], "First rate element mismatch");
            assert_eq!(output[1], expected[1], "Second rate element mismatch");
            assert_eq!(output[2], expected[2], "Capacity should be unchanged");
        }
    }

    #[test]
    fn test_poseidon_kimchi_sponge_witness_matches_circuit() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let sponge = PoseidonKimchiSponge::<Fp>::new(kimchi_params());

        for _ in 0..10 {
            let state = [
                Fp::from(rng.gen::<u64>()),
                Fp::from(rng.gen::<u64>()),
                Fp::from(rng.gen::<u64>()),
            ];
            let values = [Fp::from(rng.gen::<u64>()), Fp::from(rng.gen::<u64>())];

            // Test absorb: witness should match constraint output
            let absorb_witness = sponge.absorb_witness(&state, values);

            let mut env = Trace::<Fp>::new(16);
            let state_vars = env.make_input_vars(state);
            let value_vars = [
                env.make_input_vars([values[0]])[0].clone(),
                env.make_input_vars([values[1]])[0].clone(),
            ];
            let absorb_circuit = sponge.absorb(&mut env, &state_vars, value_vars);

            assert_eq!(
                absorb_circuit,
                absorb_witness,
                "Absorb witness should match circuit output"
            );

            // Test permute: witness should match circuit output
            let permute_witness = sponge.permute_witness(&state);

            // Verify permute_witness matches the circuit's output()
            let circuit = PoseidonKimchiPermutationCircuit::<Fp>::new(kimchi_params());
            let circuit_output = circuit.output(&state);
            assert_eq!(
                permute_witness, circuit_output,
                "Permute witness should match circuit output()"
            );
        }
    }

    #[test]
    fn test_poseidon_kimchi_known_test_vector() {
        // Test with a known test vector to ensure consistency
        let circuit = PoseidonKimchiPermutationCircuit::<Fp>::new(kimchi_params());

        // Zero input test vector
        let zero_input = [Fp::from(0u64), Fp::from(0u64), Fp::from(0u64)];
        let zero_output = circuit.output(&zero_input);

        // Reference output from mina_poseidon
        let mut ref_state = zero_input;
        poseidon_block_cipher::<Fp, PlonkSpongeConstantsKimchi, KIMCHI_FULL_ROUNDS>(
            kimchi_params(),
            &mut ref_state,
        );

        assert_eq!(
            zero_output, ref_state,
            "Zero input test vector should match mina_poseidon"
        );

        // Small values test vector
        let small_input = [Fp::from(1u64), Fp::from(2u64), Fp::from(3u64)];
        let small_output = circuit.output(&small_input);

        let mut ref_state2 = small_input;
        poseidon_block_cipher::<Fp, PlonkSpongeConstantsKimchi, KIMCHI_FULL_ROUNDS>(
            kimchi_params(),
            &mut ref_state2,
        );

        assert_eq!(
            small_output, ref_state2,
            "Small values test vector should match mina_poseidon"
        );
    }

    #[test]
    fn test_poseidon_kimchi_sponge_hash_matches_mina() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        // Test hashing various numbers of field elements
        for num_elements in 1..=8 {
            let elements: Vec<Fp> = (0..num_elements)
                .map(|_| Fp::from(rng.gen::<u64>()))
                .collect();

            // Our sponge: absorb all elements (2 at a time), then squeeze
            let sponge = PoseidonKimchiSponge::<Fp>::new(kimchi_params());
            let mut state = [Fp::zero(), Fp::zero(), Fp::zero()];

            // Absorb elements 2 at a time (rate = 2)
            for chunk in elements.chunks(2) {
                let v1 = chunk[0];
                let v2 = if chunk.len() > 1 { chunk[1] } else { Fp::zero() };
                state = sponge.absorb_witness(&state, [v1, v2]);
                state = sponge.permute_witness(&state);
            }
            let our_output = sponge.squeeze_witness(&state);

            // Reference: mina_poseidon ArithmeticSponge
            let mut ref_sponge = ArithmeticSponge::<Fp, PlonkSpongeConstantsKimchi, KIMCHI_FULL_ROUNDS>::new(
                kimchi_params(),
            );
            // ArithmeticSponge absorbs and permutes internally
            for chunk in elements.chunks(2) {
                let v1 = chunk[0];
                let v2 = if chunk.len() > 1 { chunk[1] } else { Fp::zero() };
                ref_sponge.absorb(&[v1, v2]);
            }
            let ref_output = ref_sponge.squeeze();

            assert_eq!(
                our_output, ref_output,
                "Hashing {} elements should match mina_poseidon",
                num_elements
            );
        }
    }
}
