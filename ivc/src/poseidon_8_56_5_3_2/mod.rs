//! Specialised circuit for Poseidon where we have maximum degree 2 constraints.

pub mod columns;
pub mod interpreter;

pub mod bn254;

#[cfg(test)]
mod tests {
    use crate::poseidon_8_56_5_3_2::{
        bn254::{
            static_params, Column, PlonkSpongeConstantsIVC, PoseidonBN254Parameters, MAX_DEGREE,
            NB_CONSTRAINTS, NB_FULL_ROUND, NB_PARTIAL_ROUND, NB_TOTAL_ROUND, STATE_SIZE,
        },
        columns::PoseidonColumn,
        interpreter,
        interpreter::PoseidonParams,
    };
    use ark_ff::{UniformRand, Zero};
    use kimchi_msm::{
        circuit_design::{ColAccessCap, ConstraintBuilderEnv, WitnessBuilderEnv},
        columns::ColumnIndexer,
        lookups::DummyLookupTable,
        Fp,
    };
    use mina_poseidon::permutation::poseidon_block_cipher;

    pub const N_COL: usize = Column::N_COL;
    pub const N_DSEL: usize = 0;
    pub const N_FSEL: usize = NB_TOTAL_ROUND * STATE_SIZE;

    type PoseidonWitnessBuilderEnv = WitnessBuilderEnv<
        Fp,
        Column,
        { <Column as ColumnIndexer<usize>>::N_COL },
        { <Column as ColumnIndexer<usize>>::N_COL },
        N_DSEL,
        N_FSEL,
        DummyLookupTable,
    >;

    /// Tests that poseidon circuit is correctly formed (witness
    /// generation + constraints match) and matches the CPU
    /// specification of Poseidon. Fast to run, can be used for
    /// debugging.
    #[test]
    pub fn test_poseidon_circuit() {
        let mut rng = o1_utils::tests::make_test_rng(None);
        let domain_size = 1 << 4;

        let mut witness_env: PoseidonWitnessBuilderEnv = WitnessBuilderEnv::create();
        // Write constants
        {
            let rc = PoseidonBN254Parameters.constants();
            rc.iter().enumerate().for_each(|(round, rcs)| {
                rcs.iter().enumerate().for_each(|(state_index, rc)| {
                    let rc = vec![*rc; domain_size];
                    witness_env.set_fixed_selector_cix(
                        PoseidonColumn::RoundConstant(round, state_index),
                        rc,
                    )
                });
            });
        }

        // Generate random inputs at each row
        for _row in 0..domain_size {
            let x: Fp = Fp::rand(&mut rng);
            let y: Fp = Fp::rand(&mut rng);
            let z: Fp = Fp::rand(&mut rng);

            interpreter::poseidon_circuit(&mut witness_env, &PoseidonBN254Parameters, [x, y, z]);

            // Check internal consistency of our circuit: that our
            // computed values match the CPU-spec implementation of
            // Poseidon.
            {
                let exp_output: Vec<Fp> = {
                    let mut state: Vec<Fp> = vec![x, y, z];
                    poseidon_block_cipher::<Fp, PlonkSpongeConstantsIVC>(
                        static_params(),
                        &mut state,
                    );
                    state
                };
                let x_col: PoseidonColumn<STATE_SIZE, NB_FULL_ROUND, NB_PARTIAL_ROUND> =
                    PoseidonColumn::FullRound(NB_FULL_ROUND - 1, 3);
                let y_col: PoseidonColumn<STATE_SIZE, NB_FULL_ROUND, NB_PARTIAL_ROUND> =
                    PoseidonColumn::FullRound(NB_FULL_ROUND - 1, 7);
                let z_col: PoseidonColumn<STATE_SIZE, NB_FULL_ROUND, NB_PARTIAL_ROUND> =
                    PoseidonColumn::FullRound(NB_FULL_ROUND - 1, 11);
                assert_eq!(witness_env.read_column(x_col), exp_output[0]);
                assert_eq!(witness_env.read_column(y_col), exp_output[1]);
                assert_eq!(witness_env.read_column(z_col), exp_output[2]);
            }

            witness_env.next_row();
        }
    }

    #[test]
    /// Checks that poseidon circuit can be proven and verified. Big domain.
    pub fn heavy_test_completeness() {
        let mut rng = o1_utils::tests::make_test_rng(None);
        let domain_size: usize = 1 << 15;

        let (relation_witness, fixed_selectors) = {
            let mut witness_env: PoseidonWitnessBuilderEnv = WitnessBuilderEnv::create();

            let mut fixed_selectors: [Vec<Fp>; N_FSEL] =
                core::array::from_fn(|_| vec![Fp::zero(); 1]);
            // Write constants
            {
                let rc = PoseidonBN254Parameters.constants();
                rc.iter().enumerate().for_each(|(round, rcs)| {
                    rcs.iter().enumerate().for_each(|(state_index, rc)| {
                        witness_env.set_fixed_selector_cix(
                            PoseidonColumn::RoundConstant(round, state_index),
                            vec![*rc; domain_size],
                        );
                        fixed_selectors[round * STATE_SIZE + state_index] = vec![*rc; domain_size];
                    });
                });
            }

            // Generate random inputs at each row
            for _row in 0..domain_size {
                let x: Fp = Fp::rand(&mut rng);
                let y: Fp = Fp::rand(&mut rng);
                let z: Fp = Fp::rand(&mut rng);

                interpreter::poseidon_circuit(
                    &mut witness_env,
                    &PoseidonBN254Parameters,
                    [x, y, z],
                );

                witness_env.next_row();
            }

            (
                witness_env.get_relation_witness(domain_size),
                fixed_selectors,
            )
        };

        let constraints = {
            let mut constraint_env = ConstraintBuilderEnv::<Fp, DummyLookupTable>::create();
            interpreter::apply_permutation::<
                Fp,
                3,
                NB_FULL_ROUND,
                NB_PARTIAL_ROUND,
                NB_TOTAL_ROUND,
                _,
                _,
            >(&mut constraint_env, &PoseidonBN254Parameters);
            let constraints = constraint_env.get_constraints();

            // We have 432 constraints in total if state size = 3, nb full
            // rounds = 8, nb partial rounds = 56
            assert_eq!(
                constraints.len(),
                4 * STATE_SIZE * NB_FULL_ROUND + (4 + STATE_SIZE - 1) * NB_PARTIAL_ROUND
            );
            assert_eq!(constraints.len(), NB_CONSTRAINTS);

            // Maximum degree of the constraints is 2
            assert_eq!(
                constraints.iter().map(|c| c.degree(1, 0)).max().unwrap(),
                MAX_DEGREE
            );

            constraints
        };

        kimchi_msm::test::test_completeness_generic_no_lookups::<N_COL, N_COL, N_DSEL, N_FSEL, _>(
            constraints,
            Box::new(fixed_selectors),
            relation_witness,
            domain_size,
            &mut rng,
        );
    }
}
