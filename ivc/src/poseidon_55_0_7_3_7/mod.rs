pub mod columns;
pub mod interpreter;

#[cfg(test)]
mod tests {
    use crate::{
        poseidon_55_0_7_3_7::{columns::PoseidonColumn, interpreter, interpreter::PoseidonParams},
        poseidon_params_55_0_7_3,
        poseidon_params_55_0_7_3::PlonkSpongeConstantsIVC,
    };
    use ark_ff::{UniformRand, Zero};
    use kimchi_msm::{
        circuit_design::{ColAccessCap, ConstraintBuilderEnv, WitnessBuilderEnv},
        columns::ColumnIndexer,
        lookups::DummyLookupTable,
        Fp,
    };
    use mina_poseidon::permutation::poseidon_block_cipher;

    pub struct PoseidonBN254Parameters;

    pub const STATE_SIZE: usize = 3;
    pub const NB_FULL_ROUND: usize = 55;
    type TestPoseidonColumn = PoseidonColumn<STATE_SIZE, NB_FULL_ROUND>;
    pub const N_COL: usize = TestPoseidonColumn::N_COL;
    pub const N_DSEL: usize = 0;
    pub const N_FSEL: usize = 165;

    impl PoseidonParams<Fp, STATE_SIZE, NB_FULL_ROUND> for PoseidonBN254Parameters {
        fn constants(&self) -> [[Fp; STATE_SIZE]; NB_FULL_ROUND] {
            let rc = &poseidon_params_55_0_7_3::static_params().round_constants;
            core::array::from_fn(|i| core::array::from_fn(|j| Fp::from(rc[i][j])))
        }

        fn mds(&self) -> [[Fp; STATE_SIZE]; STATE_SIZE] {
            let mds = &poseidon_params_55_0_7_3::static_params().mds;
            core::array::from_fn(|i| core::array::from_fn(|j| Fp::from(mds[i][j])))
        }
    }

    type PoseidonWitnessBuilderEnv = WitnessBuilderEnv<
        Fp,
        TestPoseidonColumn,
        { <TestPoseidonColumn as ColumnIndexer<usize>>::N_COL },
        { <TestPoseidonColumn as ColumnIndexer<usize>>::N_COL },
        N_DSEL,
        N_FSEL,
        DummyLookupTable,
    >;

    #[test]
    /// Tests that poseidon circuit is correctly formed (witness
    /// generation + constraints match) and matches the CPU
    /// specification of Poseidon. Fast to run, can be used for
    /// debugging.
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
                        poseidon_params_55_0_7_3::static_params(),
                        &mut state,
                    );
                    state
                };
                let x_col: PoseidonColumn<STATE_SIZE, NB_FULL_ROUND> =
                    PoseidonColumn::Round(NB_FULL_ROUND - 1, 0);
                let y_col: PoseidonColumn<STATE_SIZE, NB_FULL_ROUND> =
                    PoseidonColumn::Round(NB_FULL_ROUND - 1, 1);
                let z_col: PoseidonColumn<STATE_SIZE, NB_FULL_ROUND> =
                    PoseidonColumn::Round(NB_FULL_ROUND - 1, 2);
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
        let domain_size: usize = 1 << 4;

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
            interpreter::apply_permutation(&mut constraint_env, &PoseidonBN254Parameters);
            let constraints = constraint_env.get_constraints();

            // Constraints properties check. For this test, we do have 165 constraints
            assert_eq!(constraints.len(), STATE_SIZE * NB_FULL_ROUND);
            // Maximum degree of the constraints
            assert_eq!(constraints.iter().map(|c| c.degree(1, 0)).max().unwrap(), 7);
            // We only have degree 7 constraints
            constraints
                .iter()
                .map(|c| c.degree(1, 0))
                .for_each(|d| assert_eq!(d, 7));

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
