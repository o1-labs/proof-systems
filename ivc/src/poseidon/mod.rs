pub mod columns;
pub mod interpreter;
/// Parameters for the Poseidon sponge.
// FIXME: move it into the crate mina_poseidon
pub mod params;

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{params, params::PlonkSpongeConstantsIVC};
    use crate::poseidon::{columns::PoseidonColumn, interpreter, interpreter::Params};
    use ark_ff::UniformRand;
    use kimchi::circuits::domains::EvaluationDomains;
    use kimchi_msm::{
        circuit_design::{ColAccessCap, ConstraintBuilderEnv, WitnessBuilderEnv},
        columns::ColumnIndexer,
        lookups::DummyLookupTable,
        prover::prove,
        verifier::verify,
        witness::Witness,
        BaseSponge, Fp, OpeningProof, ScalarSponge, BN254,
    };
    use mina_poseidon::permutation::poseidon_block_cipher;
    use poly_commitment::pairing_proof::PairingSRS;

    pub struct PoseidonBN254Parameters;

    pub const STATE_SIZE: usize = 3;
    pub const NB_FULL_ROUND: usize = 55;
    pub const N_COL: usize = PoseidonColumn::<STATE_SIZE, NB_FULL_ROUND>::COL_N;

    impl Params<Fp, STATE_SIZE, NB_FULL_ROUND> for PoseidonBN254Parameters {
        fn constants(&self) -> [[Fp; STATE_SIZE]; NB_FULL_ROUND] {
            let rc = &params::static_params().round_constants;
            std::array::from_fn(|i| std::array::from_fn(|j| Fp::from(rc[i][j])))
        }

        fn mds(&self) -> [[Fp; STATE_SIZE]; STATE_SIZE] {
            let mds = &params::static_params().mds;
            std::array::from_fn(|i| std::array::from_fn(|j| Fp::from(mds[i][j])))
        }
    }

    #[test]
    /// Tests that poseidon circuit is correctly formed (witness
    /// generation + constraints match) and matches the CPU
    /// specification of Poseidon. Fast to run, can be used for
    /// debugging.
    pub fn test_poseidon_circuit() {
        let mut rng = o1_utils::tests::make_test_rng();
        let domain_size = 1 << 4;

        let mut witness_env: WitnessBuilderEnv<Fp, N_COL, DummyLookupTable> =
            WitnessBuilderEnv::create();

        // Generate random inputs at each row
        for _row in 0..domain_size {
            let x: Fp = Fp::rand(&mut rng);
            let y: Fp = Fp::rand(&mut rng);
            let z: Fp = Fp::rand(&mut rng);

            interpreter::poseidon_circuit(&mut witness_env, PoseidonBN254Parameters, (x, y, z));

            // Check internal consistency of our circuit: that our
            // computed values match the CPU-spec implementation of
            // Poseidon.
            {
                let exp_output: Vec<Fp> = {
                    let mut state: Vec<Fp> = vec![x, y, z];
                    poseidon_block_cipher::<Fp, PlonkSpongeConstantsIVC>(
                        params::static_params(),
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
        }
    }

    #[test]
    /// Checks that poseidon circuit can be proven and verified. Big domain.
    pub fn test_completeness() {
        let mut rng = o1_utils::tests::make_test_rng();
        let domain_size = 1 << 15;
        let domain = EvaluationDomains::<Fp>::create(domain_size).unwrap();

        let srs_trapdoor = Fp::rand(&mut rng);
        let mut srs: PairingSRS<BN254> = PairingSRS::create(srs_trapdoor, domain.d1.size as usize);
        srs.full_srs.add_lagrange_basis(domain.d1);

        let empty_lookups = BTreeMap::new();
        let proof_inputs = {
            let mut witness_env: WitnessBuilderEnv<Fp, N_COL, DummyLookupTable> =
                WitnessBuilderEnv::create();

            // Generate random inputs at each row
            for _row in 0..domain.d1.size {
                let x: Fp = Fp::rand(&mut rng);
                let y: Fp = Fp::rand(&mut rng);
                let z: Fp = Fp::rand(&mut rng);

                interpreter::poseidon_circuit(&mut witness_env, PoseidonBN254Parameters, (x, y, z));
            }

            witness_env.get_proof_inputs(domain, empty_lookups)
        };

        let constraints = {
            let mut constraint_env = ConstraintBuilderEnv::<Fp, DummyLookupTable>::create();
            interpreter::apply_permutation(&mut constraint_env, PoseidonBN254Parameters);
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

        // generate the proof
        let proof = prove::<_, OpeningProof, BaseSponge, ScalarSponge, _, N_COL, _>(
            domain,
            &srs,
            &constraints,
            proof_inputs,
            &mut rng,
        )
        .unwrap();

        // verify the proof
        let verifies = verify::<_, OpeningProof, BaseSponge, ScalarSponge, N_COL, 0, _>(
            domain,
            &srs,
            &constraints,
            &proof,
            Witness::zero_vec(domain_size),
        );

        assert!(verifies);
    }
}
