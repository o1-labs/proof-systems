pub mod columns;
pub mod interpreter;
/// Parameters for the Poseidon sponge.
// FIXME: move it into the crate mina_poseidon
pub mod params;

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::params;
    use crate::poseidon::{columns::PoseidonColumn, interpreter, interpreter::Params};
    use ark_ff::UniformRand;
    use kimchi::circuits::domains::EvaluationDomains;
    use kimchi_msm::{
        circuit_design::{ConstraintBuilderEnv, WitnessBuilderEnv},
        columns::{Column, ColumnIndexer},
        lookups::DummyLookupTable,
        prover::prove,
        verifier::verify,
        witness::Witness,
        BaseSponge, Fp, OpeningProof, ScalarSponge, BN254,
    };
    use poly_commitment::pairing_proof::PairingSRS;

    pub struct PoseidonBN254Parameters;

    pub const STATE_SIZE: usize = 3;
    pub const NB_FULL_ROUND: usize = 55;
    pub const N_COL: usize = STATE_SIZE + NB_FULL_ROUND * STATE_SIZE;

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
    pub fn test_completeness() {
        let mut rng = o1_utils::tests::make_test_rng();
        let domain_size = 1 << 15;
        let domain = EvaluationDomains::<Fp>::create(domain_size).unwrap();

        let srs_trapdoor = Fp::rand(&mut rng);
        let mut srs: PairingSRS<BN254> = PairingSRS::create(srs_trapdoor, domain.d1.size as usize);
        srs.full_srs.add_lagrange_basis(domain.d1);

        let mut witness_env: WitnessBuilderEnv<Fp, N_COL, DummyLookupTable> =
            WitnessBuilderEnv::create();

        // Generate random inputs at each row
        for _row in 0..domain.d1.size {
            let x: Fp = Fp::rand(&mut rng);
            let y: Fp = Fp::rand(&mut rng);
            let z: Fp = Fp::rand(&mut rng);
            let input_x: PoseidonColumn<STATE_SIZE, NB_FULL_ROUND> = PoseidonColumn::Input(0);
            let input_y: PoseidonColumn<STATE_SIZE, NB_FULL_ROUND> = PoseidonColumn::Input(1);
            let input_z: PoseidonColumn<STATE_SIZE, NB_FULL_ROUND> = PoseidonColumn::Input(2);

            witness_env.write_column(input_x.to_column(), x);
            witness_env.write_column(input_y.to_column(), y);
            witness_env.write_column(input_z.to_column(), z);

            interpreter::apply_permutation(&mut witness_env, PoseidonBN254Parameters);

            // TODO: add a check on the output, using read_column, and a
            // concrete implementation of Poseidon
        }

        let empty_lookups = BTreeMap::new();
        let proof_inputs = witness_env.get_proof_inputs(domain, empty_lookups);

        let constraints = {
            let mut constraint_env = ConstraintBuilderEnv::<Fp, DummyLookupTable>::create();
            interpreter::apply_permutation(&mut constraint_env, PoseidonBN254Parameters);
            constraint_env.get_constraints()
        };

        // Constraints properties check. For this test, we do have 165 constraints
        assert_eq!(constraints.len(), STATE_SIZE * NB_FULL_ROUND);
        // Maximum degree of the constraints
        assert_eq!(constraints.iter().map(|c| c.degree(1, 0)).max().unwrap(), 7);
        // We only have degree 7 constraints
        constraints
            .iter()
            .map(|c| c.degree(1, 0))
            .for_each(|d| assert_eq!(d, 7));

        // generate the proof
        let proof = prove::<_, OpeningProof, BaseSponge, ScalarSponge, Column, _, N_COL, _>(
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
