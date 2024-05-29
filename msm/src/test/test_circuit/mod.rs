pub mod columns;
pub mod interpreter;

#[cfg(test)]
mod tests {
    use crate::{
        circuit_design::{ConstraintBuilderEnv, WitnessBuilderEnv},
        columns::ColumnIndexer,
        logup::LookupTableID,
        lookups::DummyLookupTable,
        precomputed_srs::get_bn254_srs,
        prover::prove,
        test::test_circuit::{
            columns::{TestColumn, TEST_N_COLUMNS},
            interpreter::{self as test_interpreter},
        },
        verifier::verify,
        witness::Witness,
        BaseSponge, Ff1, Fp, OpeningProof, ScalarSponge, BN254,
    };
    use ark_ff::UniformRand;
    use kimchi::circuits::domains::EvaluationDomains;
    use poly_commitment::pairing_proof::PairingSRS;
    use rand::{CryptoRng, Rng, RngCore};
    use std::collections::BTreeMap;

    type TestWitnessBuilderEnv<LT> = WitnessBuilderEnv<
        Fp,
        TestColumn,
        { <TestColumn as ColumnIndexer>::N_COL - 1 },
        { <TestColumn as ColumnIndexer>::N_COL - 1 },
        0,
        1,
        LT,
    >;

    fn build_test_fixed_sel_circuit<RNG: RngCore + CryptoRng, LT: LookupTableID>(
        rng: &mut RNG,
        domain_size: usize,
    ) -> TestWitnessBuilderEnv<LT> {
        let mut witness_env = WitnessBuilderEnv::create();

        let fixed_sel: Vec<Fp> = (0..domain_size).map(|i| Fp::from(i as u64)).collect();
        witness_env.set_fixed_selector_cix(TestColumn::FixedE, fixed_sel);

        for row_i in 0..domain_size {
            let a: Fp = <Fp as UniformRand>::rand(rng);
            test_interpreter::test_fixed_sel(&mut witness_env, a);

            if row_i < domain_size - 1 {
                witness_env.next_row();
            }
        }

        witness_env
    }

    #[test]
    pub fn test_build_test_fixed_sel_circuit() {
        let mut rng = o1_utils::tests::make_test_rng();
        build_test_fixed_sel_circuit::<_, DummyLookupTable>(&mut rng, 1 << 4);
    }

    #[test]
    fn test_completeness_fixed_sel() {
        let mut rng = o1_utils::tests::make_test_rng();

        // Include tests for completeness for Logup as the random witness
        // includes all arguments
        let domain_size = 1 << 8;
        let domain = EvaluationDomains::<Fp>::create(domain_size).unwrap();

        let srs: PairingSRS<BN254> = get_bn254_srs(domain);

        let mut lookup_tables_data = BTreeMap::new();
        for table_id in DummyLookupTable::all_variants().into_iter() {
            lookup_tables_data.insert(table_id, table_id.entries(domain.d1.size));
        }
        let witness_env =
            build_test_fixed_sel_circuit::<_, DummyLookupTable>(&mut rng, domain_size);
        let mut proof_inputs = witness_env.get_proof_inputs(domain, lookup_tables_data);
        // Don't use lookups for now
        proof_inputs.logups = vec![];

        let mut constraint_env = ConstraintBuilderEnv::<Fp, DummyLookupTable>::create();
        test_interpreter::constrain_test_fixed_sel::<Fp, _>(&mut constraint_env);
        // Don't use lookups for now
        let constraints = constraint_env.get_relation_constraints();

        let fixed_selectors: Box<[Vec<Fp>; 1]> =
            Box::new([(0..domain_size).map(|i| Fp::from(i as u64)).collect()]);

        // generate the proof
        let proof = prove::<
            _,
            OpeningProof,
            BaseSponge,
            ScalarSponge,
            _,
            { TEST_N_COLUMNS - 1 },
            { TEST_N_COLUMNS - 1 },
            0,
            1,
            DummyLookupTable,
        >(
            domain,
            &srs,
            &constraints,
            fixed_selectors.clone(),
            proof_inputs,
            &mut rng,
        )
        .unwrap();

        // verify the proof
        let verifies = verify::<
            _,
            OpeningProof,
            BaseSponge,
            ScalarSponge,
            { TEST_N_COLUMNS - 1 },
            { TEST_N_COLUMNS - 1 },
            0,
            1,
            0,
            DummyLookupTable,
        >(
            domain,
            &srs,
            &constraints,
            fixed_selectors,
            &proof,
            Witness::zero_vec(domain_size),
        );

        assert!(verifies);
    }

    fn build_test_const_circuit<RNG: RngCore + CryptoRng, LT: LookupTableID>(
        rng: &mut RNG,
        domain_size: usize,
    ) -> (TestWitnessBuilderEnv<LT>, Fp) {
        let mut witness_env = WitnessBuilderEnv::create();

        // To support less rows than domain_size we need to have selectors.
        //let row_num = rng.gen_range(0..domain_size);

        let fixed_sel: Vec<Fp> = (0..domain_size).map(|i| Fp::from(i as u64)).collect();
        witness_env.set_fixed_selector_cix(TestColumn::FixedE, fixed_sel);

        let constant: Fp = <Fp as UniformRand>::rand(rng);
        for row_i in 0..domain_size {
            let a: Fp = <Fp as UniformRand>::rand(rng);
            let b: Fp = constant / a;
            assert!(a * b == constant);
            test_interpreter::test_const(&mut witness_env, a, b, constant);

            if row_i < domain_size - 1 {
                witness_env.next_row();
            }
        }

        (witness_env, constant)
    }

    #[test]
    pub fn test_build_test_constant_circuit() {
        let mut rng = o1_utils::tests::make_test_rng();
        build_test_const_circuit::<_, DummyLookupTable>(&mut rng, 1 << 4);
    }

    #[test]
    fn test_completeness_constant() {
        let mut rng = o1_utils::tests::make_test_rng();

        // Include tests for completeness for Logup as the random witness
        // includes all arguments
        let domain_size = 1 << 8;
        let domain = EvaluationDomains::<Fp>::create(domain_size).unwrap();

        let srs: PairingSRS<BN254> = get_bn254_srs(domain);

        let mut lookup_tables_data = BTreeMap::new();
        for table_id in DummyLookupTable::all_variants().into_iter() {
            lookup_tables_data.insert(table_id, table_id.entries(domain.d1.size));
        }
        let (witness_env, constant) =
            build_test_const_circuit::<_, DummyLookupTable>(&mut rng, domain_size);
        let mut proof_inputs = witness_env.get_proof_inputs(domain, lookup_tables_data);
        // Don't use lookups for now
        proof_inputs.logups = vec![];

        let mut constraint_env = ConstraintBuilderEnv::<Fp, DummyLookupTable>::create();
        test_interpreter::constrain_test_const::<Fp, _>(&mut constraint_env, constant);
        // Don't use lookups for now
        let constraints = constraint_env.get_relation_constraints();

        let fixed_selectors: Box<[Vec<Fp>; 1]> =
            Box::new([(0..domain_size).map(|i| Fp::from(i as u64)).collect()]);

        // generate the proof
        let proof = prove::<
            _,
            OpeningProof,
            BaseSponge,
            ScalarSponge,
            _,
            { TEST_N_COLUMNS - 1 },
            { TEST_N_COLUMNS - 1 },
            0,
            1,
            DummyLookupTable,
        >(
            domain,
            &srs,
            &constraints,
            fixed_selectors.clone(),
            proof_inputs,
            &mut rng,
        )
        .unwrap();

        // verify the proof
        let verifies = verify::<
            _,
            OpeningProof,
            BaseSponge,
            ScalarSponge,
            { TEST_N_COLUMNS - 1 },
            { TEST_N_COLUMNS - 1 },
            0,
            1,
            0,
            DummyLookupTable,
        >(
            domain,
            &srs,
            &constraints,
            fixed_selectors,
            &proof,
            Witness::zero_vec(domain_size),
        );

        assert!(verifies);
    }

    fn build_test_mul_circuit<RNG: RngCore + CryptoRng, LT: LookupTableID>(
        rng: &mut RNG,
        domain_size: usize,
    ) -> TestWitnessBuilderEnv<LT> {
        let mut witness_env = WitnessBuilderEnv::create();

        // To support less rows than domain_size we need to have selectors.
        //let row_num = rng.gen_range(0..domain_size);

        let fixed_sel: Vec<Fp> = (0..domain_size).map(|i| Fp::from(i as u64)).collect();
        witness_env.set_fixed_selector_cix(TestColumn::FixedE, fixed_sel);

        let row_num = 10;
        for row_i in 0..row_num {
            let a: Ff1 = From::from(rng.gen_range(0..(1 << 16)));
            let b: Ff1 = From::from(rng.gen_range(0..(1 << 16)));
            test_interpreter::test_multiplication(&mut witness_env, a, b);
            if row_i < domain_size - 1 {
                witness_env.next_row();
            }
        }

        witness_env
    }

    #[test]
    /// Tests if the "test" circuit is valid without running the proof.
    pub fn test_build_test_mul_circuit() {
        let mut rng = o1_utils::tests::make_test_rng();
        build_test_mul_circuit::<_, DummyLookupTable>(&mut rng, 1 << 4);
    }

    #[test]
    fn test_completeness() {
        let mut rng = o1_utils::tests::make_test_rng();

        // Include tests for completeness for Logup as the random witness
        // includes all arguments
        let domain_size = 1 << 8;
        let domain = EvaluationDomains::<Fp>::create(domain_size).unwrap();

        let srs: PairingSRS<BN254> = get_bn254_srs(domain);

        let mut constraint_env = ConstraintBuilderEnv::<Fp, DummyLookupTable>::create();
        test_interpreter::constrain_multiplication::<Fp, _>(&mut constraint_env);
        // Don't use lookups for now
        let constraints = constraint_env.get_relation_constraints();

        let fixed_selectors: Box<[Vec<Fp>; 1]> =
            Box::new([(0..domain_size).map(|i| Fp::from(i as u64)).collect()]);

        let mut lookup_tables_data = BTreeMap::new();
        for table_id in DummyLookupTable::all_variants().into_iter() {
            lookup_tables_data.insert(table_id, table_id.entries(domain.d1.size));
        }
        let witness_env = build_test_mul_circuit::<_, DummyLookupTable>(&mut rng, domain_size);
        let mut proof_inputs = witness_env.get_proof_inputs(domain, lookup_tables_data);
        // Don't use lookups for now
        proof_inputs.logups = vec![];

        // generate the proof
        let proof = prove::<
            _,
            OpeningProof,
            BaseSponge,
            ScalarSponge,
            _,
            { TEST_N_COLUMNS - 1 },
            { TEST_N_COLUMNS - 1 },
            0,
            1,
            DummyLookupTable,
        >(
            domain,
            &srs,
            &constraints,
            fixed_selectors.clone(),
            proof_inputs,
            &mut rng,
        )
        .unwrap();

        // verify the proof
        let verifies = verify::<
            _,
            OpeningProof,
            BaseSponge,
            ScalarSponge,
            { TEST_N_COLUMNS - 1 },
            { TEST_N_COLUMNS - 1 },
            0,
            1,
            0,
            DummyLookupTable,
        >(
            domain,
            &srs,
            &constraints,
            fixed_selectors,
            &proof,
            Witness::zero_vec(domain_size),
        );

        assert!(verifies);
    }

    #[test]
    fn test_soundness() {
        let mut rng = o1_utils::tests::make_test_rng();

        // We generate two different witness and two different proofs.
        let domain_size = 1 << 8;
        let domain = EvaluationDomains::<Fp>::create(domain_size).unwrap();

        let srs: PairingSRS<BN254> = get_bn254_srs(domain);

        let mut constraint_env = ConstraintBuilderEnv::<Fp, DummyLookupTable>::create();
        test_interpreter::constrain_multiplication::<Fp, _>(&mut constraint_env);
        // Don't use lookups for now
        let constraints = constraint_env.get_relation_constraints();

        let fixed_selectors: Box<[Vec<Fp>; 1]> =
            Box::new([(0..domain_size).map(|i| Fp::from(i as u64)).collect()]);

        let mut lookup_tables_data = BTreeMap::new();
        for table_id in DummyLookupTable::all_variants().into_iter() {
            lookup_tables_data.insert(table_id, table_id.entries(domain.d1.size));
        }
        let witness_env = build_test_mul_circuit::<_, DummyLookupTable>(&mut rng, domain_size);
        let mut proof_inputs = witness_env.get_proof_inputs(domain, lookup_tables_data.clone());
        proof_inputs.logups = vec![];

        // generate the proof
        let proof = prove::<
            _,
            OpeningProof,
            BaseSponge,
            ScalarSponge,
            _,
            { TEST_N_COLUMNS - 1 },
            { TEST_N_COLUMNS - 1 },
            0,
            1,
            DummyLookupTable,
        >(
            domain,
            &srs,
            &constraints,
            fixed_selectors.clone(),
            proof_inputs,
            &mut rng,
        )
        .unwrap();

        let witness_env_prime =
            build_test_mul_circuit::<_, DummyLookupTable>(&mut rng, domain_size);
        let mut proof_inputs_prime =
            witness_env_prime.get_proof_inputs(domain, lookup_tables_data.clone());
        proof_inputs_prime.logups = vec![];

        // generate another (prime) proof
        let proof_prime = prove::<
            _,
            OpeningProof,
            BaseSponge,
            ScalarSponge,
            _,
            { TEST_N_COLUMNS - 1 },
            { TEST_N_COLUMNS - 1 },
            0,
            1,
            DummyLookupTable,
        >(
            domain,
            &srs,
            &constraints,
            fixed_selectors.clone(),
            proof_inputs_prime,
            &mut rng,
        )
        .unwrap();

        // Swap the opening proof. The verification should fail.
        {
            let mut proof_clone = proof.clone();
            proof_clone.opening_proof = proof_prime.opening_proof;
            let verifies = verify::<
                _,
                OpeningProof,
                BaseSponge,
                ScalarSponge,
                { TEST_N_COLUMNS - 1 },
                { TEST_N_COLUMNS - 1 },
                0,
                1,
                0,
                DummyLookupTable,
            >(
                domain,
                &srs,
                &constraints,
                fixed_selectors.clone(),
                &proof_clone,
                Witness::zero_vec(domain_size),
            );
            assert!(!verifies, "Proof with a swapped opening must fail");
        }

        // Changing at least one commitment in the proof should fail the verification.
        // TODO: improve me by swapping only one commitments. It should be
        // easier when an index trait is implemented.
        {
            let mut proof_clone = proof.clone();
            proof_clone.proof_comms = proof_prime.proof_comms;
            let verifies = verify::<
                _,
                OpeningProof,
                BaseSponge,
                ScalarSponge,
                { TEST_N_COLUMNS - 1 },
                { TEST_N_COLUMNS - 1 },
                0,
                1,
                0,
                DummyLookupTable,
            >(
                domain,
                &srs,
                &constraints,
                fixed_selectors.clone(),
                &proof_clone,
                Witness::zero_vec(domain_size),
            );
            assert!(!verifies, "Proof with a swapped commitment must fail");
        }

        // Changing at least one evaluation at zeta in the proof should fail
        // the verification.
        // TODO: improve me by swapping only one evaluation at \zeta. It should be
        // easier when an index trait is implemented.
        {
            let mut proof_clone = proof.clone();
            proof_clone.proof_evals.witness_evals = proof_prime.proof_evals.witness_evals;
            let verifies = verify::<
                _,
                OpeningProof,
                BaseSponge,
                ScalarSponge,
                { TEST_N_COLUMNS - 1 },
                { TEST_N_COLUMNS - 1 },
                0,
                1,
                0,
                DummyLookupTable,
            >(
                domain,
                &srs,
                &constraints,
                fixed_selectors,
                &proof_clone,
                Witness::zero_vec(domain_size),
            );
            assert!(!verifies, "Proof with a swapped witness eval must fail");
        }
    }
}
