pub mod columns;
pub mod interpreter;

#[cfg(test)]
mod tests {
    use crate::{
        circuit_design::{ConstraintBuilderEnv, WitnessBuilderEnv},
        logup::LookupTableID,
        lookups::DummyLookupTable,
        test::test_circuit::{
            columns::{TestColumn, N_COL_TEST, N_FSEL_TEST},
            interpreter as test_interpreter,
        },
        Ff1, Fp,
    };
    use ark_ff::UniformRand;
    use rand::{CryptoRng, Rng, RngCore};
    use std::collections::BTreeMap;

    type TestWitnessBuilderEnv<LT> = WitnessBuilderEnv<
        Fp,
        TestColumn,
        { N_COL_TEST - N_FSEL_TEST },
        { N_COL_TEST - N_FSEL_TEST },
        0,
        N_FSEL_TEST,
        LT,
    >;

    fn build_test_fixed_sel_circuit<RNG: RngCore + CryptoRng, LT: LookupTableID>(
        rng: &mut RNG,
        domain_size: usize,
    ) -> TestWitnessBuilderEnv<LT> {
        let mut witness_env = WitnessBuilderEnv::create();

        let fixed_selectors = test_interpreter::build_fixed_selectors(domain_size);
        witness_env.set_fixed_selectors(fixed_selectors.to_vec());

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
        let mut rng = o1_utils::tests::make_test_rng(None);
        build_test_fixed_sel_circuit::<_, DummyLookupTable>(&mut rng, 1 << 4);
    }

    #[test]
    fn test_completeness_fixed_sel() {
        let mut rng = o1_utils::tests::make_test_rng(None);

        // Include tests for completeness for Logup as the random witness
        // includes all arguments
        let domain_size = 1 << 8;

        let fixed_selectors = test_interpreter::build_fixed_selectors(domain_size);

        let mut constraint_env = ConstraintBuilderEnv::<Fp, DummyLookupTable>::create();
        test_interpreter::constrain_test_fixed_sel::<Fp, _>(&mut constraint_env);
        // Don't use lookups for now
        let constraints = constraint_env.get_relation_constraints();

        let witness_env =
            build_test_fixed_sel_circuit::<_, DummyLookupTable>(&mut rng, domain_size);
        let relation_witness = witness_env.get_relation_witness(domain_size);

        crate::test::test_completeness_generic_no_lookups::<
            { N_COL_TEST - N_FSEL_TEST },
            { N_COL_TEST - N_FSEL_TEST },
            0,
            N_FSEL_TEST,
            _,
        >(
            constraints,
            fixed_selectors,
            relation_witness,
            domain_size,
            &mut rng,
        );
    }

    fn build_test_fixed_sel_degree_7_circuit<RNG: RngCore + CryptoRng, LT: LookupTableID>(
        rng: &mut RNG,
        domain_size: usize,
    ) -> TestWitnessBuilderEnv<LT> {
        let mut witness_env = WitnessBuilderEnv::create();

        let fixed_sel: Vec<Fp> = (0..domain_size).map(|i| Fp::from(i as u64)).collect();
        witness_env.set_fixed_selector_cix(TestColumn::FixedSel1, fixed_sel);

        for row_i in 0..domain_size {
            let a: Fp = <Fp as UniformRand>::rand(rng);
            test_interpreter::test_fixed_sel_degree_7(&mut witness_env, a);

            if row_i < domain_size - 1 {
                witness_env.next_row();
            }
        }

        witness_env
    }

    #[test]
    fn test_completeness_fixed_sel_degree_7() {
        let mut rng = o1_utils::tests::make_test_rng(None);

        // Include tests for completeness for Logup as the random witness
        // includes all arguments
        let domain_size = 1 << 8;

        let fixed_selectors = test_interpreter::build_fixed_selectors(domain_size);

        let mut constraint_env = ConstraintBuilderEnv::<Fp, DummyLookupTable>::create();
        test_interpreter::constrain_test_fixed_sel_degree_7::<Fp, _>(&mut constraint_env);
        // Don't use lookups for now
        let constraints = constraint_env.get_relation_constraints();

        let witness_env =
            build_test_fixed_sel_degree_7_circuit::<_, DummyLookupTable>(&mut rng, domain_size);
        let relation_witness = witness_env.get_relation_witness(domain_size);

        crate::test::test_completeness_generic_no_lookups::<
            { N_COL_TEST - N_FSEL_TEST },
            { N_COL_TEST - N_FSEL_TEST },
            0,
            N_FSEL_TEST,
            _,
        >(
            constraints,
            fixed_selectors,
            relation_witness,
            domain_size,
            &mut rng,
        );
    }

    fn build_test_fixed_sel_degree_7_circuit_with_constants<
        RNG: RngCore + CryptoRng,
        LT: LookupTableID,
    >(
        rng: &mut RNG,
        domain_size: usize,
    ) -> TestWitnessBuilderEnv<LT> {
        let mut witness_env = WitnessBuilderEnv::create();

        let fixed_sel: Vec<Fp> = (0..domain_size).map(|i| Fp::from(i as u64)).collect();
        witness_env.set_fixed_selector_cix(TestColumn::FixedSel1, fixed_sel);

        for row_i in 0..domain_size {
            let a: Fp = <Fp as UniformRand>::rand(rng);
            test_interpreter::test_fixed_sel_degree_7_with_constants(&mut witness_env, a);

            if row_i < domain_size - 1 {
                witness_env.next_row();
            }
        }

        witness_env
    }

    #[test]
    fn test_completeness_fixed_sel_degree_7_with_constants() {
        let mut rng = o1_utils::tests::make_test_rng(None);

        // Include tests for completeness for Logup as the random witness
        // includes all arguments
        let domain_size = 1 << 8;

        let fixed_selectors = test_interpreter::build_fixed_selectors(domain_size);

        let mut constraint_env = ConstraintBuilderEnv::<Fp, DummyLookupTable>::create();
        test_interpreter::constrain_test_fixed_sel_degree_7_with_constants::<Fp, _>(
            &mut constraint_env,
        );
        // Don't use lookups for now
        let constraints = constraint_env.get_relation_constraints();

        let witness_env = build_test_fixed_sel_degree_7_circuit_with_constants::<_, DummyLookupTable>(
            &mut rng,
            domain_size,
        );
        let relation_witness = witness_env.get_relation_witness(domain_size);

        crate::test::test_completeness_generic_no_lookups::<
            { N_COL_TEST - N_FSEL_TEST },
            { N_COL_TEST - N_FSEL_TEST },
            0,
            N_FSEL_TEST,
            _,
        >(
            constraints,
            fixed_selectors,
            relation_witness,
            domain_size,
            &mut rng,
        );
    }

    fn build_test_fixed_sel_degree_7_circuit_mul_witness<
        RNG: RngCore + CryptoRng,
        LT: LookupTableID,
    >(
        rng: &mut RNG,
        domain_size: usize,
    ) -> TestWitnessBuilderEnv<LT> {
        let mut witness_env = WitnessBuilderEnv::create();

        let fixed_selectors = test_interpreter::build_fixed_selectors(domain_size);
        witness_env.set_fixed_selectors(fixed_selectors.to_vec());

        for row_i in 0..domain_size {
            let a: Fp = <Fp as UniformRand>::rand(rng);
            test_interpreter::test_fixed_sel_degree_7_mul_witness(&mut witness_env, a);

            if row_i < domain_size - 1 {
                witness_env.next_row();
            }
        }

        witness_env
    }

    #[test]
    fn test_completeness_fixed_sel_degree_7_mul_witness() {
        let mut rng = o1_utils::tests::make_test_rng(None);

        // Include tests for completeness for Logup as the random witness
        // includes all arguments
        let domain_size = 1 << 8;

        let fixed_selectors = test_interpreter::build_fixed_selectors(domain_size);

        let mut constraint_env = ConstraintBuilderEnv::<Fp, DummyLookupTable>::create();
        test_interpreter::constrain_test_fixed_sel_degree_7_mul_witness::<Fp, _>(
            &mut constraint_env,
        );
        // Don't use lookups for now
        let constraints = constraint_env.get_relation_constraints();

        let witness_env = build_test_fixed_sel_degree_7_circuit_mul_witness::<_, DummyLookupTable>(
            &mut rng,
            domain_size,
        );
        let relation_witness = witness_env.get_relation_witness(domain_size);

        crate::test::test_completeness_generic_no_lookups::<
            { N_COL_TEST - N_FSEL_TEST },
            { N_COL_TEST - N_FSEL_TEST },
            0,
            N_FSEL_TEST,
            _,
        >(
            constraints,
            fixed_selectors,
            relation_witness,
            domain_size,
            &mut rng,
        );
    }

    fn build_test_fixed_sel_degree_7_circuit_fixed_values<
        RNG: RngCore + CryptoRng,
        LT: LookupTableID,
    >(
        rng: &mut RNG,
        domain_size: usize,
    ) -> TestWitnessBuilderEnv<LT> {
        let mut witness_env = WitnessBuilderEnv::create();

        let fixed_selectors = test_interpreter::build_fixed_selectors(domain_size);
        witness_env.set_fixed_selectors(fixed_selectors.to_vec());

        for row_i in 0..domain_size {
            let a: Fp = <Fp as UniformRand>::rand(rng);
            test_interpreter::test_fixed_sel_degree_7(&mut witness_env, a);

            if row_i < domain_size - 1 {
                witness_env.next_row();
            }
        }

        witness_env
    }

    #[test]
    fn test_completeness_fixed_sel_degree_7_fixed_values() {
        let mut rng = o1_utils::tests::make_test_rng(None);

        // Include tests for completeness for Logup as the random witness
        // includes all arguments
        let domain_size = 1 << 8;

        let fixed_selectors = test_interpreter::build_fixed_selectors(domain_size);

        let mut constraint_env = ConstraintBuilderEnv::<Fp, DummyLookupTable>::create();
        test_interpreter::constrain_test_fixed_sel_degree_7::<Fp, _>(&mut constraint_env);
        // Don't use lookups for now
        let constraints = constraint_env.get_relation_constraints();

        let witness_env = build_test_fixed_sel_degree_7_circuit_fixed_values::<_, DummyLookupTable>(
            &mut rng,
            domain_size,
        );
        let relation_witness = witness_env.get_relation_witness(domain_size);

        crate::test::test_completeness_generic_no_lookups::<
            { N_COL_TEST - N_FSEL_TEST },
            { N_COL_TEST - N_FSEL_TEST },
            0,
            N_FSEL_TEST,
            _,
        >(
            constraints,
            fixed_selectors,
            relation_witness,
            domain_size,
            &mut rng,
        );
    }

    fn build_test_const_circuit<RNG: RngCore + CryptoRng, LT: LookupTableID>(
        rng: &mut RNG,
        domain_size: usize,
    ) -> (TestWitnessBuilderEnv<LT>, Fp) {
        let mut witness_env = WitnessBuilderEnv::create();

        // To support less rows than domain_size we need to have selectors.
        //let row_num = rng.gen_range(0..domain_size);

        let fixed_sel: Vec<Fp> = (0..domain_size).map(|i| Fp::from(i as u64)).collect();
        witness_env.set_fixed_selector_cix(TestColumn::FixedSel1, fixed_sel);

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
        let mut rng = o1_utils::tests::make_test_rng(None);
        build_test_const_circuit::<_, DummyLookupTable>(&mut rng, 1 << 4);
    }

    #[test]
    fn test_completeness_constant() {
        let mut rng = o1_utils::tests::make_test_rng(None);

        // Include tests for completeness for Logup as the random witness
        // includes all arguments
        let domain_size = 1 << 8;

        let fixed_selectors = test_interpreter::build_fixed_selectors(domain_size);

        let (witness_env, constant) =
            build_test_const_circuit::<_, DummyLookupTable>(&mut rng, domain_size);
        let relation_witness = witness_env.get_relation_witness(domain_size);

        let mut constraint_env = ConstraintBuilderEnv::<Fp, DummyLookupTable>::create();
        test_interpreter::constrain_test_const::<Fp, _>(&mut constraint_env, constant);
        let constraints = constraint_env.get_relation_constraints();

        crate::test::test_completeness_generic_no_lookups::<
            { N_COL_TEST - N_FSEL_TEST },
            { N_COL_TEST - N_FSEL_TEST },
            0,
            N_FSEL_TEST,
            _,
        >(
            constraints,
            fixed_selectors,
            relation_witness,
            domain_size,
            &mut rng,
        );
    }

    fn build_test_mul_circuit<RNG: RngCore + CryptoRng, LT: LookupTableID>(
        rng: &mut RNG,
        domain_size: usize,
    ) -> TestWitnessBuilderEnv<LT> {
        let mut witness_env = WitnessBuilderEnv::create();

        // To support less rows than domain_size we need to have selectors.
        //let row_num = rng.gen_range(0..domain_size);

        let fixed_sel: Vec<Fp> = (0..domain_size).map(|i| Fp::from(i as u64)).collect();
        witness_env.set_fixed_selector_cix(TestColumn::FixedSel1, fixed_sel);

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
        let mut rng = o1_utils::tests::make_test_rng(None);
        build_test_mul_circuit::<_, DummyLookupTable>(&mut rng, 1 << 4);
    }

    #[test]
    fn test_completeness() {
        let mut rng = o1_utils::tests::make_test_rng(None);

        // Include tests for completeness for Logup as the random witness
        // includes all arguments
        let domain_size = 1 << 8;

        let fixed_selectors = test_interpreter::build_fixed_selectors(domain_size);

        let mut constraint_env = ConstraintBuilderEnv::<Fp, DummyLookupTable>::create();
        test_interpreter::constrain_multiplication::<Fp, _>(&mut constraint_env);
        // Don't use lookups for now
        let constraints = constraint_env.get_relation_constraints();

        let witness_env = build_test_mul_circuit::<_, DummyLookupTable>(&mut rng, domain_size);
        let relation_witness = witness_env.get_relation_witness(domain_size);

        crate::test::test_completeness_generic_no_lookups::<
            { N_COL_TEST - N_FSEL_TEST },
            { N_COL_TEST - N_FSEL_TEST },
            0,
            N_FSEL_TEST,
            _,
        >(
            constraints,
            fixed_selectors,
            relation_witness,
            domain_size,
            &mut rng,
        );
    }

    #[test]
    fn test_soundness() {
        let mut rng = o1_utils::tests::make_test_rng(None);

        // We generate two different witness and two different proofs.
        let domain_size: usize = 1 << 8;

        let fixed_selectors = test_interpreter::build_fixed_selectors(domain_size);

        let mut constraint_env = ConstraintBuilderEnv::<Fp, DummyLookupTable>::create();
        test_interpreter::constrain_multiplication::<Fp, _>(&mut constraint_env);
        let constraints = constraint_env.get_relation_constraints();

        let lookup_tables_data = BTreeMap::new();
        let witness_env = build_test_mul_circuit::<_, DummyLookupTable>(&mut rng, domain_size);
        let mut proof_inputs =
            witness_env.get_proof_inputs(domain_size, lookup_tables_data.clone());
        proof_inputs.logups = Default::default();

        let witness_env_prime =
            build_test_mul_circuit::<_, DummyLookupTable>(&mut rng, domain_size);
        let mut proof_inputs_prime =
            witness_env_prime.get_proof_inputs(domain_size, lookup_tables_data.clone());
        proof_inputs_prime.logups = Default::default();

        crate::test::test_soundness_generic::<
            { N_COL_TEST - N_FSEL_TEST },
            { N_COL_TEST - N_FSEL_TEST },
            0,
            N_FSEL_TEST,
            DummyLookupTable,
            _,
        >(
            constraints,
            fixed_selectors,
            proof_inputs,
            proof_inputs_prime,
            domain_size,
            &mut rng,
        );
    }
}
