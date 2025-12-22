pub mod columns;
pub mod interpreter;
pub mod lookups;

#[cfg(test)]
mod tests {
    use crate::{
        circuit_design::WitnessBuilderEnv,
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

    fn build_test_const_circuit<RNG: RngCore + CryptoRng, LT: LookupTableID>(
        rng: &mut RNG,
        domain_size: usize,
    ) -> (TestWitnessBuilderEnv<LT>, Fp) {
        let mut witness_env = WitnessBuilderEnv::create();

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

    fn build_test_mul_circuit<RNG: RngCore + CryptoRng, LT: LookupTableID>(
        rng: &mut RNG,
        domain_size: usize,
    ) -> TestWitnessBuilderEnv<LT> {
        let mut witness_env = WitnessBuilderEnv::create();

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
}
