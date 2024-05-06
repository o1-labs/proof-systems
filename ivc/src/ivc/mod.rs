pub mod columns;
pub mod interpreter;
pub mod lookups;

#[cfg(test)]
mod tests {

    use crate::ivc::{
        columns::IVCColumn,
        interpreter::{ivc_circuit, ivc_constraint},
        lookups::IVCLookupTable,
    };
    use ark_ff::UniformRand;
    use kimchi_msm::{circuit_design::WitnessBuilderEnv, columns::ColumnIndexer, Ff1, Fp};
    use rand::{CryptoRng, RngCore};

    // Test number
    pub const TEST_N_COL_TOTAL: usize = 50;
    pub const TEST_DOMAIN_SIZE: usize = 1 << 15;

    fn build_ivc_circuit<RNG: RngCore + CryptoRng>(
        rng: &mut RNG,
    ) -> WitnessBuilderEnv<Fp, { <IVCColumn as ColumnIndexer>::COL_N }, IVCLookupTable<Ff1>> {
        let mut witness_env = WitnessBuilderEnv::create();

        // To support less rows than domain_size we need to have selectors.
        //let row_num = rng.gen_range(0..domain_size);

        let comms_left: [_; TEST_N_COL_TOTAL] = core::array::from_fn(|_i| {
            (
                <Ff1 as UniformRand>::rand(rng),
                <Ff1 as UniformRand>::rand(rng),
            )
        });
        let comms_right: [_; TEST_N_COL_TOTAL] = core::array::from_fn(|_i| {
            (
                <Ff1 as UniformRand>::rand(rng),
                <Ff1 as UniformRand>::rand(rng),
            )
        });
        let comms_output: [_; TEST_N_COL_TOTAL] = core::array::from_fn(|_i| {
            (
                <Ff1 as UniformRand>::rand(rng),
                <Ff1 as UniformRand>::rand(rng),
            )
        });

        for row_i in 0..TEST_DOMAIN_SIZE {
            ivc_circuit::<Fp, Ff1, _, TEST_N_COL_TOTAL>(
                &mut witness_env,
                comms_left,
                comms_right,
                comms_output,
                row_i,
            );
            ivc_constraint(&mut witness_env);

            if row_i < TEST_DOMAIN_SIZE - 1 {
                witness_env.next_row();
            }
        }

        witness_env
    }

    #[test]
    /// Builds the FF addition circuit with random values. The witness
    /// environment enforces the constraints internally, so it is
    /// enough to just build the circuit to ensure it is satisfied.
    pub fn test_ivc_addition_circuit() {
        let mut rng = o1_utils::tests::make_test_rng();
        build_ivc_circuit(&mut rng);
    }
}
