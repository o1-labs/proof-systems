pub mod columns;
pub mod interpreter;
pub mod lookups;

#[cfg(test)]
mod tests {

    use crate::{
        ivc::{
            columns::{IVCColumn, IVC_POSEIDON_NB_FULL_ROUND, IVC_POSEIDON_STATE_SIZE},
            interpreter::ivc_circuit,
            lookups::IVCLookupTable,
        },
        poseidon::{interpreter::PoseidonParams, params::static_params},
    };
    use ark_ff::UniformRand;
    use kimchi_msm::{circuit_design::WitnessBuilderEnv, columns::ColumnIndexer, Ff1, Fp};
    use rand::{CryptoRng, RngCore};

    // Test number
    pub const TEST_N_COL_TOTAL: usize = 50;
    pub const TEST_DOMAIN_SIZE: usize = 1 << 15;

    #[derive(Clone)]
    pub struct PoseidonBN254Parameters;

    type IVCWitnessBuilderEnv =
        WitnessBuilderEnv<Fp, { <IVCColumn as ColumnIndexer>::COL_N }, IVCLookupTable<Ff1>>;

    impl PoseidonParams<Fp, IVC_POSEIDON_STATE_SIZE, IVC_POSEIDON_NB_FULL_ROUND>
        for PoseidonBN254Parameters
    {
        fn constants(&self) -> [[Fp; IVC_POSEIDON_STATE_SIZE]; IVC_POSEIDON_NB_FULL_ROUND] {
            let rc = &static_params().round_constants;
            std::array::from_fn(|i| std::array::from_fn(|j| Fp::from(rc[i][j])))
        }

        fn mds(&self) -> [[Fp; IVC_POSEIDON_STATE_SIZE]; IVC_POSEIDON_STATE_SIZE] {
            let mds = &static_params().mds;
            std::array::from_fn(|i| std::array::from_fn(|j| Fp::from(mds[i][j])))
        }
    }

    fn build_ivc_circuit<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> IVCWitnessBuilderEnv {
        let mut witness_env = IVCWitnessBuilderEnv::create();

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

        ivc_circuit::<_, _, _, _, TEST_N_COL_TOTAL>(
            &mut witness_env,
            comms_left,
            comms_right,
            comms_output,
            &PoseidonBN254Parameters,
            TEST_DOMAIN_SIZE,
        );

        witness_env
    }

    #[test]
    /// Tests if building the IVC circuit succeeds.
    pub fn test_ivc_circuit() {
        let mut rng = o1_utils::tests::make_test_rng();
        build_ivc_circuit(&mut rng);
    }
}
