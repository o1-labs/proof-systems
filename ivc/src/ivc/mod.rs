pub mod columns;
pub mod interpreter;
pub mod lookups;

#[cfg(test)]
mod tests {

    use crate::{
        ivc::{
            columns::{IVCColumn, IVC_POSEIDON_NB_FULL_ROUND, IVC_POSEIDON_STATE_SIZE, N_BLOCKS},
            interpreter::{build_selectors, constrain_ivc, ivc_circuit},
            lookups::IVCLookupTable,
        },
        poseidon::{interpreter::PoseidonParams, params::static_params},
    };
    use ark_ff::{Field, UniformRand, Zero};
    use kimchi_msm::{
        circuit_design::{
            composition::{IdMPrism, MPrism},
            ConstraintBuilderEnv, SubEnvLookup, WitnessBuilderEnv,
        },
        columns::ColumnIndexer,
        logup::LookupTableID,
        Ff1, Fp,
    };
    use o1_utils::box_array;
    use rand::{CryptoRng, RngCore};

    // Total number of columns in IVC and Application circuits.
    pub const TEST_N_COL_TOTAL: usize = IVCColumn::N_COL + 50;
    // Absolutely no idea.
    pub const TEST_N_CHALS: usize = 200;
    pub const TEST_DOMAIN_SIZE: usize = 1 << 15;

    #[derive(Clone)]
    pub struct PoseidonBN254Parameters;

    type IVCWitnessBuilderEnvRaw<LT> = WitnessBuilderEnv<
        Fp,
        IVCColumn,
        { <IVCColumn as ColumnIndexer>::N_COL - N_BLOCKS },
        { <IVCColumn as ColumnIndexer>::N_COL - N_BLOCKS },
        0,
        N_BLOCKS,
        LT,
    >;

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

    fn build_ivc_circuit<
        RNG: RngCore + CryptoRng,
        LT: LookupTableID,
        L: MPrism<Source = LT, Target = IVCLookupTable<Ff1>>,
    >(
        rng: &mut RNG,
        domain_size: usize,
        lt_lens: L,
    ) -> IVCWitnessBuilderEnvRaw<LT> {
        let mut witness_env = IVCWitnessBuilderEnvRaw::<LT>::create();

        let mut comms_left: Box<_> = box_array![(Ff1::zero(),Ff1::zero()); TEST_N_COL_TOTAL];
        let mut comms_right: Box<_> = box_array![(Ff1::zero(),Ff1::zero()); TEST_N_COL_TOTAL];
        let mut comms_output: Box<_> = box_array![(Ff1::zero(),Ff1::zero()); TEST_N_COL_TOTAL];

        for i in 0..TEST_N_COL_TOTAL {
            comms_left[i] = (
                <Ff1 as UniformRand>::rand(rng),
                <Ff1 as UniformRand>::rand(rng),
            );
            comms_right[i] = (
                <Ff1 as UniformRand>::rand(rng),
                <Ff1 as UniformRand>::rand(rng),
            );
            comms_output[i] = (
                <Ff1 as UniformRand>::rand(rng),
                <Ff1 as UniformRand>::rand(rng),
            );
        }

        println!("Building fixed selectors");
        let fixed_selectors: Vec<Vec<Fp>> =
            build_selectors::<_, TEST_N_COL_TOTAL, TEST_N_CHALS>(domain_size).to_vec();
        witness_env.set_fixed_selectors(fixed_selectors);

        let alpha = <Fp as UniformRand>::rand(rng);
        let alphas: Vec<_> = (0..TEST_N_CHALS).map(|i| alpha.pow([i as u64])).collect();

        println!("Calling the IVC circuit");
        // TODO add nonzero E/T values.
        ivc_circuit::<_, _, _, _, TEST_N_COL_TOTAL, TEST_N_CHALS>(
            &mut SubEnvLookup::new(&mut witness_env, lt_lens),
            comms_left,
            comms_right,
            comms_output,
            [(
                <Ff1 as UniformRand>::rand(rng),
                <Ff1 as UniformRand>::rand(rng),
            ); 3],
            [(
                <Ff1 as UniformRand>::rand(rng),
                <Ff1 as UniformRand>::rand(rng),
            ); 2],
            <Fp as UniformRand>::rand(rng),
            Box::new((*alphas.into_boxed_slice()).try_into().unwrap()),
            1,
            &PoseidonBN254Parameters,
            TEST_DOMAIN_SIZE,
        );

        witness_env
    }

    #[test]
    /// Tests if building the IVC circuit succeeds.
    pub fn test_ivc_circuit() {
        let mut rng = o1_utils::tests::make_test_rng();
        build_ivc_circuit::<_, IVCLookupTable<Ff1>, _>(
            &mut rng,
            1 << 15,
            IdMPrism::<IVCLookupTable<Ff1>>::default(),
        );
    }

    #[test]
    fn test_completeness_ivc() {
        let mut rng = o1_utils::tests::make_test_rng();

        let domain_size = 1 << 15;

        let witness_env = build_ivc_circuit::<_, IVCLookupTable<Ff1>, _>(
            &mut rng,
            domain_size,
            IdMPrism::<IVCLookupTable<Ff1>>::default(),
        );
        let relation_witness = witness_env.get_relation_witness(domain_size);

        let mut constraint_env = ConstraintBuilderEnv::<Fp, IVCLookupTable<Ff1>>::create();
        constrain_ivc::<Fp, Ff1, _>(&mut constraint_env);
        let constraints = constraint_env.get_relation_constraints();

        let fixed_selectors: Box<[Vec<Fp>; N_BLOCKS]> =
            Box::new(build_selectors::<_, TEST_N_COL_TOTAL, TEST_N_CHALS>(
                domain_size,
            ));

        kimchi_msm::test::test_completeness_generic_no_lookups::<
            { IVCColumn::N_COL - N_BLOCKS },
            { IVCColumn::N_COL - N_BLOCKS },
            0,
            N_BLOCKS,
            _,
        >(
            constraints,
            fixed_selectors,
            relation_witness,
            domain_size,
            &mut rng,
        );
    }
}
