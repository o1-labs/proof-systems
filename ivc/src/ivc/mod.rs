pub mod columns;
pub mod constraints;
pub mod helpers;
pub mod interpreter;
pub mod lookups;

/// The biggest packing variant for foreign field. Used for hashing. 150-bit limbs.
pub const LIMB_BITSIZE_XLARGE: usize = 150;

/// The biggest packing format, 2 limbs.
pub const N_LIMBS_XLARGE: usize = 2;

/// Number of additional columns that a reduction to degree 2 will
/// require.
// This value has been generated using a fake folding config like in
// [folding::tests::test_quadraticization]
pub const N_ADDITIONAL_WIT_COL_QUAD: usize = 48;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::{
        ivc::{
            columns::{IVCColumn, IVC_NB_TOTAL_FIXED_SELECTORS, N_BLOCKS},
            constraints::constrain_ivc,
            interpreter::{build_selectors, ivc_circuit},
            lookups::IVCLookupTable,
            N_ADDITIONAL_WIT_COL_QUAD,
        },
        poseidon_8_56_5_3_2::{
            bn254::{
                PoseidonBN254Parameters, NB_CONSTRAINTS as IVC_POSEIDON_NB_CONSTRAINTS,
                STATE_SIZE as IVC_POSEIDON_STATE_SIZE,
            },
            interpreter::PoseidonParams,
        },
    };
    use ark_ff::{UniformRand, Zero};
    use kimchi_msm::{
        circuit_design::{
            composition::{IdMPrism, MPrism},
            ConstraintBuilderEnv, SubEnvLookup, WitnessBuilderEnv,
        },
        columns::ColumnIndexer,
        logup::LookupTableID,
        Ff1, Fp,
    };
    use rand::{CryptoRng, RngCore};

    pub const TEST_DOMAIN_SIZE: usize = 1 << 15;

    type IVCWitnessBuilderEnvRaw<LT> = WitnessBuilderEnv<
        Fp,
        IVCColumn,
        { <IVCColumn as ColumnIndexer>::N_COL - N_BLOCKS },
        { <IVCColumn as ColumnIndexer>::N_COL - N_BLOCKS },
        0,
        IVC_NB_TOTAL_FIXED_SELECTORS,
        LT,
    >;

    fn build_ivc_circuit<
        RNG: RngCore + CryptoRng,
        LT: LookupTableID,
        L: MPrism<Source = LT, Target = IVCLookupTable<Ff1>>,
        const N_COL_TOTAL: usize,
        const N_CHALS: usize,
    >(
        rng: &mut RNG,
        domain_size: usize,
        lt_lens: L,
    ) -> IVCWitnessBuilderEnvRaw<LT> {
        let mut witness_env = IVCWitnessBuilderEnvRaw::<LT>::create();

        let mut comms_left: Vec<_> = vec![];
        let mut comms_right: Vec<_> = vec![];
        let mut comms_output: Vec<_> = vec![];

        for _i in 0..N_COL_TOTAL {
            comms_left.push((
                <Ff1 as UniformRand>::rand(rng),
                <Ff1 as UniformRand>::rand(rng),
            ));
            comms_right.push((
                <Ff1 as UniformRand>::rand(rng),
                <Ff1 as UniformRand>::rand(rng),
            ));
            comms_output.push((
                <Ff1 as UniformRand>::rand(rng),
                <Ff1 as UniformRand>::rand(rng),
            ));
        }

        println!("Building fixed selectors");
        let mut fixed_selectors: Vec<Vec<Fp>> =
            build_selectors::<Fp, N_COL_TOTAL, N_CHALS>(domain_size).to_vec();

        // Write constants
        {
            let rc = PoseidonBN254Parameters.constants();
            rc.iter().enumerate().for_each(|(_, rcs)| {
                rcs.iter().enumerate().for_each(|(_, rc)| {
                    let rc = vec![*rc; domain_size];
                    fixed_selectors.push(rc);
                });
            });
        }

        witness_env.set_fixed_selectors(fixed_selectors);

        println!("Calling the IVC circuit");
        // TODO add nonzero E/T values.
        ivc_circuit::<_, _, _, _, N_COL_TOTAL, N_CHALS>(
            &mut SubEnvLookup::new(&mut witness_env, lt_lens),
            0,
            comms_left.try_into().unwrap(),
            comms_right.try_into().unwrap(),
            comms_output.try_into().unwrap(),
            [(Ff1::zero(), Ff1::zero()); 3],
            [(Ff1::zero(), Ff1::zero()); 2],
            Fp::zero(),
            Box::new(
                (*vec![Fp::zero(); N_CHALS].into_boxed_slice())
                    .try_into()
                    .unwrap(),
            ),
            &PoseidonBN254Parameters,
            TEST_DOMAIN_SIZE,
        );

        witness_env
    }

    /// Tests if building the IVC circuit succeeds.
    pub fn generic_ivc_circuit<const N_COL_TOTAL: usize, const N_CHALS: usize>() {
        let mut rng = o1_utils::tests::make_test_rng(None);
        build_ivc_circuit::<_, IVCLookupTable<Ff1>, _, N_COL_TOTAL, N_CHALS>(
            &mut rng,
            TEST_DOMAIN_SIZE,
            IdMPrism::<IVCLookupTable<Ff1>>::default(),
        );
    }

    #[test]
    pub fn test_generic_ivc_circuit_app_50_cols() {
        pub const TEST_N_CHALS: usize = IVC_POSEIDON_NB_CONSTRAINTS;

        generic_ivc_circuit::<{ IVCColumn::N_COL + 50 }, TEST_N_CHALS>()
    }

    #[test]
    fn test_regression_ivc_constraints() {
        let mut constraint_env = ConstraintBuilderEnv::<Fp, IVCLookupTable<Ff1>>::create();
        constrain_ivc::<Fp, Ff1, _>(&mut constraint_env);
        let constraints = constraint_env.get_relation_constraints();

        let mut constraints_degrees = HashMap::new();

        // Regression testing for the number of constraints and their degree
        {
            // Hashes are not included for now.
            assert_eq!(constraints.len(), 55);
            constraints.iter().for_each(|c| {
                let degree = c.degree(1, 0);
                *constraints_degrees.entry(degree).or_insert(0) += 1;
            });

            assert_eq!(constraints_degrees.get(&1), None);
            assert_eq!(constraints_degrees.get(&2), Some(&29));
            assert_eq!(constraints_degrees.get(&3), Some(&5));
            assert_eq!(constraints_degrees.get(&4), Some(&21));
        }
    }

    fn test_completeness_ivc<const N_COL_TOTAL: usize, const N_CHALS: usize>() {
        let mut rng = o1_utils::tests::make_test_rng(None);

        let witness_env = build_ivc_circuit::<_, IVCLookupTable<Ff1>, _, N_COL_TOTAL, N_CHALS>(
            &mut rng,
            TEST_DOMAIN_SIZE,
            IdMPrism::<IVCLookupTable<Ff1>>::default(),
        );
        let relation_witness = witness_env.get_relation_witness(TEST_DOMAIN_SIZE);

        let mut constraint_env = ConstraintBuilderEnv::<Fp, IVCLookupTable<Ff1>>::create();
        constrain_ivc::<Fp, Ff1, _>(&mut constraint_env);
        let constraints = constraint_env.get_relation_constraints();

        let mut fixed_selectors: Box<[Vec<Fp>; IVC_NB_TOTAL_FIXED_SELECTORS]> =
            { Box::new(build_selectors::<_, N_COL_TOTAL, N_CHALS>(TEST_DOMAIN_SIZE)) };

        // Write constants
        {
            let rc = PoseidonBN254Parameters.constants();
            rc.iter().enumerate().for_each(|(round, rcs)| {
                rcs.iter().enumerate().for_each(|(state_index, rc)| {
                    let rc = vec![*rc; TEST_DOMAIN_SIZE];
                    fixed_selectors[N_BLOCKS + round * IVC_POSEIDON_STATE_SIZE + state_index] = rc;
                });
            });
        }

        kimchi_msm::test::test_completeness_generic_no_lookups::<
            { IVCColumn::N_COL - N_BLOCKS },
            { IVCColumn::N_COL - N_BLOCKS },
            0,
            IVC_NB_TOTAL_FIXED_SELECTORS,
            _,
        >(
            constraints,
            fixed_selectors,
            relation_witness,
            TEST_DOMAIN_SIZE,
            &mut rng,
        );
    }

    #[test]
    // Verifying the IVC circuit can be built with 50 columns for the
    // application
    fn test_completeness_ivc_app_50_cols() {
        // Simulating 3 challenges for PIOP as we do have in general.
        pub const TEST_N_CHALS: usize =
            IVC_POSEIDON_NB_CONSTRAINTS + N_BLOCKS + N_ADDITIONAL_WIT_COL_QUAD + 3;

        test_completeness_ivc::<{ IVCColumn::N_COL + 50 }, TEST_N_CHALS>()
    }

    #[test]
    // Verifying the IVC circuit can be built with 100 columns for the
    // application
    fn test_completeness_ivc_app_100_cols() {
        pub const TEST_N_CHALS: usize =
            IVC_POSEIDON_NB_CONSTRAINTS + N_BLOCKS + N_ADDITIONAL_WIT_COL_QUAD + 3;

        test_completeness_ivc::<{ IVCColumn::N_COL + 100 }, TEST_N_CHALS>()
    }

    #[test]
    // Verifying the IVC circuit can be built with 231 columns for the
    // application
    fn test_completeness_ivc_app_233_cols() {
        pub const TEST_N_CHALS: usize =
            IVC_POSEIDON_NB_CONSTRAINTS + N_BLOCKS + N_ADDITIONAL_WIT_COL_QUAD + 3;

        test_completeness_ivc::<{ IVCColumn::N_COL + 233 }, TEST_N_CHALS>()
    }

    #[test]
    #[should_panic]
    // Verifying that the maximum number is 234 columns for the application,
    // without any additional challenge.
    // It should panic by saying that the domain size is not big enough.
    fn test_regression_completeness_ivc_app_maximum_234_cols() {
        pub const TEST_N_CHALS: usize =
            IVC_POSEIDON_NB_CONSTRAINTS + N_BLOCKS + N_ADDITIONAL_WIT_COL_QUAD + 3;

        test_completeness_ivc::<{ IVCColumn::N_COL + 234 }, TEST_N_CHALS>()
    }
}
