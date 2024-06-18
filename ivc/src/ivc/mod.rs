pub mod columns;
pub mod constraints;
pub mod helpers;
pub mod interpreter;
pub mod lookups;

/// The biggest packing variant for foreign field. Used for hashing. 150-bit limbs.
pub const LIMB_BITSIZE_XLARGE: usize = 150;

/// The biggest packing format, 2 limbs.
pub const N_LIMBS_XLARGE: usize = 2;

#[cfg(test)]
mod tests {
    use crate::{
        ivc::{
            columns::{IVCColumn, IVC_NB_TOTAL_FIXED_SELECTORS, N_BLOCKS},
            constraints::constrain_ivc,
            interpreter::{build_selectors, ivc_circuit},
            lookups::IVCLookupTable,
        },
        poseidon_8_56_5_3_2::{
            bn254::{PoseidonBN254Parameters, STATE_SIZE as IVC_POSEIDON_STATE_SIZE},
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
    use o1_utils::box_array;
    use rand::{CryptoRng, RngCore};

    // Total number of columns in IVC and Application circuits.
    pub const TEST_N_COL_TOTAL: usize = IVCColumn::N_COL + 50;
    // Absolutely no idea.
    pub const TEST_N_CHALS: usize = 200;
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
        let mut fixed_selectors: Vec<Vec<Fp>> =
            build_selectors::<Fp, TEST_N_COL_TOTAL, TEST_N_CHALS>(domain_size).to_vec();

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
        ivc_circuit::<_, _, _, _, TEST_N_COL_TOTAL, TEST_N_CHALS>(
            &mut SubEnvLookup::new(&mut witness_env, lt_lens),
            0,
            comms_left,
            comms_right,
            comms_output,
            [(Ff1::zero(), Ff1::zero()); 3],
            [(Ff1::zero(), Ff1::zero()); 2],
            Fp::zero(),
            Box::new(
                (*vec![Fp::zero(); TEST_N_CHALS].into_boxed_slice())
                    .try_into()
                    .unwrap(),
            ),
            &PoseidonBN254Parameters,
            TEST_DOMAIN_SIZE,
        );

        witness_env
    }

    #[test]
    /// Tests if building the IVC circuit succeeds.
    pub fn test_ivc_circuit() {
        let mut rng = o1_utils::tests::make_test_rng(None);
        build_ivc_circuit::<_, IVCLookupTable<Ff1>, _>(
            &mut rng,
            1 << 15,
            IdMPrism::<IVCLookupTable<Ff1>>::default(),
        );
    }

    #[test]
    fn test_completeness_ivc() {
        let mut rng = o1_utils::tests::make_test_rng(None);

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

        let mut fixed_selectors: Box<[Vec<Fp>; IVC_NB_TOTAL_FIXED_SELECTORS]> = {
            Box::new(build_selectors::<_, TEST_N_COL_TOTAL, TEST_N_CHALS>(
                domain_size,
            ))
        };

        // Write constants
        {
            let rc = PoseidonBN254Parameters.constants();
            rc.iter().enumerate().for_each(|(round, rcs)| {
                rcs.iter().enumerate().for_each(|(state_index, rc)| {
                    let rc = vec![*rc; domain_size];
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
            domain_size,
            &mut rng,
        );
    }
}
