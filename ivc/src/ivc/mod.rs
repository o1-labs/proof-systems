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
    use ark_ff::{UniformRand, Zero};
    use kimchi::circuits::domains::EvaluationDomains;
    use kimchi_msm::{
        circuit_design::{ConstraintBuilderEnv, WitnessBuilderEnv},
        columns::ColumnIndexer,
        logup::LookupTableID,
        precomputed_srs::get_bn254_srs,
        prover::prove,
        verifier::verify,
        witness::Witness,
        BaseSponge, Ff1, Fp, OpeningProof, ScalarSponge, BN254,
    };
    use poly_commitment::pairing_proof::PairingSRS;
    use rand::{CryptoRng, RngCore};
    use std::collections::BTreeMap;

    // Test number
    pub const TEST_N_COL_TOTAL: usize = 2 * IVCColumn::N_COL;
    // Absolutely no idea.
    pub const TEST_N_CHALS: usize = 200;
    pub const TEST_DOMAIN_SIZE: usize = 1 << 15;

    #[derive(Clone)]
    pub struct PoseidonBN254Parameters;

    type IVCWitnessBuilderEnv = WitnessBuilderEnv<
        Fp,
        IVCColumn,
        { <IVCColumn as ColumnIndexer>::N_COL },
        { <IVCColumn as ColumnIndexer>::N_COL },
        0,
        0,
        IVCLookupTable<Ff1>,
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

    fn build_ivc_circuit<RNG: RngCore + CryptoRng>(
        rng: &mut RNG,
        domain_size: usize,
    ) -> IVCWitnessBuilderEnv {
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

        let fixed_selectors: [Vec<Fp>; N_BLOCKS] =
            build_selectors::<_, TEST_N_COL_TOTAL, TEST_N_CHALS>(domain_size);
        witness_env.set_fixed_selectors(fixed_selectors.to_vec());

        // TODO add nonzero E/T values.
        ivc_circuit::<_, _, _, _, TEST_N_COL_TOTAL>(
            &mut witness_env,
            comms_left,
            comms_right,
            comms_output,
            [(Ff1::zero(), Ff1::zero()); 3],
            [(Ff1::zero(), Ff1::zero()); 2],
            Fp::zero(),
            vec![Fp::zero(); 200],
            &PoseidonBN254Parameters,
            TEST_DOMAIN_SIZE,
        );

        witness_env
    }

    #[test]
    /// Tests if building the IVC circuit succeeds.
    pub fn test_ivc_circuit() {
        let mut rng = o1_utils::tests::make_test_rng();
        build_ivc_circuit(&mut rng, 1 << 8);
    }

    #[test]
    fn test_completeness_ivc() {
        let mut rng = o1_utils::tests::make_test_rng();

        let domain_size = 1 << 15;
        let domain = EvaluationDomains::<Fp>::create(domain_size).unwrap();

        let srs: PairingSRS<BN254> = get_bn254_srs(domain);

        let mut lookup_tables_data = BTreeMap::new();
        for table_id in IVCLookupTable::<Ff1>::all_variants().into_iter() {
            lookup_tables_data.insert(table_id, table_id.entries(domain.d1.size));
        }
        let witness_env = build_ivc_circuit::<_>(&mut rng, domain_size);
        let mut proof_inputs = witness_env.get_proof_inputs(domain, lookup_tables_data);
        // Don't use lookups for now
        proof_inputs.logups = vec![];

        let mut constraint_env = ConstraintBuilderEnv::<Fp, IVCLookupTable<Ff1>>::create();
        constrain_ivc::<Fp, Ff1, _>(&mut constraint_env);
        // Don't use lookups for now
        let constraints = constraint_env.get_relation_constraints();

        // generate the proof
        let proof = prove::<
            _,
            OpeningProof,
            BaseSponge,
            ScalarSponge,
            _,
            { IVCColumn::N_COL },
            { IVCColumn::N_COL - N_BLOCKS },
            0,
            N_BLOCKS,
            IVCLookupTable<Ff1>,
        >(domain, &srs, &constraints, proof_inputs, &mut rng)
        .unwrap();

        // verify the proof
        let verifies = verify::<
            _,
            OpeningProof,
            BaseSponge,
            ScalarSponge,
            { IVCColumn::N_COL },
            { IVCColumn::N_COL - N_BLOCKS },
            0,
            N_BLOCKS,
            0,
            IVCLookupTable<Ff1>,
        >(
            domain,
            &srs,
            &constraints,
            &proof,
            Witness::zero_vec(domain_size),
        );

        assert!(verifies);
    }
}
