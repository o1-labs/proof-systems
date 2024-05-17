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
        circuit_design::{
            composition::{IdMPrism, MPrism},
            ConstraintBuilderEnv, SubEnvLookup, WitnessBuilderEnv,
        },
        columns::ColumnIndexer,
        logup::LookupTableID,
        precomputed_srs::get_bn254_srs,
        proof::ProofInputs,
        prover::prove,
        verifier::verify,
        witness::Witness,
        BaseSponge, Ff1, Fp, OpeningProof, ScalarSponge, BN254,
    };
    use poly_commitment::pairing_proof::PairingSRS;
    use rand::{CryptoRng, RngCore};

    // Test number
    pub const TEST_N_COL_TOTAL: usize = IVCColumn::N_COL + 50;
    // Absolutely no idea.
    pub const TEST_N_CHALS: usize = 200;
    pub const TEST_DOMAIN_SIZE: usize = 1 << 15;

    #[derive(Clone)]
    pub struct PoseidonBN254Parameters;

    type IVCWitnessBuilderEnvRaw<LT> = WitnessBuilderEnv<
        Fp,
        IVCColumn,
        { <IVCColumn as ColumnIndexer>::N_COL },
        { <IVCColumn as ColumnIndexer>::N_COL },
        0,
        0,
        LT,
    >;
    //type IVCWitnessBuilderEnv = IVCWitnessBuilderEnvRaw<IVCLookupTable<Ff1>>;
    //type IVCWitnessBuilderEnvDummy = IVCWitnessBuilderEnvRaw<DummyLookupTable>;

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

        // To support less rows than domain_size we need to have selectors.
        //let row_num = rng.gen_range(0..domain_size);

        let comms_left: Box<[_; TEST_N_COL_TOTAL]> = Box::new(core::array::from_fn(|_i| {
            (
                <Ff1 as UniformRand>::rand(rng),
                <Ff1 as UniformRand>::rand(rng),
            )
        }));
        let comms_right: Box<[_; TEST_N_COL_TOTAL]> = Box::new(core::array::from_fn(|_i| {
            (
                <Ff1 as UniformRand>::rand(rng),
                <Ff1 as UniformRand>::rand(rng),
            )
        }));
        let comms_output: Box<[_; TEST_N_COL_TOTAL]> = Box::new(core::array::from_fn(|_i| {
            (
                <Ff1 as UniformRand>::rand(rng),
                <Ff1 as UniformRand>::rand(rng),
            )
        }));

        let fixed_selectors: Vec<Vec<Fp>> =
            build_selectors::<_, TEST_N_COL_TOTAL, TEST_N_CHALS>(domain_size);
        witness_env.set_fixed_selectors(fixed_selectors.to_vec());

        // TODO add nonzero E/T values.
        ivc_circuit::<_, _, _, _, TEST_N_COL_TOTAL>(
            &mut SubEnvLookup::new(&mut witness_env, lt_lens),
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
        build_ivc_circuit::<_, IVCLookupTable<Ff1>, _>(
            &mut rng,
            1 << 8,
            IdMPrism::<IVCLookupTable<Ff1>>::default(),
        );
    }

    #[test]
    fn test_completeness_ivc() {
        let mut rng = o1_utils::tests::make_test_rng();

        let domain_size = 1 << 15;
        let domain = EvaluationDomains::<Fp>::create(domain_size).unwrap();

        let srs: PairingSRS<BN254> = get_bn254_srs(domain);

        let witness_env = build_ivc_circuit::<_, IVCLookupTable<Ff1>, _>(
            &mut rng,
            domain_size,
            IdMPrism::<IVCLookupTable<Ff1>>::default(),
        );
        // Don't use lookups for now
        let rel_witness = witness_env.get_relation_witness(domain);
        let proof_inputs = ProofInputs {
            evaluations: rel_witness,
            logups: vec![],
        };

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
