use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use poly_commitment::pairing_proof::PairingProof;

pub use logup::{
    Logup, LogupWitness, LookupProof as LogupProof, LookupTable as LogupTable,
    LookupTableID as LogupTableID, LookupTableID,
};

pub mod circuit_design;
pub mod column_env;
pub mod columns;
pub mod expr;
pub mod logup;
/// Instantiations of Logups for the MSM project
// REMOVEME. The different interpreters must define their own tables.
pub mod lookups;
pub mod precomputed_srs;
pub mod proof;
pub mod prover;
pub mod verifier;
pub mod witness;

pub mod fec;
pub mod ffa;
pub mod serialization;
pub mod test;

/// Define the maximum degree we support for the evaluations.
/// For instance, it can be used to split the looked-up functions into partial
/// sums.
#[allow(dead_code)]
const MAX_SUPPORTED_DEGREE: usize = 8;

/// Domain size for the MSM project, equal to the BN254 SRS size.
pub const DOMAIN_SIZE: usize = 1 << 15;

// @volhovm: maybe move these to the FF circuits module later.
/// Bitsize of the foreign field limb representation.
pub const LIMB_BITSIZE: usize = 15;

/// Number of limbs representing one foreign field element (either
/// [`Ff1`] or [`Ff2`]).
pub const N_LIMBS: usize = 17;

pub type BN254 = ark_ec::bn::Bn<ark_bn254::Parameters>;
pub type BN254G1Affine = <BN254 as ark_ec::PairingEngine>::G1Affine;
pub type BN254G2Affine = <BN254 as ark_ec::PairingEngine>::G2Affine;

/// The native field we are working with.
pub type Fp = ark_bn254::Fr;

/// The foreign field we are emulating (one of the two)
pub type Ff1 = mina_curves::pasta::Fp;
pub type Ff2 = mina_curves::pasta::Fq;

pub type SpongeParams = PlonkSpongeConstantsKimchi;
pub type BaseSponge = DefaultFqSponge<ark_bn254::g1::Parameters, SpongeParams>;
pub type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;
pub type OpeningProof = PairingProof<BN254>;

#[cfg(test)]
mod tests {
    use crate::{
        circuit_design::{ConstraintBuilderEnv, WitnessBuilderEnv},
        columns::ColumnIndexer,
        logup::LookupTableID,
        lookups::{DummyLookupTable, Lookup, LookupTableIDs},
        precomputed_srs::get_bn254_srs,
        proof::ProofInputs,
        prover::prove,
        test::{
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

    fn build_test_circuit<RNG: RngCore + CryptoRng, LT: LookupTableID>(
        rng: &mut RNG,
        domain_size: usize,
    ) -> WitnessBuilderEnv<Fp, { <TestColumn as ColumnIndexer>::COL_N }, LT> {
        let mut witness_env = WitnessBuilderEnv::create();

        // To support less rows than domain_size we need to have selectors.
        //let row_num = rng.gen_range(0..domain_size);

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
    pub fn test_test_circuit() {
        let mut rng = o1_utils::tests::make_test_rng();
        build_test_circuit::<_, DummyLookupTable>(&mut rng, 1 << 4);
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
        test_interpreter::constrain_multiplication::<Fp, Ff1, _>(&mut constraint_env);
        // Don't use lookups for now
        let constraints = constraint_env.get_relation_constraints();

        let mut lookup_tables_data = BTreeMap::new();
        for table_id in DummyLookupTable::all_variants().into_iter() {
            lookup_tables_data.insert(table_id, table_id.entries(domain.d1.size));
        }
        let witness_env = build_test_circuit::<_, DummyLookupTable>(&mut rng, domain_size);
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
            TEST_N_COLUMNS,
            TEST_N_COLUMNS,
            0,
            DummyLookupTable,
        >(domain, &srs, &constraints, proof_inputs, &mut rng)
        .unwrap();

        // verify the proof
        let verifies = verify::<
            _,
            OpeningProof,
            BaseSponge,
            ScalarSponge,
            TEST_N_COLUMNS,
            TEST_N_COLUMNS,
            0,
            0,
            DummyLookupTable,
        >(
            domain,
            &srs,
            &constraints,
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
        test_interpreter::constrain_multiplication::<Fp, Ff1, _>(&mut constraint_env);
        // Don't use lookups for now
        let constraints = constraint_env.get_relation_constraints();

        let mut lookup_tables_data = BTreeMap::new();
        for table_id in DummyLookupTable::all_variants().into_iter() {
            lookup_tables_data.insert(table_id, table_id.entries(domain.d1.size));
        }
        let witness_env = build_test_circuit::<_, DummyLookupTable>(&mut rng, domain_size);
        let mut proof_inputs = witness_env.get_proof_inputs(domain, lookup_tables_data.clone());
        proof_inputs.logups = vec![];

        // generate the proof
        let proof = prove::<
            _,
            OpeningProof,
            BaseSponge,
            ScalarSponge,
            _,
            TEST_N_COLUMNS,
            TEST_N_COLUMNS,
            0,
            DummyLookupTable,
        >(domain, &srs, &constraints, proof_inputs, &mut rng)
        .unwrap();

        let witness_env_prime = build_test_circuit::<_, DummyLookupTable>(&mut rng, domain_size);
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
            TEST_N_COLUMNS,
            TEST_N_COLUMNS,
            0,
            DummyLookupTable,
        >(domain, &srs, &constraints, proof_inputs_prime, &mut rng)
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
                TEST_N_COLUMNS,
                TEST_N_COLUMNS,
                0,
                0,
                DummyLookupTable,
            >(
                domain,
                &srs,
                &constraints,
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
                TEST_N_COLUMNS,
                TEST_N_COLUMNS,
                0,
                0,
                DummyLookupTable,
            >(
                domain,
                &srs,
                &constraints,
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
                TEST_N_COLUMNS,
                TEST_N_COLUMNS,
                0,
                0,
                DummyLookupTable,
            >(
                domain,
                &srs,
                &constraints,
                &proof_clone,
                Witness::zero_vec(domain_size),
            );
            assert!(!verifies, "Proof with a swapped witness eval must fail");
        }
    }

    // Number of columns
    const LOOKUP_TEST_N_COL: usize = 10;

    #[test]
    #[ignore]
    fn test_soundness_logup() {
        let mut rng = o1_utils::tests::make_test_rng();

        // We generate two different witness and two different proofs.
        let domain_size = 1 << 8;
        let domain = EvaluationDomains::<Fp>::create(domain_size).unwrap();

        // Trusted setup toxic waste
        let x = Fp::rand(&mut rng);

        let mut srs: PairingSRS<BN254> = PairingSRS::create(x, domain.d1.size as usize);
        srs.full_srs.add_lagrange_basis(domain.d1);

        let mut inputs = ProofInputs::random(domain);
        let constraints = vec![];
        // Take one random f_i (FIXME: taking first one for now)
        let looked_up_values = inputs.logups[0].f[0].clone();
        // We change a random looked up element (FIXME: first one for now)
        let wrong_looked_up_value = Lookup {
            table_id: looked_up_values[0].table_id,
            numerator: looked_up_values[0].numerator,
            value: vec![Fp::rand(&mut rng)],
        };
        // Overwriting the first looked up value
        inputs.logups[0].f[0][0] = wrong_looked_up_value;
        // generate the proof
        let proof = prove::<
            _,
            OpeningProof,
            BaseSponge,
            ScalarSponge,
            _,
            LOOKUP_TEST_N_COL,
            LOOKUP_TEST_N_COL,
            0,
            LookupTableIDs,
        >(domain, &srs, &constraints, inputs, &mut rng)
        .unwrap();
        let verifies = verify::<
            _,
            OpeningProof,
            BaseSponge,
            ScalarSponge,
            LOOKUP_TEST_N_COL,
            LOOKUP_TEST_N_COL,
            0,
            0,
            LookupTableIDs,
        >(
            domain,
            &srs,
            &constraints,
            &proof,
            Witness::zero_vec(domain_size),
        );
        // FIXME: At the moment, it does verify. It should not. We are missing constraints.
        assert!(!verifies);
    }
}
