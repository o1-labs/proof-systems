use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use poly_commitment::pairing_proof::PairingProof;

pub use logup::{
    Logup, LogupWitness, LookupProof as LogupProof, LookupTable as LogupTable,
    LookupTableID as LogupTableID, LookupTableID,
};

pub mod column_env;
pub mod columns;
pub mod expr;
pub mod interpreter;
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
        columns::Column,
        lookups::{Lookup, LookupTableIDs},
        proof::ProofInputs,
        prover::prove,
        test::{
            columns::TEST_N_COLUMNS,
            constraint::ConstraintBuilderEnv as TestConstraintBuilderEnv,
            interpreter::{self as ffa_interpreter, TestInterpreterEnv},
            witness::WitnessBuilderEnv as TestWitnessBuilderEnv,
        },
        verifier::verify,
        witness::Witness,
        BaseSponge, Ff1, Fp, OpeningProof, ScalarSponge, BN254,
    };
    use ark_ff::UniformRand;
    use kimchi::circuits::domains::EvaluationDomains;
    use poly_commitment::pairing_proof::PairingSRS;
    use rand::{CryptoRng, Rng, RngCore};

    // Number of columns
    const N: usize = 10;

    // Creates a test witness for a * b = c constraint.
    fn gen_random_mul_witness<RNG: RngCore + CryptoRng>(
        witness_env: &mut TestWitnessBuilderEnv<Fp>,
        rng: &mut RNG,
    ) {
        let row_num = 10;
        for _row_i in 0..row_num {
            let a: Ff1 = From::from(rng.gen_range(0..(1 << 16)));
            let b: Ff1 = From::from(rng.gen_range(0..(1 << 16)));
            ffa_interpreter::test_multiplication(witness_env, a, b);
            witness_env.next_row();
        }
    }

    #[test]
    fn test_completeness() {
        let mut rng = o1_utils::tests::make_test_rng();

        // Include tests for completeness for Logup as the random witness
        // includes all arguments
        let domain_size = 1 << 8;
        let domain = EvaluationDomains::<Fp>::create(domain_size).unwrap();

        // Trusted setup toxic waste
        let x = Fp::rand(&mut rng);

        let mut srs: PairingSRS<BN254> = PairingSRS::create(x, domain.d1.size as usize);
        srs.full_srs.add_lagrange_basis(domain.d1);

        let mut witness_env = TestWitnessBuilderEnv::<Fp>::empty();
        let mut constraint_env = TestConstraintBuilderEnv::<Fp>::empty();

        ffa_interpreter::constrain_multiplication(&mut constraint_env);
        gen_random_mul_witness(&mut witness_env, &mut rng);

        let inputs = witness_env.get_witness(domain_size);
        let constraints = constraint_env.constraints;

        // generate the proof
        let proof = prove::<
            _,
            OpeningProof,
            BaseSponge,
            ScalarSponge,
            Column,
            _,
            TEST_N_COLUMNS,
            LookupTableIDs,
        >(domain, &srs, &constraints, inputs, &mut rng)
        .unwrap();

        // verify the proof
        let verifies =
            verify::<_, OpeningProof, BaseSponge, ScalarSponge, TEST_N_COLUMNS, 0, LookupTableIDs>(
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

        // Trusted setup toxic waste
        let x = Fp::rand(&mut rng);

        let mut srs: PairingSRS<BN254> = PairingSRS::create(x, domain.d1.size as usize);
        srs.full_srs.add_lagrange_basis(domain.d1);

        let mut constraint_env = TestConstraintBuilderEnv::<Fp>::empty();
        ffa_interpreter::constrain_multiplication(&mut constraint_env);
        let constraints = constraint_env.constraints;

        let mut witness_env = TestWitnessBuilderEnv::<Fp>::empty();
        gen_random_mul_witness(&mut witness_env, &mut rng);
        let inputs = witness_env.get_witness(domain_size);

        // generate the proof
        let proof = prove::<
            _,
            OpeningProof,
            BaseSponge,
            ScalarSponge,
            Column,
            _,
            TEST_N_COLUMNS,
            LookupTableIDs,
        >(domain, &srs, &constraints, inputs, &mut rng)
        .unwrap();

        let mut witness_env_prime = TestWitnessBuilderEnv::<Fp>::empty();
        gen_random_mul_witness(&mut witness_env_prime, &mut rng);
        let inputs_prime = witness_env_prime.get_witness(domain_size);

        // generate another (prime) proof
        let proof_prime = prove::<
            _,
            OpeningProof,
            BaseSponge,
            ScalarSponge,
            Column,
            _,
            TEST_N_COLUMNS,
            LookupTableIDs,
        >(domain, &srs, &constraints, inputs_prime, &mut rng)
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
                0,
                LookupTableIDs,
            >(
                domain,
                &srs,
                &constraints,
                &proof_clone,
                Witness::zero_vec(domain_size),
            );
            assert!(!verifies);
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
                0,
                LookupTableIDs,
            >(
                domain,
                &srs,
                &constraints,
                &proof_clone,
                Witness::zero_vec(domain_size),
            );
            assert!(!verifies);
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
                0,
                LookupTableIDs,
            >(
                domain,
                &srs,
                &constraints,
                &proof_clone,
                Witness::zero_vec(domain_size),
            );
            assert!(!verifies);
        }
    }

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
        let proof =
            prove::<_, OpeningProof, BaseSponge, ScalarSponge, Column, _, N, LookupTableIDs>(
                domain,
                &srs,
                &constraints,
                inputs,
                &mut rng,
            )
            .unwrap();
        let verifies = verify::<_, OpeningProof, BaseSponge, ScalarSponge, N, 0, LookupTableIDs>(
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
