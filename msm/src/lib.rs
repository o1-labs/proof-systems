use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use poly_commitment::pairing_proof::PairingProof;

pub use mvlookup::{
    LookupProof as MVLookupProof, LookupTable as MVLookupTable, LookupTableID as MVLookupTableID,
    LookupTableID, MVLookup, MVLookupWitness,
};

pub mod column_env;
pub mod columns;
pub mod expr;
/// Instantiations of MVLookups for the MSM project
pub mod lookups;
/// Generic definitions of MVLookups
pub mod mvlookup;
pub mod precomputed_srs;
pub mod proof;
pub mod prover;
pub mod verifier;
pub mod witness;

pub mod ffa;
pub mod serialization;

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
        verifier::verify,
        BaseSponge, Fp, OpeningProof, ScalarSponge, BN254,
    };
    use ark_ff::UniformRand;
    use kimchi::circuits::domains::EvaluationDomains;
    use poly_commitment::pairing_proof::PairingSRS;

    // Number of columns
    const N: usize = 10;

    #[test]
    fn test_completeness() {
        let mut rng = o1_utils::tests::make_test_rng();

        // Include tests for completeness for MVLookup as the random witness
        // includes all arguments
        let domain_size = 1 << 8;
        let domain = EvaluationDomains::<Fp>::create(domain_size).unwrap();

        // Trusted setup toxic waste
        let x = Fp::rand(&mut rng);

        let mut srs: PairingSRS<BN254> = PairingSRS::create(x, domain.d1.size as usize);
        srs.full_srs.add_lagrange_basis(domain.d1);

        let inputs = ProofInputs::random(domain);
        let constraints: Vec<_> = vec![];

        // generate the proof
        let proof = prove::<_, OpeningProof, BaseSponge, ScalarSponge, Column, _, N, LookupTableIDs>(
            domain,
            &srs,
            &constraints,
            inputs,
            &mut rng,
        );

        // verify the proof
        let verifies = verify::<_, OpeningProof, BaseSponge, ScalarSponge, N>(
            domain,
            &srs,
            &constraints,
            &proof,
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

        let inputs = ProofInputs::random(domain);
        let constraints = vec![];
        // generate the proof
        let proof = prove::<_, OpeningProof, BaseSponge, ScalarSponge, Column, _, N, LookupTableIDs>(
            domain,
            &srs,
            &constraints,
            inputs,
            &mut rng,
        );

        let inputs_prime = ProofInputs::random(domain);
        let proof_prime =
            prove::<_, OpeningProof, BaseSponge, ScalarSponge, Column, _, N, LookupTableIDs>(
                domain,
                &srs,
                &constraints,
                inputs_prime,
                &mut rng,
            );

        // Swap the opening proof. The verification should fail.
        {
            let mut proof_clone = proof.clone();
            proof_clone.opening_proof = proof_prime.opening_proof;
            let verifies = verify::<_, OpeningProof, BaseSponge, ScalarSponge, N>(
                domain,
                &srs,
                &constraints,
                &proof_clone,
            );
            assert!(!verifies);
        }

        // Changing at least one commitment in the proof should fail the verification.
        // TODO: improve me by swapping only one commitments. It should be
        // easier when an index trait is implemented.
        {
            let mut proof_clone = proof.clone();
            proof_clone.proof_comms = proof_prime.proof_comms;
            let verifies = verify::<_, OpeningProof, BaseSponge, ScalarSponge, N>(
                domain,
                &srs,
                &constraints,
                &proof_clone,
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
            let verifies = verify::<_, OpeningProof, BaseSponge, ScalarSponge, N>(
                domain,
                &srs,
                &constraints,
                &proof_clone,
            );
            assert!(!verifies);
        }
    }

    #[test]
    #[ignore]
    fn test_soundness_mvlookup() {
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
        let looked_up_values = inputs.mvlookups[0].f[0].clone();
        // We change a random looked up element (FIXME: first one for now)
        let wrong_looked_up_value = Lookup {
            table_id: looked_up_values[0].table_id,
            numerator: looked_up_values[0].numerator,
            value: vec![Fp::rand(&mut rng)],
        };
        // Overwriting the first looked up value
        inputs.mvlookups[0].f[0][0] = wrong_looked_up_value;
        // generate the proof
        let proof = prove::<_, OpeningProof, BaseSponge, ScalarSponge, Column, _, N, LookupTableIDs>(
            domain,
            &srs,
            &constraints,
            inputs,
            &mut rng,
        );
        let verifies = verify::<_, OpeningProof, BaseSponge, ScalarSponge, N>(
            domain,
            &srs,
            &constraints,
            &proof,
        );
        // FIXME: At the moment, it does verify. It should not. We are missing constraints.
        assert!(!verifies);
    }
}
