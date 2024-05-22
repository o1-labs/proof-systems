/// Generic test runners for prover/verifier.
use crate::{
    expr::E, logup::LookupTableID, lookups::LookupTableIDs, proof::ProofInputs, prover::prove,
    verifier::verify, witness::Witness, BaseSponge, Fp, OpeningProof, ScalarSponge, BN254,
};
use ark_ff::Zero;
use kimchi::circuits::domains::EvaluationDomains;
use poly_commitment::pairing_proof::PairingSRS;
use rand::{CryptoRng, RngCore};

/// No lookups, no selectors, only witness column. `N_WIT == N_REL`.
pub fn test_completeness_generic_only_relation<const N_REL: usize, RNG>(
    constraints: Vec<E<Fp>>,
    evaluations: Witness<N_REL, Vec<Fp>>,
    domain_size: usize,
    rng: &mut RNG,
) where
    RNG: RngCore + CryptoRng,
{
    let proof_inputs = ProofInputs {
        evaluations,
        logups: vec![],
    };
    test_completeness_generic::<N_REL, N_REL, 0, 0, LookupTableIDs, _>(
        constraints,
        Box::new([]),
        proof_inputs,
        domain_size,
        rng,
    )
}

pub fn test_completeness_generic_no_lookups<
    const N_WIT: usize,
    const N_REL: usize,
    const N_DSEL: usize,
    const N_FSEL: usize,
    RNG,
>(
    constraints: Vec<E<Fp>>,
    fixed_selectors: Box<[Vec<Fp>; N_FSEL]>,
    evaluations: Witness<N_WIT, Vec<Fp>>,
    domain_size: usize,
    rng: &mut RNG,
) where
    RNG: RngCore + CryptoRng,
{
    let proof_inputs = ProofInputs {
        evaluations,
        logups: vec![],
    };
    test_completeness_generic::<N_WIT, N_REL, N_DSEL, N_FSEL, LookupTableIDs, _>(
        constraints,
        fixed_selectors,
        proof_inputs,
        domain_size,
        rng,
    )
}

// Generic function to test with different circuits with the generic prover/verifier.
// It doesn't use the interpreter to build the witness and compute the constraints.
pub fn test_completeness_generic<
    const N_WIT: usize,
    const N_REL: usize,
    const N_DSEL: usize,
    const N_FSEL: usize,
    LT: LookupTableID,
    RNG,
>(
    constraints: Vec<E<Fp>>,
    fixed_selectors: Box<[Vec<Fp>; N_FSEL]>,
    proof_inputs: ProofInputs<N_WIT, Fp, LT>,
    domain_size: usize,
    rng: &mut RNG,
) where
    RNG: RngCore + CryptoRng,
{
    let domain = EvaluationDomains::<Fp>::create(domain_size).unwrap();

    let srs: PairingSRS<BN254> = crate::precomputed_srs::get_bn254_srs(domain);

    let proof =
        prove::<_, OpeningProof, BaseSponge, ScalarSponge, _, N_WIT, N_REL, N_DSEL, N_FSEL, LT>(
            domain,
            &srs,
            &constraints,
            fixed_selectors.clone(),
            proof_inputs.clone(),
            rng,
        )
        .unwrap();

    {
        // Checking the proof size. We should have:
        // - N commitments for the columns
        // - N evaluations for the columns
        // - MAX_DEGREE - 1 commitments for the constraints (quotient polynomial)
        // TODO: add lookups

        // We check there is always only one commitment chunk
        (&proof.proof_comms.witness_comms)
            .into_iter()
            .for_each(|x| assert_eq!(x.len(), 1));
        // This equality is therefore trivial, but still doing it.
        assert!(
            (&proof.proof_comms.witness_comms)
                .into_iter()
                .fold(0, |acc, x| acc + x.len())
                == N_WIT
        );
        // Checking that none of the commitments are zero
        (&proof.proof_comms.witness_comms)
            .into_iter()
            .for_each(|v| v.elems.iter().for_each(|x| assert!(!x.is_zero())));

        // Checking the number of chunks of the quotient polynomial
        let max_degree = {
            if proof_inputs.logups.is_empty() {
                constraints
                    .iter()
                    .map(|expr| expr.degree(1, 0))
                    .max()
                    .unwrap_or(0)
            } else {
                8
            }
        };

        if max_degree == 1 {
            assert_eq!(proof.proof_comms.t_comm.len(), 1);
        } else {
            assert_eq!(proof.proof_comms.t_comm.len(), max_degree as usize - 1);
        }
    }

    let verifies =
        verify::<_, OpeningProof, BaseSponge, ScalarSponge, N_WIT, N_REL, N_DSEL, N_FSEL, 0, LT>(
            domain,
            &srs,
            &constraints,
            fixed_selectors,
            &proof,
            Witness::zero_vec(domain_size),
        );
    assert!(verifies)
}

pub fn test_soundness_generic<
    const N_WIT: usize,
    const N_REL: usize,
    const N_DSEL: usize,
    const N_FSEL: usize,
    LT: LookupTableID,
    RNG,
>(
    constraints: Vec<E<Fp>>,
    fixed_selectors: Box<[Vec<Fp>; N_FSEL]>,
    proof_inputs: ProofInputs<N_WIT, Fp, LT>,
    proof_inputs_prime: ProofInputs<N_WIT, Fp, LT>,
    domain_size: usize,
    rng: &mut RNG,
) where
    RNG: RngCore + CryptoRng,
{
    let domain = EvaluationDomains::<Fp>::create(domain_size).unwrap();

    let srs: PairingSRS<BN254> = crate::precomputed_srs::get_bn254_srs(domain);

    // generate the proof
    let proof =
        prove::<_, OpeningProof, BaseSponge, ScalarSponge, _, N_WIT, N_REL, N_DSEL, N_FSEL, LT>(
            domain,
            &srs,
            &constraints,
            fixed_selectors.clone(),
            proof_inputs,
            rng,
        )
        .unwrap();

    // generate another (prime) proof
    let proof_prime =
        prove::<_, OpeningProof, BaseSponge, ScalarSponge, _, N_WIT, N_REL, N_DSEL, N_FSEL, LT>(
            domain,
            &srs,
            &constraints,
            fixed_selectors.clone(),
            proof_inputs_prime,
            rng,
        )
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
            N_WIT,
            N_REL,
            N_DSEL,
            N_FSEL,
            0,
            LT,
        >(
            domain,
            &srs,
            &constraints,
            fixed_selectors.clone(),
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
            N_WIT,
            N_REL,
            N_DSEL,
            N_FSEL,
            0,
            LT,
        >(
            domain,
            &srs,
            &constraints,
            fixed_selectors.clone(),
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
            N_WIT,
            N_REL,
            N_DSEL,
            N_FSEL,
            0,
            LT,
        >(
            domain,
            &srs,
            &constraints,
            fixed_selectors,
            &proof_clone,
            Witness::zero_vec(domain_size),
        );
        assert!(!verifies, "Proof with a swapped witness eval must fail");
    }
}
