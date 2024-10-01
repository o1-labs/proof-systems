#[cfg(test)]
mod tests {
    use crate::{
        lookups::{Lookup, LookupTableIDs},
        proof::ProofInputs,
        prover::prove,
        verifier::verify,
        witness::Witness,
        BaseSponge, Fp, OpeningProof, ScalarSponge, BN254,
    };
    use ark_ff::UniformRand;
    use kimchi::circuits::domains::EvaluationDomains;
    use poly_commitment::{kzg::PairingSRS, SRS as _};

    // Number of columns
    const LOOKUP_TEST_N_COL: usize = 10;

    #[test]
    #[ignore]
    fn test_soundness_logup() {
        let mut rng = o1_utils::tests::make_test_rng(None);

        // We generate two different witness and two different proofs.
        let domain_size = 1 << 8;
        let domain = EvaluationDomains::<Fp>::create(domain_size).unwrap();

        let mut srs: PairingSRS<BN254> = {
            let toxic_waste = Fp::rand(&mut rng);
            unsafe { PairingSRS::create(toxic_waste, domain.d1.size as usize) }
        };
        srs.full_srs.add_lagrange_basis(domain.d1);

        let mut inputs = ProofInputs::random(domain);
        let constraints = vec![];
        // Take one random f_i (FIXME: taking first one for now)
        let test_table_id = *inputs.logups.first_key_value().unwrap().0;
        let looked_up_values = inputs.logups.get_mut(&test_table_id).unwrap().f[0].clone();
        // We change a random looked up element (FIXME: first one for now)
        let wrong_looked_up_value = Lookup {
            table_id: looked_up_values[0].table_id,
            numerator: looked_up_values[0].numerator,
            value: vec![Fp::rand(&mut rng)],
        };
        // Overwriting the first looked up value
        inputs.logups.get_mut(&test_table_id).unwrap().f[0][0] = wrong_looked_up_value;
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
            0,
            LookupTableIDs,
        >(domain, &srs, &constraints, Box::new([]), inputs, &mut rng)
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
            0,
            LookupTableIDs,
        >(
            domain,
            &srs,
            &constraints,
            Box::new([]),
            &proof,
            Witness::zero_vec(domain_size),
        );
        // FIXME: At the moment, it does verify. It should not. We are missing constraints.
        assert!(!verifies);
    }
}
