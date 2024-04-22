pub mod columns;
pub mod constraint;
pub mod interpreter;
pub mod witness;

#[cfg(test)]
mod tests {

    use std::collections::BTreeMap;

    use crate::{
        columns::Column,
        fec::{
            columns::FEC_N_COLUMNS,
            constraint::ConstraintBuilderEnv as FECConstraintBuilderEnv,
            interpreter::{self as fec_interpreter, FECInterpreterEnv},
            witness::WitnessBuilderEnv as FECWitnessBuilderEnv,
        },
        logup,
        lookups::LookupTableIDs,
        prover::prove,
        verifier::verify,
        witness::Witness,
        BaseSponge, Ff1, Fp, OpeningProof, ScalarSponge, BN254,
    };
    use ark_ff::UniformRand;
    use kimchi::circuits::domains::EvaluationDomains;
    use poly_commitment::pairing_proof::PairingSRS;
    use rand::Rng;

    fn build_foreign_field_addition_circuit(domain_size: usize) -> FECWitnessBuilderEnv<Fp> {
        let mut rng = o1_utils::tests::make_test_rng();

        let mut witness_env = FECWitnessBuilderEnv::<Fp>::empty();

        let row_num = rng.gen_range(0..domain_size);

        for _row_i in 0..row_num {
            let xp: Ff1 = <Ff1 as UniformRand>::rand(&mut rng);
            let yp: Ff1 = <Ff1 as UniformRand>::rand(&mut rng);
            let xq: Ff1 = <Ff1 as UniformRand>::rand(&mut rng);
            let yq: Ff1 = <Ff1 as UniformRand>::rand(&mut rng);

            fec_interpreter::ec_add_circuit(&mut witness_env, 0, xp, yp, xq, yq);
            witness_env.next_row();
        }

        witness_env
    }

    #[test]
    /// Builds the FF addition circuit with random values. The witness
    /// environment enforces the constraints internally, so it is
    /// enough to just build the circuit to ensure it is satisfied.
    pub fn test_foreign_field_addition_circuit() {
        build_foreign_field_addition_circuit(1 << 4);
    }

    #[test]
    pub fn test_fec_completeness() {
        let mut rng = o1_utils::tests::make_test_rng();
        let domain_size = 1 << 8;
        let domain = EvaluationDomains::<Fp>::create(domain_size).unwrap();

        let srs_trapdoor = Fp::rand(&mut rng);
        let mut srs: PairingSRS<BN254> = PairingSRS::create(srs_trapdoor, domain.d1.size as usize);
        srs.full_srs.add_lagrange_basis(domain.d1);

        let mut constraint_env = FECConstraintBuilderEnv::<Fp>::empty();
        let witness_env = build_foreign_field_addition_circuit(domain_size);

        fec_interpreter::constrain_ec_addition::<Fp, Ff1, _>(&mut constraint_env, 0);

        let inputs = witness_env.get_witness(domain_size);
        // FIXME: remove clone
        let fixed_lookup_tables = if inputs.logups.is_some() {
            inputs.logups.clone().unwrap().fixed_lookup_tables.clone()
        } else {
            BTreeMap::new()
        };
        let constraints = constraint_env.constraints;

        // generate the proof
        let proof = prove::<
            _,
            OpeningProof,
            BaseSponge,
            ScalarSponge,
            Column,
            _,
            FEC_N_COLUMNS,
            LookupTableIDs,
        >(domain, &srs, &constraints, inputs, &mut rng)
        .unwrap();

        let public_inputs = Witness::zero_vec(domain_size);
        let logup_index: Option<logup::verifier::Index<_, LookupTableIDs>> =
            Some(logup::verifier::Index {
                fixed_lookup_tables,
            });

        // verify the proof
        let verifies =
            verify::<_, OpeningProof, BaseSponge, ScalarSponge, FEC_N_COLUMNS, 0, LookupTableIDs>(
                domain,
                &srs,
                &constraints,
                public_inputs,
                logup_index,
                &proof,
            );

        assert!(verifies);
    }
}
