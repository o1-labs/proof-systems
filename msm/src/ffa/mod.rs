pub mod columns;
pub mod interpreter;
pub mod lookups;

#[cfg(test)]
mod tests {

    use crate::{
        circuit_design::{ConstraintBuilderEnv, WitnessBuilderEnv},
        columns::ColumnIndexer,
        ffa::{
            columns::{FFAColumn, FFA_N_COLUMNS},
            interpreter::{self as ffa_interpreter},
            lookups::LookupTable,
        },
        logup::LookupTableID,
        precomputed_srs::get_bn254_srs,
        prover::prove,
        verifier::verify,
        witness::Witness,
        BaseSponge, Ff1, Fp, OpeningProof, ScalarSponge, BN254,
    };
    use ark_ff::UniformRand;
    use kimchi::circuits::domains::EvaluationDomains;
    use poly_commitment::pairing_proof::PairingSRS;
    use rand::{CryptoRng, RngCore};
    use std::collections::BTreeMap;

    /// Builds the FF addition circuit with random values. The witness
    /// environment enforces the constraints internally, so it is
    /// enough to just build the circuit to ensure it is satisfied.
    fn build_ffa_circuit<RNG: RngCore + CryptoRng>(
        rng: &mut RNG,
        domain_size: usize,
    ) -> WitnessBuilderEnv<Fp, { <FFAColumn as ColumnIndexer>::COL_N }, LookupTable> {
        let mut witness_env =
            WitnessBuilderEnv::<Fp, { <FFAColumn as ColumnIndexer>::COL_N }, LookupTable>::create();

        for _row_i in 0..domain_size {
            let a: Ff1 = <Ff1 as UniformRand>::rand(rng);
            let b: Ff1 = <Ff1 as UniformRand>::rand(rng);

            //use rand::Rng;
            //let a: Ff1 = From::from(rng.gen_range(0..(1 << 50)));
            //let b: Ff1 = From::from(rng.gen_range(0..(1 << 50)));
            ffa_interpreter::ff_addition_circuit(&mut witness_env, a, b);
            witness_env.next_row();
        }

        witness_env
    }

    #[test]
    /// Tests if FFA circuit is valid.
    pub fn test_ffa_circuit() {
        let mut rng = o1_utils::tests::make_test_rng();
        build_ffa_circuit(&mut rng, 1 << 4);
    }

    #[test]
    pub fn test_ffa_completeness() {
        let mut rng = o1_utils::tests::make_test_rng();
        let domain_size = 1 << 15; // Otherwise we can't do 15-bit lookups.
        let domain = EvaluationDomains::<Fp>::create(domain_size).unwrap();

        let srs: PairingSRS<BN254> = get_bn254_srs(domain);

        let mut constraint_env = ConstraintBuilderEnv::<Fp, LookupTable>::create();
        ffa_interpreter::constrain_ff_addition(&mut constraint_env);
        let constraints = constraint_env.get_constraints();

        let witness_env = build_ffa_circuit(&mut rng, domain_size);

        // Fixed tables can be generated inside lookup_tables_data. Runtime should be generated here.
        let mut lookup_tables_data = BTreeMap::new();
        for table_id in LookupTable::all_variants().into_iter() {
            lookup_tables_data.insert(table_id, table_id.entries(domain.d1.size));
        }
        let proof_inputs = witness_env.get_proof_inputs(domain, lookup_tables_data);

        // generate the proof
        let proof = prove::<
            _,
            OpeningProof,
            BaseSponge,
            ScalarSponge,
            _,
            FFA_N_COLUMNS,
            FFA_N_COLUMNS,
            0,
            _,
        >(domain, &srs, &constraints, proof_inputs, &mut rng)
        .unwrap();

        // verify the proof
        let verifies = verify::<
            _,
            OpeningProof,
            BaseSponge,
            ScalarSponge,
            FFA_N_COLUMNS,
            FFA_N_COLUMNS,
            0,
            0,
            _,
        >(
            domain,
            &srs,
            &constraints,
            &proof,
            Witness::zero_vec(domain_size),
        );

        assert!(verifies, "Proof must verify");
    }
}
