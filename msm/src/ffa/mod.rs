pub mod columns;
pub mod interpreter;
pub mod lookups;

#[cfg(test)]
mod tests {

    use crate::{
        circuit_design::{ConstraintBuilderEnv, WitnessBuilderEnv},
        columns::ColumnIndexer,
        ffa::{
            columns::FFAColumn,
            interpreter::{self as ffa_interpreter},
            lookups::LookupTable,
        },
        logup::LookupTableID,
        Ff1, Fp,
    };
    use ark_ff::UniformRand;
    use rand::{CryptoRng, RngCore};
    use std::collections::BTreeMap;

    type FFAWitnessBuilderEnv = WitnessBuilderEnv<
        Fp,
        FFAColumn,
        { <FFAColumn as ColumnIndexer<usize>>::N_COL },
        { <FFAColumn as ColumnIndexer<usize>>::N_COL },
        0,
        0,
        LookupTable,
    >;

    /// Builds the FF addition circuit with random values. The witness
    /// environment enforces the constraints internally, so it is
    /// enough to just build the circuit to ensure it is satisfied.
    fn build_ffa_circuit<RNG: RngCore + CryptoRng>(
        rng: &mut RNG,
        domain_size: usize,
    ) -> FFAWitnessBuilderEnv {
        let mut witness_env = FFAWitnessBuilderEnv::create();

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
        let mut rng = o1_utils::tests::make_test_rng(None);
        build_ffa_circuit(&mut rng, 1 << 4);
    }

    #[test]
    pub fn heavy_test_ffa_completeness() {
        let mut rng = o1_utils::tests::make_test_rng(None);
        let domain_size = 1 << 15; // Otherwise we can't do 15-bit lookups.

        let mut constraint_env = ConstraintBuilderEnv::<Fp, LookupTable>::create();
        ffa_interpreter::constrain_ff_addition(&mut constraint_env);
        let constraints = constraint_env.get_constraints();

        let witness_env = build_ffa_circuit(&mut rng, domain_size);

        // Fixed tables can be generated inside lookup_tables_data. Runtime should be generated here.
        let mut lookup_tables_data = BTreeMap::new();
        for table_id in LookupTable::all_variants().into_iter() {
            lookup_tables_data.insert(
                table_id,
                vec![table_id
                    .entries(domain_size as u64)
                    .into_iter()
                    .map(|x| vec![x])
                    .collect()],
            );
        }
        let proof_inputs = witness_env.get_proof_inputs(domain_size, lookup_tables_data);

        crate::test::test_completeness_generic::<
            { <FFAColumn as ColumnIndexer<usize>>::N_COL },
            { <FFAColumn as ColumnIndexer<usize>>::N_COL },
            0,
            0,
            LookupTable,
            _,
        >(
            constraints,
            Box::new([]),
            proof_inputs,
            domain_size,
            &mut rng,
        );
    }
}
