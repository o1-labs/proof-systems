pub mod columns;
pub mod interpreter;
pub mod lookups;

#[cfg(test)]
mod tests {

    use crate::{
        circuit_design::{ConstraintBuilderEnv, WitnessBuilderEnv},
        columns::ColumnIndexer,
        fec::{
            columns::{FECColumn, FEC_N_COLUMNS},
            interpreter::{constrain_ec_addition, ec_add_circuit},
            lookups::LookupTable,
        },
        logup::LookupTableID,
        Ff1, Fp,
    };
    use ark_ff::UniformRand;
    use rand::{CryptoRng, RngCore};
    use std::collections::BTreeMap;

    type FECWitnessBuilderEnv = WitnessBuilderEnv<
        Fp,
        FECColumn,
        { <FECColumn as ColumnIndexer>::N_COL },
        { <FECColumn as ColumnIndexer>::N_COL },
        0,
        0,
        LookupTable<Ff1>,
    >;

    fn build_fec_addition_circuit<RNG: RngCore + CryptoRng>(
        rng: &mut RNG,
        domain_size: usize,
    ) -> FECWitnessBuilderEnv {
        let mut witness_env = WitnessBuilderEnv::create();

        // To support less rows than domain_size we need to have selectors.
        //let row_num = rng.gen_range(0..domain_size);

        for row_i in 0..domain_size {
            let xp: Ff1 = <Ff1 as UniformRand>::rand(rng);
            let yp: Ff1 = <Ff1 as UniformRand>::rand(rng);
            let xq: Ff1 = <Ff1 as UniformRand>::rand(rng);
            let yq: Ff1 = <Ff1 as UniformRand>::rand(rng);

            ec_add_circuit(&mut witness_env, xp, yp, xq, yq);
            if row_i < domain_size - 1 {
                witness_env.next_row();
            }
        }

        witness_env
    }

    #[test]
    /// Builds the FF addition circuit with random values. The witness
    /// environment enforces the constraints internally, so it is
    /// enough to just build the circuit to ensure it is satisfied.
    pub fn test_fec_addition_circuit() {
        let mut rng = o1_utils::tests::make_test_rng();
        build_fec_addition_circuit(&mut rng, 1 << 4);
    }

    #[test]
    pub fn test_fec_completeness() {
        let mut rng = o1_utils::tests::make_test_rng();
        let domain_size = 1 << 15; // Otherwise we can't do 15-bit lookups.

        let mut constraint_env = ConstraintBuilderEnv::<Fp, LookupTable<Ff1>>::create();
        constrain_ec_addition::<Fp, Ff1, _>(&mut constraint_env);
        let constraints = constraint_env.get_constraints();

        let witness_env = build_fec_addition_circuit(&mut rng, domain_size);

        // Fixed tables can be generated inside lookup_tables_data. Runtime should be generated here.
        let mut lookup_tables_data = BTreeMap::new();
        for table_id in LookupTable::<Ff1>::all_variants().into_iter() {
            lookup_tables_data.insert(table_id, table_id.entries(domain_size as u64));
        }
        let proof_inputs = witness_env.get_proof_inputs(domain_size, lookup_tables_data);

        crate::test::test_completeness_generic::<
            FEC_N_COLUMNS,
            FEC_N_COLUMNS,
            0,
            0,
            LookupTable<Ff1>,
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
