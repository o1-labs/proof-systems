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
    use ark_ec::AffineCurve;
    use ark_ff::UniformRand;
    use rand::{CryptoRng, RngCore};
    use std::collections::{BTreeMap, HashMap};

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
        use mina_curves::pasta::{Fp, Pallas};

        let mut witness_env = WitnessBuilderEnv::create();

        // To support less rows than domain_size we need to have selectors.
        //let row_num = rng.gen_range(0..domain_size);

        let gen = Pallas::prime_subgroup_generator();
        let kp: Fp = UniformRand::rand(rng);
        let p: Pallas = gen.mul(kp).into();
        let px: Ff1 = p.x;
        let py: Ff1 = p.y;

        for row_i in 0..domain_size {
            let kq: Fp = UniformRand::rand(rng);
            let q: Pallas = gen.mul(kq).into();

            let qx: Ff1 = q.x;
            let qy: Ff1 = q.y;

            let (rx, ry) = ec_add_circuit(&mut witness_env, px, py, qx, qy);

            let r: Pallas =
                ark_ec::models::short_weierstrass_jacobian::GroupAffine::new(rx, ry, false);

            assert!(
                r == p + q,
                "fec addition circuit does not compute actual p + q, expected {} got {r:?}",
                p + q
            );

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
        let mut rng = o1_utils::tests::make_test_rng(None);
        build_fec_addition_circuit(&mut rng, 1 << 4);
    }

    #[test]
    pub fn test_regression_relation_constraints_fec() {
        let mut constraint_env = ConstraintBuilderEnv::<Fp, LookupTable<Ff1>>::create();
        constrain_ec_addition::<Fp, Ff1, _>(&mut constraint_env);
        let constraints = constraint_env.get_relation_constraints();

        let mut constraints_degrees = HashMap::new();

        assert_eq!(constraints.len(), 36);

        {
            constraints.iter().for_each(|c| {
                let degree = c.degree(1, 0);
                *constraints_degrees.entry(degree).or_insert(0) += 1;
            });

            assert_eq!(constraints_degrees.get(&1), None);
            assert_eq!(constraints_degrees.get(&2), Some(&36));
            assert_eq!(constraints_degrees.get(&3), None);

            assert!(constraints.iter().map(|c| c.degree(1, 0)).max() <= Some(3));
        }
    }

    #[test]
    pub fn test_regression_constraints_fec() {
        let mut constraint_env = ConstraintBuilderEnv::<Fp, LookupTable<Ff1>>::create();
        constrain_ec_addition::<Fp, Ff1, _>(&mut constraint_env);
        let constraints = constraint_env.get_constraints();

        let mut constraints_degrees = HashMap::new();

        assert_eq!(constraints.len(), 75);

        {
            constraints.iter().for_each(|c| {
                let degree = c.degree(1, 0);
                *constraints_degrees.entry(degree).or_insert(0) += 1;
            });

            assert_eq!(constraints_degrees.get(&1), Some(&1));
            assert_eq!(constraints_degrees.get(&2), Some(&38));
            assert_eq!(constraints_degrees.get(&3), None);
            assert_eq!(constraints_degrees.get(&4), None);
            assert_eq!(constraints_degrees.get(&5), Some(&2));
            assert_eq!(constraints_degrees.get(&6), None);
            assert_eq!(constraints_degrees.get(&7), Some(&34));
        }
    }

    #[test]
    pub fn test_fec_completeness() {
        let mut rng = o1_utils::tests::make_test_rng(None);
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
