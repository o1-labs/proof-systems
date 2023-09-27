use super::framework::{print_witness, TestFramework};
use crate::circuits::{
    gate::{CircuitGate, GateType},
    lookup::{
        runtime_tables::{RuntimeTable, RuntimeTableCfg},
        tables::LookupTable,
    },
    polynomial::COLUMNS,
    wires::Wire,
};
use ark_ff::{UniformRand, Zero};
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use rand::Rng;
use std::array;

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

fn setup_lookup_proof(use_values_from_table: bool, num_lookups: usize, table_sizes: Vec<usize>) {
    let lookup_table_values: Vec<Vec<_>> = table_sizes
        .iter()
        .map(|size| (0..*size).map(|_| rand::random()).collect())
        .collect();
    let lookup_tables = lookup_table_values
        .iter()
        .enumerate()
        .map(|(id, lookup_table_values)| {
            let index_column = (0..lookup_table_values.len() as u64)
                .map(Into::into)
                .collect();
            LookupTable {
                id: id as i32,
                data: vec![index_column, lookup_table_values.clone()],
            }
        })
        .collect();

    // circuit gates
    let gates = (0..num_lookups)
        .map(|i| CircuitGate::new(GateType::Lookup, Wire::for_row(i), vec![]))
        .collect();

    let witness = {
        let mut lookup_table_ids = Vec::with_capacity(num_lookups);
        let mut lookup_indexes: [_; 3] = array::from_fn(|_| Vec::with_capacity(num_lookups));
        let mut lookup_values: [_; 3] = array::from_fn(|_| Vec::with_capacity(num_lookups));
        let unused = || vec![Fp::zero(); num_lookups];

        let num_tables = table_sizes.len();
        let mut tables_used = std::collections::HashSet::new();
        for _ in 0..num_lookups {
            let table_id = rand::random::<usize>() % num_tables;
            tables_used.insert(table_id);
            let lookup_table_values: &Vec<Fp> = &lookup_table_values[table_id];
            lookup_table_ids.push((table_id as u64).into());
            for i in 0..3 {
                let index = rand::random::<usize>() % lookup_table_values.len();
                let value = if use_values_from_table {
                    lookup_table_values[index]
                } else {
                    rand::random()
                };
                lookup_indexes[i].push((index as u64).into());
                lookup_values[i].push(value);
            }
        }

        // Sanity check: if we were given multiple tables, we should have used multiple tables,
        // assuming we're generating enough gates.
        assert!(tables_used.len() >= 2 || table_sizes.len() <= 1);

        let [lookup_indexes0, lookup_indexes1, lookup_indexes2] = lookup_indexes;
        let [lookup_values0, lookup_values1, lookup_values2] = lookup_values;
        [
            lookup_table_ids,
            lookup_indexes0,
            lookup_values0,
            lookup_indexes1,
            lookup_values1,
            lookup_indexes2,
            lookup_values2,
            unused(),
            unused(),
            unused(),
            unused(),
            unused(),
            unused(),
            unused(),
            unused(),
        ]
    };

    TestFramework::<Vesta>::default()
        .gates(gates)
        .witness(witness)
        .lookup_tables(lookup_tables)
        .setup()
        .prove_and_verify::<BaseSponge, ScalarSponge>()
        .unwrap();
}

#[test]
fn lookup_gate_proving_works() {
    setup_lookup_proof(true, 500, vec![256])
}

#[test]
#[should_panic]
fn lookup_gate_rejects_bad_lookups() {
    setup_lookup_proof(false, 500, vec![256])
}

#[test]
fn lookup_gate_proving_works_multiple_tables() {
    setup_lookup_proof(true, 500, vec![100, 50, 50, 2, 2])
}

#[test]
#[should_panic]
fn lookup_gate_rejects_bad_lookups_multiple_tables() {
    setup_lookup_proof(false, 500, vec![100, 50, 50, 2, 2])
}

fn setup_successfull_runtime_table_test(
    runtime_table_cfgs: Vec<RuntimeTableCfg<Fp>>,
    runtime_tables: Vec<RuntimeTable<Fp>>,
    lookups: Vec<i32>,
) {
    let mut rng = rand::thread_rng();
    let nb_lookups = lookups.len();

    // circuit
    let mut gates = vec![];
    for row in 0..nb_lookups {
        gates.push(CircuitGate::new(
            GateType::Lookup,
            Wire::for_row(row),
            vec![],
        ));
    }

    // witness
    let witness = {
        let mut cols: [_; COLUMNS] = array::from_fn(|_col| vec![Fp::zero(); gates.len()]);

        // only the first 7 registers are used in the lookup gate
        let (lookup_cols, _rest) = cols.split_at_mut(7);

        for (i, table_id) in lookups.into_iter().enumerate() {
            lookup_cols[0][i] = Fp::from(table_id);
            let rt = runtime_table_cfgs
                .clone()
                .into_iter()
                .find(|rt_cfg| rt_cfg.id == table_id)
                .unwrap();
            let len_rt = rt.len();
            let first_column = rt.first_column;
            let data = runtime_tables
                .clone()
                .into_iter()
                .find(|rt| rt.id == table_id)
                .unwrap()
                .data;

            // create queries into our runtime lookup table.
            // We will set [w1, w2], [w3, w4] and [w5, w6] to randon indexes and
            // the corresponding values
            let lookup_cols = &mut lookup_cols[1..];
            for chunk in lookup_cols.chunks_mut(2) {
                let idx = rng.gen_range(0..len_rt);
                chunk[0][i] = first_column[idx];
                chunk[1][i] = data[idx];
            }
        }
        cols
    };

    // run test
    TestFramework::<Vesta>::default()
        .gates(gates)
        .witness(witness)
        .runtime_tables_setup(runtime_table_cfgs)
        .setup()
        .runtime_tables(runtime_tables)
        .prove_and_verify::<BaseSponge, ScalarSponge>()
        .unwrap();
}

#[test]
fn test_runtime_table() {
    let num = 5;
    let mut rng = rand::thread_rng();

    let first_column = [8u32, 9, 8, 7, 1];
    let len = first_column.len();

    let mut runtime_tables_setup = vec![];
    for table_id in 0..num {
        let cfg = RuntimeTableCfg {
            id: table_id,
            first_column: first_column.into_iter().map(Into::into).collect(),
        };
        runtime_tables_setup.push(cfg);
    }

    let data: Vec<Fp> = [0u32, 2, 3, 4, 5].into_iter().map(Into::into).collect();
    let runtime_tables: Vec<RuntimeTable<Fp>> = runtime_tables_setup
        .iter()
        .map(|cfg| RuntimeTable {
            id: cfg.id(),
            data: data.clone(),
        })
        .collect();

    // circuit
    let mut gates = vec![];
    for row in 0..20 {
        gates.push(CircuitGate::new(
            GateType::Lookup,
            Wire::for_row(row),
            vec![],
        ));
    }

    // witness
    let witness = {
        let mut cols: [_; COLUMNS] = array::from_fn(|_col| vec![Fp::zero(); gates.len()]);

        // only the first 7 registers are used in the lookup gate
        let (lookup_cols, _rest) = cols.split_at_mut(7);

        for row in 0..20 {
            // the first register is the table id. We pick one random table.
            lookup_cols[0][row] = (rng.gen_range(0..num) as u32).into();

            // create queries into our runtime lookup table.
            // We will set [w1, w2], [w3, w4] and [w5, w6] to randon indexes and
            // the corresponding values
            let lookup_cols = &mut lookup_cols[1..];
            for chunk in lookup_cols.chunks_mut(2) {
                let idx = rng.gen_range(0..len);
                chunk[0][row] = first_column[idx].into();
                chunk[1][row] = data[idx];
            }
        }
        cols
    };

    print_witness(&witness, 0, 20);

    // run test
    TestFramework::<Vesta>::default()
        .gates(gates)
        .witness(witness)
        .runtime_tables_setup(runtime_tables_setup)
        .setup()
        .runtime_tables(runtime_tables)
        .prove_and_verify::<BaseSponge, ScalarSponge>()
        .unwrap();
}

#[test]
fn test_negative_test_runtime_table_value_not_in_table() {
    // We create 1 runtime table cfg
    let first_column = [8u32, 9, 8, 7, 1];

    let cfg = RuntimeTableCfg {
        id: 1,
        first_column: first_column.into_iter().map(Into::into).collect(),
    };

    let data: Vec<Fp> = [0u32, 2, 3, 4, 5].into_iter().map(Into::into).collect();
    let runtime_table: RuntimeTable<Fp> = RuntimeTable { id: cfg.id(), data };

    // circuit
    let mut gates = vec![];
    let nb_gates = 20;
    for row in 0..nb_gates {
        gates.push(CircuitGate::new(
            GateType::Lookup,
            Wire::for_row(row),
            vec![],
        ));
    }

    // witness. The whole witness is going to be wrong.
    let witness = {
        let mut cols: [_; COLUMNS] = array::from_fn(|_col| vec![Fp::zero(); nb_gates]);

        // only the first 7 registers are used in the lookup gate
        let (lookup_cols, _rest) = cols.split_at_mut(7);

        for row in 0..nb_gates {
            // the first register is the table id.
            lookup_cols[0][row] = 1.into();
            // create queries into our runtime lookup table.
            let lookup_cols = &mut lookup_cols[1..];
            for chunk in lookup_cols.chunks_mut(2) {
                // None of these values are correct
                chunk[0][row] = 42.into();
                chunk[1][row] = 42.into();
            }
        }
        cols
    };

    // run prover only as the error should be raised while creating the proof.
    let err = TestFramework::<Vesta>::default()
        .gates(gates)
        .witness(witness)
        .runtime_tables_setup(vec![cfg])
        .setup()
        .runtime_tables(vec![runtime_table])
        .prove::<BaseSponge, ScalarSponge>()
        .unwrap_err();

    // The whole witness is wrong, but we check the first row is incorrect as it
    // is the error returned by the prover call.
    assert_eq!(err, "the lookup failed to find a match in the table: row=0");
}

#[test]
fn test_negative_test_runtime_table_prover_with_undefined_id_in_index_and_witnesses_uses_correct_id(
) {
    // We create 1 runtime table cfg with ID 1
    let first_column = [8u32, 9, 8, 7, 1];

    let cfg = RuntimeTableCfg {
        id: 1,
        first_column: first_column.into_iter().map(Into::into).collect(),
    };

    // We give a different ID, not defined in the index.
    let data: Vec<Fp> = [0u32, 2, 3, 4, 5].into_iter().map(Into::into).collect();
    let runtime_table: RuntimeTable<Fp> = RuntimeTable { id: 2, data };

    // circuit
    let mut gates = vec![];
    let nb_gates = 20;
    for row in 0..nb_gates {
        gates.push(CircuitGate::new(
            GateType::Lookup,
            Wire::for_row(row),
            vec![],
        ));
    }

    // witness
    let witness = {
        let mut cols: [_; COLUMNS] = array::from_fn(|_col| vec![Fp::zero(); nb_gates]);

        // only the first 7 registers are used in the lookup gate
        let (lookup_cols, _rest) = cols.split_at_mut(7);

        for row in 0..nb_gates {
            // the first register is the table id. We set the index to the one
            // given while building the cs.
            lookup_cols[0][row] = 1.into();
            // We will set [w1, w2], [w3, w4] and [w5, w6] to correct values
            let lookup_cols = &mut lookup_cols[1..];
            for chunk in lookup_cols.chunks_mut(2) {
                chunk[0][row] = 8u32.into();
                chunk[1][row] = 0u32.into();
            }
        }
        cols
    };

    // We only run the prover. No need to verify.
    let err = TestFramework::<Vesta>::default()
        .gates(gates)
        .witness(witness)
        .runtime_tables_setup(vec![cfg])
        .setup()
        .runtime_tables(vec![runtime_table])
        .prove::<BaseSponge, ScalarSponge>()
        .unwrap_err();
    assert_eq!(
        err,
        "the runtime tables provided did not match the index's configuration"
    );
}

#[test]
fn test_negative_test_runtime_table_prover_uses_undefined_id_in_index_and_witnesses_too() {
    // We create 1 runtime table cfg with ID 1
    let first_column = [8u32, 9, 8, 7, 1];

    let cfg = RuntimeTableCfg {
        id: 1,
        first_column: first_column.into_iter().map(Into::into).collect(),
    };

    let data: Vec<Fp> = [0u32, 2, 3, 4, 5].into_iter().map(Into::into).collect();
    let runtime_table: RuntimeTable<Fp> = RuntimeTable { id: 2, data };

    // circuit
    let mut gates = vec![];
    let nb_gates = 20;
    for row in 0..nb_gates {
        gates.push(CircuitGate::new(
            GateType::Lookup,
            Wire::for_row(row),
            vec![],
        ));
    }

    // witness
    let witness = {
        let mut cols: [_; COLUMNS] = array::from_fn(|_col| vec![Fp::zero(); nb_gates]);

        // only the first 7 registers are used in the lookup gate
        let (lookup_cols, _rest) = cols.split_at_mut(7);

        for row in 0..nb_gates {
            // the first register is the table id. We set to the runtime table
            // ID given by the prover
            lookup_cols[0][row] = runtime_table.id.into();
            // We will set [w1, w2], [w3, w4] and [w5, w6] to correct values
            let lookup_cols = &mut lookup_cols[1..];
            for chunk in lookup_cols.chunks_mut(2) {
                chunk[0][row] = 8u32.into();
                chunk[1][row] = 0u32.into();
            }
        }
        cols
    };

    // We only run the prover. No need to verify.
    let err = TestFramework::<Vesta>::default()
        .gates(gates)
        .witness(witness)
        .runtime_tables_setup(vec![cfg])
        .setup()
        .runtime_tables(vec![runtime_table])
        .prove::<BaseSponge, ScalarSponge>()
        .unwrap_err();
    assert_eq!(
        err,
        "the runtime tables provided did not match the index's configuration"
    );
}

#[test]
fn test_runtime_table_with_more_than_one_runtime_table_data_given_by_prover() {
    let mut rng = rand::thread_rng();

    let first_column = [0, 1, 2, 3, 4];
    let len = first_column.len();

    let cfg = RuntimeTableCfg {
        id: 1,
        first_column: first_column.into_iter().map(Into::into).collect(),
    };

    /* We want to simulate this
        table ID  | idx | v | v2
           1      |  0  | 0 | 42
           1      |  1  | 2 | 32
           1      |  2  | 4 | 22
           1      |  3  | 5 | 12
           1      |  4  | 4 |  2
    */

    let data_v: Vec<Fp> = [0u32, 2, 3, 4, 5].into_iter().map(Into::into).collect();
    let data_v2: Vec<Fp> = [42, 32, 22, 12, 2].into_iter().map(Into::into).collect();
    let runtime_tables: Vec<RuntimeTable<Fp>> = vec![
        RuntimeTable {
            id: 1,
            data: data_v.clone(),
        },
        RuntimeTable {
            id: 1,
            data: data_v2,
        },
    ];

    // circuit
    let mut gates = vec![];
    for row in 0..20 {
        gates.push(CircuitGate::new(
            GateType::Lookup,
            Wire::for_row(row),
            vec![],
        ));
    }

    // witness
    let witness = {
        let mut cols: [_; COLUMNS] = array::from_fn(|_col| vec![Fp::zero(); gates.len()]);

        // only the first 7 registers are used in the lookup gate
        let (lookup_cols, _rest) = cols.split_at_mut(7);

        for row in 0..20 {
            // the first register is the table id.
            lookup_cols[0][row] = 1.into();

            // create queries into our runtime lookup table.
            // We will set [w1, w2], [w3, w4] and [w5, w6] to randon indexes and
            // the corresponding values
            let lookup_cols = &mut lookup_cols[1..];
            for chunk in lookup_cols.chunks_mut(2) {
                let idx = rng.gen_range(0..len);
                chunk[0][row] = first_column[idx].into();
                chunk[1][row] = data_v[idx];
            }
        }
        cols
    };

    print_witness(&witness, 0, 20);

    // run test
    let err = TestFramework::<Vesta>::default()
        .gates(gates)
        .witness(witness)
        .runtime_tables_setup(vec![cfg])
        .setup()
        .runtime_tables(runtime_tables)
        .prove_and_verify::<BaseSponge, ScalarSponge>()
        .unwrap_err();
    assert_eq!(
        err,
        "the runtime tables provided did not match the index's configuration"
    );
}

#[test]
fn test_runtime_table_only_one_table_with_id_zero_with_non_zero_entries_fixed_values() {
    let first_column = [0, 1, 2, 3, 4, 5];
    let table_id = 0;

    let cfg = RuntimeTableCfg {
        id: table_id,
        first_column: first_column.into_iter().map(Into::into).collect(),
    };

    let data: Vec<Fp> = [0u32, 1, 2, 3, 4, 5].into_iter().map(Into::into).collect();
    let runtime_table = RuntimeTable { id: table_id, data };

    let lookups: Vec<i32> = [0; 20].into();

    setup_successfull_runtime_table_test(vec![cfg], vec![runtime_table], lookups);
}

#[test]
fn test_runtime_table_only_one_table_with_id_zero_with_non_zero_entries_random_values() {
    let mut rng = rand::thread_rng();

    let len = rng.gen_range(1usize..1000);
    let first_column: Vec<i32> = (0..len as i32).collect();

    let table_id = 0;

    let cfg = RuntimeTableCfg {
        id: table_id,
        first_column: first_column.clone().into_iter().map(Into::into).collect(),
    };

    let data: Vec<Fp> = first_column
        .into_iter()
        .map(|_| UniformRand::rand(&mut rng))
        .collect();
    let runtime_table = RuntimeTable { id: table_id, data };

    let lookups: Vec<i32> = [0; 20].into();

    setup_successfull_runtime_table_test(vec![cfg], vec![runtime_table], lookups);
}
