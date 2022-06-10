use super::framework::{print_witness, TestFramework};
use crate::circuits::{
    gate::{CircuitGate, GateType},
    lookup::{
        runtime_tables::{RuntimeTable, RuntimeTableCfg, RuntimeTableSpec},
        tables::LookupTable,
    },
    polynomial::COLUMNS,
    wires::Wire,
};
use ark_ff::Zero;
use array_init::array_init;
use mina_curves::pasta::fp::Fp;

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
        .map(|i| CircuitGate {
            typ: GateType::Lookup,
            coeffs: vec![],
            wires: Wire::new(i),
        })
        .collect();

    let witness = {
        let mut lookup_table_ids = Vec::with_capacity(num_lookups);
        let mut lookup_indexes: [_; 3] = array_init(|_| Vec::with_capacity(num_lookups));
        let mut lookup_values: [_; 3] = array_init(|_| Vec::with_capacity(num_lookups));
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

    TestFramework::default()
        .gates(gates)
        .witness(witness)
        .lookup_tables(lookup_tables)
        .setup()
        .prove_and_verify();
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

fn runtime_table(num: usize, indexed: bool) {
    // runtime
    let mut runtime_tables_setup = vec![];
    for table_id in 0..num {
        let cfg = if indexed {
            RuntimeTableCfg::Indexed(RuntimeTableSpec {
                id: table_id as i32,
                len: 5,
            })
        } else {
            RuntimeTableCfg::Custom {
                id: table_id as i32,
                first_column: [8u32, 9, 8, 7, 1].into_iter().map(Into::into).collect(),
            }
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
        gates.push(CircuitGate {
            typ: GateType::Lookup,
            wires: Wire::new(row),
            coeffs: vec![],
        });
    }

    // witness
    let witness = {
        let mut cols: [_; COLUMNS] = array_init(|_col| vec![Fp::zero(); gates.len()]);

        // only the first 7 registers are used in the lookup gate
        let (lookup_cols, _rest) = cols.split_at_mut(7);

        for row in 0..20 {
            // the first register is the table id
            lookup_cols[0][row] = 0u32.into();

            // create queries into our runtime lookup table
            let lookup_cols = &mut lookup_cols[1..];
            for chunk in lookup_cols.chunks_mut(2) {
                chunk[0][row] = if indexed { 1u32.into() } else { 9u32.into() }; // index
                chunk[1][row] = 2u32.into(); // value
            }
        }
        cols
    };

    print_witness(&witness, 0, 20);

    // run test
    TestFramework::default()
        .gates(gates)
        .witness(witness)
        .runtime_tables_setup(runtime_tables_setup)
        .setup()
        .runtime_tables(runtime_tables)
        .prove_and_verify();
}

#[test]
fn test_indexed_runtime_table() {
    runtime_table(5, true);
}

#[test]
fn test_custom_runtime_table() {
    runtime_table(5, false);
}

// TODO: add a test with a runtime table with ID 0 (it should panic)
