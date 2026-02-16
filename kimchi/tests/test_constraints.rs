use ark_ff::Zero;
use kimchi::circuits::{
    constraints::ConstraintSystem,
    gate::{CircuitGate, GateType},
    lookup::{runtime_tables::RuntimeTableCfg, tables::LookupTable},
    wires::{Wire, PERMUTS},
};
use mina_curves::pasta::{Fp, Fq};
use o1_utils::FieldHelpers;

#[test]
pub fn test_domains_computation_with_runtime_tables() {
    let dummy_gate = CircuitGate {
        typ: GateType::Generic,
        wires: [Wire::new(0, 0); PERMUTS],
        coeffs: vec![Fp::zero()],
    };
    // inputs + expected output
    let data = [((10, 10), 128), ((0, 0), 8), ((5, 100), 512)];
    for ((number_of_rt_cfgs, size), expected_domain_size) in data.into_iter() {
        let builder = ConstraintSystem::create(vec![dummy_gate.clone(), dummy_gate.clone()]);
        let table_ids: Vec<i32> = (0..number_of_rt_cfgs).collect();
        let rt_cfgs: Vec<RuntimeTableCfg<Fp>> = table_ids
            .into_iter()
            .map(|table_id| {
                let indexes: Vec<u32> = (0..size).collect();
                let first_column: Vec<Fp> = indexes.into_iter().map(Fp::from).collect();
                RuntimeTableCfg {
                    id: table_id,
                    first_column,
                }
            })
            .collect();
        let res = builder.runtime(Some(rt_cfgs)).build().unwrap();
        assert_eq!(res.domain.d1.size, expected_domain_size)
    }
}

#[test]
fn test_lookup_domain_size_computation() {
    let (next_start, range_check_gates_0) = CircuitGate::<Fp>::create_range_check(0); /* 1 range_check gate */
    let (next_start, range_check_gates_1) = CircuitGate::<Fp>::create_range_check(next_start); /* 1 range_check gate */
    let (next_start, xor_gates_0) = CircuitGate::<Fp>::create_xor_gadget(next_start, 3); /* 1 xor gate */
    let (next_start, xor_gates_1) = CircuitGate::<Fp>::create_xor_gadget(next_start, 3); /* 1 xor gate */
    let (_, ffm_gates) =
        CircuitGate::<Fp>::create_foreign_field_mul(next_start, &Fq::modulus_biguint()); /* 1 foreign field multiplication gate */
    let circuit_gates: Vec<CircuitGate<Fp>> = range_check_gates_0
        .into_iter()
        .chain(range_check_gates_1)
        .chain(xor_gates_0)
        .chain(xor_gates_1)
        .chain(ffm_gates)
        .collect(); /* 2 range check gates + 2 xor gates + 1 foreign field multiplication */

    // inputs + expected output
    let data = [
        (
            (10, 10),
            8192, /* 8192 > 10 * 10 + 1 * 4096 + 1 * 256 + 1 + zk_row */
        ),
        (
            (0, 0),
            8192, /* 8192 > 0 * 0 + 1 * 4096 + 1 * 256 + 1 + zk_row */
        ),
        (
            (5, 100),
            8192, /* 8192 > 5 * 100 + 1 * 4096 + 1 * 256 + 1 + zk_row */
        ),
    ];
    data.into_iter()
        .for_each(|((number_of_table_ids, size), expected_domain_size)| {
            let builder = ConstraintSystem::create(circuit_gates.clone());
            let table_ids: Vec<i32> = (3..number_of_table_ids + 3).collect();
            let lookup_tables: Vec<LookupTable<Fp>> = table_ids
                .into_iter()
                .map(|id| {
                    let indexes: Vec<u32> = (0..size).collect();
                    let data: Vec<Fp> = indexes.into_iter().map(Fp::from).collect();
                    LookupTable {
                        id,
                        data: vec![data],
                    }
                })
                .collect();
            let res = builder.lookup(lookup_tables).build().unwrap();
            assert_eq!(res.domain.d1.size, expected_domain_size);
        });
}

#[test]
fn test_constraint_system_serialization_deserialization() {
    let (next_start, range_check_gates_0) = CircuitGate::<Fp>::create_range_check(0); /* 1 range_check gate */
    let (next_start, range_check_gates_1) = CircuitGate::<Fp>::create_range_check(next_start); /* 1 range_check gate */
    let (next_start, xor_gates_0) = CircuitGate::<Fp>::create_xor_gadget(next_start, 3); /* 1 xor gate */
    let (next_start, xor_gates_1) = CircuitGate::<Fp>::create_xor_gadget(next_start, 3); /* 1 xor gate */
    let (_, ffm_gates) =
        CircuitGate::<Fp>::create_foreign_field_mul(next_start, &Fq::modulus_biguint()); /* 1 foreign field multiplication gate */
    let circuit_gates: Vec<CircuitGate<Fp>> = range_check_gates_0
        .into_iter()
        .chain(range_check_gates_1)
        .chain(xor_gates_0)
        .chain(xor_gates_1)
        .chain(ffm_gates)
        .collect(); /* 2 range check gates + 2 xor gates + 1 foreign field multiplication */

    let (number_of_table_ids, size) = (10, 10);

    let builder = ConstraintSystem::create(circuit_gates.clone());

    let table_ids: Vec<i32> = (3..number_of_table_ids + 3).collect();
    let lookup_tables: Vec<LookupTable<Fp>> = table_ids
        .into_iter()
        .map(|id| {
            let indexes: Vec<u32> = (0..size).collect();
            let data: Vec<Fp> = indexes.into_iter().map(Fp::from).collect();
            LookupTable {
                id,
                data: vec![data],
            }
        })
        .collect();
    let cs = builder.lookup(lookup_tables).build().unwrap();

    let bytes_cs: Vec<u8> = rmp_serde::to_vec(&cs).unwrap();

    // Should not panic
    let _: ConstraintSystem<Fp> = rmp_serde::from_read(bytes_cs.as_slice()).unwrap();
}
