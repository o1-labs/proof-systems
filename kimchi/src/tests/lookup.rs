use crate::{
    circuits::{
        gate::{CircuitGate, GateType, LookupTable},
        wires::Wire,
    },
    index::testing::new_index_for_test_with_lookups,
    prover::ProverProof,
    verifier::batch_verify,
};
use ark_ff::{One, Zero};
use array_init::array_init;
use colored::Colorize;
use commitment_dlog::commitment::CommitmentCurve;
use groupmap::GroupMap;
use mina_curves::pasta::{
    fp::Fp,
    vesta::{Affine, VestaParameters},
};
use oracle::{
    poseidon::PlonkSpongeConstantsKimchi,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use std::time::Instant;

// aliases

type SpongeParams = PlonkSpongeConstantsKimchi;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

const PUBLIC: usize = 0;

fn setup_lookup_proof(use_values_from_table: bool) {
    let num_lookups = 500;
    let lookup_table_values: Vec<_> = (0..256).map(|_| rand::random()).collect();
    let lookup_table = {
        let index_column = (0..256 as u64).map(Into::into).collect();
        vec![index_column, lookup_table_values.clone()]
    };

    // circuit gates
    let gates = (0..num_lookups)
        .map(|i| CircuitGate {
            typ: GateType::Lookup,
            coeffs: vec![],
            wires: Wire::new(i),
        })
        .collect();

    // create the index
    let index = new_index_for_test_with_lookups(
        gates,
        PUBLIC,
        vec![LookupTable {
            id: 1,
            data: lookup_table,
        }],
    );

    let witness = {
        let mut lookup_table_ids = Vec::with_capacity(num_lookups);
        let mut lookup_indexes: [_; 3] = array_init(|_| Vec::with_capacity(num_lookups));
        let mut lookup_values: [_; 3] = array_init(|_| Vec::with_capacity(num_lookups));
        let unused = || vec![Fp::zero(); num_lookups];
        for _ in 0..num_lookups {
            lookup_table_ids.push(Fp::one());
            for i in 0..3 {
                let index = rand::random::<u64>() % 256;
                let value = if use_values_from_table {
                    lookup_table_values[index as usize]
                } else {
                    rand::random()
                };
                lookup_indexes[i].push(index.into());
                lookup_values[i].push(value);
            }
        }
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

    let group_map = <Affine as CommitmentCurve>::Map::setup();

    let start = Instant::now();
    let proof =
        ProverProof::create::<BaseSponge, ScalarSponge>(&group_map, witness, &index, vec![])
            .unwrap();
    println!("{}{:?}", "Prover time: ".yellow(), start.elapsed());

    let start = Instant::now();
    let verifier_index = index.verifier_index();
    println!("{}{:?}", "Verifier index time: ".yellow(), start.elapsed());

    let batch: Vec<_> = vec![(&verifier_index, &proof)];
    let start = Instant::now();
    match batch_verify::<Affine, BaseSponge, ScalarSponge>(&group_map, &batch) {
        Err(error) => panic!("Failure verifying the prover's proofs in batch: {}", error),
        Ok(_) => {
            println!("{}{:?}", "Verifier time: ".yellow(), start.elapsed());
        }
    }
}

#[test]
fn lookup_gate_proving_works() {
    setup_lookup_proof(true)
}

#[test]
#[should_panic]
fn lookup_gate_rejects_bad_lookups() {
    setup_lookup_proof(false)
}
