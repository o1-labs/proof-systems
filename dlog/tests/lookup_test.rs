use ark_ff::UniformRand;
use ark_ff::Zero;
use array_init::array_init;
use colored::Colorize;
use commitment_dlog::{
    commitment::{ceil_log2, CommitmentCurve},
    srs::{endos, SRS},
};
use groupmap::GroupMap;
use kimchi::{index::Index, prover::ProverProof};
use kimchi_circuits::wires::{Wire, COLUMNS};
use kimchi_circuits::{
    gate::{CircuitGate, GateType},
    nolookup::constraints::ConstraintSystem,
    polynomials::chacha,
};
use mina_curves::pasta::{
    fp::Fp,
    pallas::Affine as Other,
    vesta::{Affine, VestaParameters},
};
use oracle::{
    poseidon::PlonkSpongeConstants15W,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use std::cmp::min;
use std::{sync::Arc, time::Instant};

// aliases

type SpongeParams = PlonkSpongeConstants15W;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

const PUBLIC: usize = 0;

#[test]
fn lookup_prover() {
    let num_lookups = 500;
    let table_size = 500;
    let max_size = 1 << ceil_log2(min(num_lookups, table_size));
    let rng = &mut rand::rngs::OsRng;
    let runtime_table: Vec<_> = (0..table_size).map(|_i| Fp::rand(rng)).collect();

    let mut gates = Vec::with_capacity(num_lookups);
    for i in 0..num_lookups {
        gates.push(CircuitGate {
            row: i,
            typ: GateType::Lookup,
            wires: array_init(|j| Wire { row: i, col: j }),
            c: vec![],
        });
    }

    let mut witness: [Vec<Fp>; COLUMNS] = array_init(|_| vec![]);
    for _ in 0..num_lookups {
        for i in 0..3 {
            let idx = rand::random::<usize>() % table_size;
            witness[i * 2].push(Into::into(idx as u64));
            witness[i * 2 + 1].push(runtime_table[idx]);
        }
        for i in 6..COLUMNS {
            witness[i].push(Fp::zero());
        }
    }

    // create the index
    let fp_sponge_params = oracle::pasta::fp::params();
    let cs =
        ConstraintSystem::<Fp>::create(gates, vec![chacha::xor_table()], fp_sponge_params, PUBLIC)
            .unwrap();
    let fq_sponge_params = oracle::pasta::fq::params();
    let (endo_q, _endo_r) = endos::<Other>();
    let mut srs = SRS::create(max_size);
    srs.add_lagrange_basis(cs.domain.d1);
    let srs = Arc::new(srs);

    let index = Index::<Affine>::create(cs, fq_sponge_params, endo_q, srs);

    let group_map = <Affine as CommitmentCurve>::Map::setup();

    let start = Instant::now();
    let proof = ProverProof::create::<BaseSponge, ScalarSponge>(
        &group_map,
        witness,
        runtime_table,
        &index,
        vec![],
    )
    .unwrap();
    println!("{}{:?}", "Prover time: ".yellow(), start.elapsed());

    let start = Instant::now();
    let verifier_index = index.verifier_index();
    println!("{}{:?}", "Verifier index time: ".yellow(), start.elapsed());

    let lgr_comms = vec![];
    let batch: Vec<_> = vec![(&verifier_index, &lgr_comms, &proof)];
    let start = Instant::now();
    match ProverProof::verify::<BaseSponge, ScalarSponge>(&group_map, &batch) {
        Err(error) => panic!("Failure verifying the prover's proofs in batch: {}", error),
        Ok(_) => {
            println!("{}{:?}", "Verifier time: ".yellow(), start.elapsed());
        }
    }
}
