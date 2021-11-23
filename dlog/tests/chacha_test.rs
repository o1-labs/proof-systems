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
    gate::CircuitGate, nolookup::constraints::ConstraintSystem, polynomials::chacha,
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
use std::{sync::Arc, time::Instant};

// aliases

type SpongeParams = PlonkSpongeConstants15W;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

const PUBLIC: usize = 0;

#[test]
fn chacha_prover() {
    let num_chachas = 8;
    let rows_per_chacha = 20 * 4 * 10;
    let n_lower_bound = rows_per_chacha * num_chachas;
    let max_size = 1 << ceil_log2(n_lower_bound);
    println!("{} {}", n_lower_bound, max_size);

    let s0: Vec<u32> = vec![
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0x03020100, 0x07060504, 0x0b0a0908,
        0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c, 0x00000001, 0x09000000,
        0x4a000000, 0x00000000,
    ];
    let expected_result: Vec<u32> = vec![
        0x837778ab, 0xe238d763, 0xa67ae21e, 0x5950bb2f, 0xc4f2d0c7, 0xfc62bb2f, 0x8fa018fc,
        0x3f5ec7b7, 0x335271c2, 0xf29489f3, 0xeabda8fc, 0x82e46ebd, 0xd19c12b4, 0xb04e16de,
        0x9e83d0cb, 0x4e3c50a2,
    ];
    assert_eq!(expected_result, chacha::chacha20(s0.clone()));

    // circuit gates
    let mut gates = vec![];
    for _ in 0..num_chachas {
        gates.extend(chacha::chacha20_gates())
    }
    let gates: Vec<CircuitGate<Fp>> = gates
        .into_iter()
        .enumerate()
        .map(|(i, typ)| CircuitGate {
            typ,
            row: i,
            c: vec![],
            wires: Wire::new(i),
        })
        .collect();

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

    let mut rows = vec![];
    for _ in 0..num_chachas {
        rows.extend(chacha::chacha20_rows::<Fp>(s0.clone()))
    }
    let mut witness: [Vec<Fp>; COLUMNS] = array_init(|_| vec![]);
    for r in rows.into_iter() {
        for (col, c) in r.into_iter().enumerate() {
            witness[col].push(c);
        }
    }

    let group_map = <Affine as CommitmentCurve>::Map::setup();

    let start = Instant::now();
    let proof = ProverProof::create::<BaseSponge, ScalarSponge>(
        &group_map,
        witness,
        vec![],
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
