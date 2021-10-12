use ark_ff::{UniformRand, Zero};
use ark_poly::{univariate::DensePolynomial, UVPolynomial};
use array_init::array_init;
use colored::Colorize;
use commitment_dlog::{
    commitment::{b_poly_coefficients, ceil_log2, CommitmentCurve},
    srs::{endos, SRS},
};
use groupmap::GroupMap;
use mina_curves::pasta::{
    fp::Fp,
    pallas::Affine as Other,
    vesta::{Affine, VestaParameters},
};
use oracle::{
    poseidon::{ArithmeticSponge, PlonkSpongeConstants15W, Sponge, SpongeConstants},
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use plonk_15_wires_circuits::wires::{Wire, COLUMNS};
use plonk_15_wires_circuits::{
    gate::CircuitGate,
    polynomials::chacha,
    nolookup::constraints::ConstraintSystem,
};
use plonk_15_wires_protocol_dlog::{
    index::{Index, SRSSpec},
    prover::ProverProof,
};
use rand::{rngs::StdRng, SeedableRng};
use std::{rc::Rc, time::Instant};
use std::{io, io::Write};

// aliases

type SpongeParams = PlonkSpongeConstants15W;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

const PUBLIC: usize = 0;

#[test]
fn chacha_prover() {
    let num_chachas = 16;
    let rows_per_chacha = 20 * 4 * 10;
    let n_lower_bound = rows_per_chacha * num_chachas;
    let max_size = 1 << ceil_log2(n_lower_bound);
    println!("{} {}", n_lower_bound, max_size);

    // we keep track of an absolute row, and relative row within a gadget
    let mut abs_row = 0;

    let s0: Vec<u32> = vec![
       0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
       0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
       0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
       0x00000001, 0x09000000, 0x4a000000, 0x00000000,
    ];
    let expected_result: Vec<u32> = vec![
       0x837778ab, 0xe238d763, 0xa67ae21e, 0x5950bb2f,
       0xc4f2d0c7, 0xfc62bb2f, 0x8fa018fc, 0x3f5ec7b7,
       0x335271c2, 0xf29489f3, 0xeabda8fc, 0x82e46ebd,
       0xd19c12b4, 0xb04e16de, 0x9e83d0cb, 0x4e3c50a2,
    ];
    assert_eq!(expected_result, chacha::chacha20(s0.clone()));

    // circuit gates
    let mut gates = vec![];
    for _ in 0..num_chachas {
        gates.extend(chacha::chacha20_gates())
    }
    let gates: Vec<CircuitGate<Fp>> = gates.into_iter().enumerate().map(|(i, typ)| {
        CircuitGate {
            typ,
            row: i,
            c: vec![],
            wires: Wire::new(i)
        }
    }).collect();

    // create the index
    let fp_sponge_params = oracle::pasta::fp::params();
    let cs = ConstraintSystem::<Fp>::create(gates, vec![chacha::xor_table()], fp_sponge_params, PUBLIC).unwrap();
    let fq_sponge_params = oracle::pasta::fq::params();
    let (endo_q, _endo_r) = endos::<Other>();
    let mut srs = SRS::create(max_size);
    srs.add_lagrange_basis(cs.domain.d1);
    let srs = Rc::new(srs);

    let index = Index::<Affine>::create(cs, fq_sponge_params, endo_q, srs);

    let mut rows = vec![];
    for _ in 0..num_chachas {
        rows.extend(chacha::chacha20_rows::<Fp>(s0.clone()))
    }
    let mut witness: [Vec<Fp>; COLUMNS] = array_init(|_| vec![Fp::zero(); max_size]);
    for (i, r) in rows.into_iter().enumerate() {
        for (col, c) in r.into_iter().enumerate() {
            witness[col][i] = c;
        }
    }

    let group_map = <Affine as CommitmentCurve>::Map::setup();

    let start = Instant::now();
    let proof =
        ProverProof::create::<BaseSponge, ScalarSponge>(
            &group_map,
            &witness,
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

/*
// creates a proof and verifies it
fn positive(index: &Index<Affine>) {
    // constant
    let max_size = 1 << ceil_log2(N_LOWER_BOUND);

    // set up
    let rng = &mut StdRng::from_seed([0u8; 32]);
    let params = oracle::pasta::fp::params();
    let mut sponge = ArithmeticSponge::<Fp, SpongeParams>::new(params);
    let group_map = <Affine as CommitmentCurve>::Map::setup();
    let mut batch = Vec::new();

    // debug
    println!("{}{:?}", "Circuit size: ".yellow(), max_size);
    println!("{}{:?}", "Polycommitment chunk size: ".yellow(), max_size);
    println!(
        "{}{:?}",
        "Number oh Poseidon hashes in the circuit: ".yellow(),
        NUM_POS
    );
    println!(
        "{}{:?}",
        "Full rounds: ".yellow(),
        SpongeParams::ROUNDS_FULL
    );
    println!("{}{:?}", "Sbox alpha: ".yellow(), SpongeParams::SPONGE_BOX);
    println!("{}", "Base curve: vesta\n".green());
    println!("{}", "Prover zk-proof computation".green());

    let mut start = Instant::now();
    for test in 0..1 {
        // witness for Poseidon permutation custom constraints
        let mut witness: [Vec<Fp>; COLUMNS] = array_init(|_| vec![Fp::zero(); max_size]);

        // creates a random initial state
        let init = vec![Fp::rand(rng), Fp::rand(rng), Fp::rand(rng)];

        // number of poseidon instances in the circuit
        for h in 0..NUM_POS {
            // index
            // TODO: is the `+ 1` correct?
            let first_row = h * (POS_ROWS_PER_HASH + 1);

            // initialize the sponge in the circuit with our random state
            let first_state_cols = &mut witness[round_to_cols(0)];
            for state_idx in 0..SPONGE_WIDTH {
                first_state_cols[state_idx][first_row] = init[state_idx];
            }

            // set the sponge state
            sponge.state = init.clone();

            // for the poseidon rows
            for row_idx in 0..POS_ROWS_PER_HASH {
                let row = row_idx + first_row;
                for round in 0..ROUNDS_PER_ROW {
                    // the last round makes use of the next row
                    let maybe_next_row = if round == ROUNDS_PER_ROW - 1 {
                        row + 1
                    } else {
                        row
                    };

                    //
                    let abs_round = round + row_idx * ROUNDS_PER_ROW;

                    // apply the sponge and record the result in the witness
                    // (this won't work if the circuit has an INITIAL_ARK)
                    assert!(!PlonkSpongeConstants15W::INITIAL_ARK);
                    sponge.full_round(abs_round);

                    // apply the sponge and record the result in the witness
                    let cols_to_update = round_to_cols((round + 1) % ROUNDS_PER_ROW);
                    witness[cols_to_update]
                        .iter_mut()
                        .zip(sponge.state.iter())
                        // update the state (last update is on the next row)
                        .for_each(|(w, s)| w[maybe_next_row] = *s);
                }
            }
        }

        // verify the circuit satisfiability by the computed witness
        index.cs.verify(&witness).unwrap();

        //
        let prev = {
            let k = ceil_log2(index.srs.get_ref().g.len());
            let chals: Vec<_> = (0..k).map(|_| Fp::rand(rng)).collect();
            let comm = {
                let coeffs = b_poly_coefficients(&chals);
                let b = DensePolynomial::from_coefficients_vec(coeffs);
                index.srs.get_ref().commit_non_hiding(&b, None)
            };

            (chals, comm)
        };

        println!("n vs domain: {} {}", max_size, index.cs.domain.d1.size);

        // add the proof to the batch
        // TODO: create and verify should not take group_map, that should be during an init phase
        batch.push(
            ProverProof::create::<BaseSponge, ScalarSponge>(
                &group_map,
                &witness,
                &index,
                vec![prev],
            )
            .unwrap(),
        );

        print!("{:?}\r", test);
        io::stdout().flush().unwrap();
    }

    // TODO: this should move to a bench
    println!("{}{:?}", "Execution time: ".yellow(), start.elapsed());

    // TODO: shouldn't verifier_index be part of ProverProof, not being passed in verify?
    let verifier_index = index.verifier_index();

    let lgr_comms = vec![];
    let batch: Vec<_> = batch
        .iter()
        .map(|proof| (&verifier_index, &lgr_comms, proof))
        .collect();

    // verify the proofs in batch
    println!("{}", "Verifier zk-proofs verification".green());
    start = Instant::now();
    match ProverProof::verify::<BaseSponge, ScalarSponge>(&group_map, &batch) {
        Err(error) => panic!("Failure verifying the prover's proofs in batch: {}", error),
        Ok(_) => {
            println!("{}{:?}", "Execution time: ".yellow(), start.elapsed());
        }
    }
}
*/
