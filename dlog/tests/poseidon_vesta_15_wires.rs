use ark_ff::{UniformRand, Zero};
use ark_poly::{univariate::DensePolynomial, UVPolynomial};
use array_init::array_init;
use colored::Colorize;
use commitment_dlog::{
    commitment::{b_poly_coefficients, ceil_log2, CommitmentCurve},
    srs::{endos, SRS},
};
use groupmap::GroupMap;
use kimchi::{index::Index, prover::ProverProof};
use kimchi_circuits::wires::{Wire, COLUMNS};
use kimchi_circuits::{
    gate::CircuitGate,
    gates::poseidon::{round_to_cols, ROUNDS_PER_ROW, SPONGE_WIDTH},
    nolookup::constraints::ConstraintSystem,
};
use mina_curves::pasta::{
    fp::Fp,
    pallas::Affine as Other,
    vesta::{Affine, VestaParameters},
};
use oracle::{
    poseidon::{ArithmeticSponge, PlonkSpongeConstants15W, Sponge, SpongeConstants},
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use rand::{rngs::StdRng, SeedableRng};
use std::{io, io::Write};
use std::{sync::Arc, time::Instant};

// aliases

type SpongeParams = PlonkSpongeConstants15W;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<Fp, SpongeParams>;

// const PERIOD: usize = SpongeParams::ROUNDS_FULL + 1;
// const M: usize = PERIOD * (NUM_POS-1);
// const MAX_SIZE: usize = N; // max size of poly chunks
const PUBLIC: usize = 0;

const NUM_POS: usize = 1; // 1360; // number of Poseidon hashes in the circuit
const ROUNDS_PER_HASH: usize = SpongeParams::ROUNDS_FULL;
const POS_ROWS_PER_HASH: usize = ROUNDS_PER_HASH / ROUNDS_PER_ROW;
const N_LOWER_BOUND: usize = (POS_ROWS_PER_HASH + 1) * NUM_POS; // Plonk domain size

#[test]
fn poseidon_vesta_15_wires() {
    let max_size = 1 << ceil_log2(N_LOWER_BOUND);
    println!("max_size = {}", max_size);
    println!("rounds per hash = {}", ROUNDS_PER_HASH);
    println!("rounds per row = {}", ROUNDS_PER_ROW);
    println!(" number of rows for poseidon ={}", POS_ROWS_PER_HASH);
    assert_eq!(ROUNDS_PER_HASH % ROUNDS_PER_ROW, 0);

    let round_constants = oracle::pasta::fp::params().round_constants;

    // we keep track of an absolute row, and relative row within a gadget
    let mut abs_row = 0;

    // circuit gates
    let mut gates: Vec<CircuitGate<Fp>> = Vec::with_capacity(max_size);

    // custom constraints for Poseidon hash function permutation
    // ROUNDS_FULL full rounds constraint gates
    for _ in 0..NUM_POS {
        let first_wire = Wire::new(abs_row);
        let last_row = abs_row + POS_ROWS_PER_HASH;
        let last_wire = Wire::new(last_row);
        let (poseidon, row) = CircuitGate::<Fp>::create_poseidon_gadget(
            abs_row,
            [first_wire, last_wire],
            &round_constants,
        );
        gates.extend(poseidon);
        abs_row = row;
    }

    // create the index
    let fp_sponge_params = oracle::pasta::fp::params();
    let mut srs = SRS::<Affine>::create(max_size);
    let cs = ConstraintSystem::<Fp>::create(gates, vec![], fp_sponge_params, PUBLIC).unwrap();
    srs.add_lagrange_basis(cs.domain.d1);
    let fq_sponge_params = oracle::pasta::fq::params();
    let (endo_q, _endo_r) = endos::<Other>();
    let srs = Arc::new(srs);

    let index = Index::<Affine>::create(cs, fq_sponge_params, endo_q, srs);

    positive(&index);
}

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
        let mut witness_cols: [Vec<Fp>; COLUMNS] =
            array_init(|_| vec![Fp::zero(); POS_ROWS_PER_HASH * NUM_POS + 1 /* last output row */]);

        // creates a random initial state
        let init = vec![Fp::rand(rng), Fp::rand(rng), Fp::rand(rng)];

        // number of poseidon instances in the circuit
        for h in 0..NUM_POS {
            // index
            let first_row = h * (POS_ROWS_PER_HASH + 1);

            // initialize the sponge in the circuit with our random state
            let first_state_cols = &mut witness_cols[round_to_cols(0)];
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
                    witness_cols[cols_to_update]
                        .iter_mut()
                        .zip(sponge.state.iter())
                        // update the state (last update is on the next row)
                        .for_each(|(w, s)| w[maybe_next_row] = *s);
                }
            }
        }

        // verify the circuit satisfiability by the computed witness
        index.cs.verify(&witness_cols).unwrap();

        //
        let prev = {
            let k = ceil_log2(index.srs.g.len());
            let chals: Vec<_> = (0..k).map(|_| Fp::rand(rng)).collect();
            let comm = {
                let coeffs = b_poly_coefficients(&chals);
                let b = DensePolynomial::from_coefficients_vec(coeffs);
                index.srs.commit_non_hiding(&b, None)
            };

            (chals, comm)
        };

        println!("n vs domain: {} {}", max_size, index.cs.domain.d1.size);

        // add the proof to the batch
        // TODO: create and verify should not take group_map, that should be during an init phase
        batch.push(
            ProverProof::create::<BaseSponge, ScalarSponge>(
                &group_map,
                witness_cols,
                index,
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
