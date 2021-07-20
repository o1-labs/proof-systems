use algebra::{
    pasta::{
        fp::Fp,
        pallas::Affine as Other,
        vesta::{Affine, VestaParameters},
    },
    UniformRand, Zero,
};
use array_init::array_init;
use colored::Colorize;
use commitment_dlog::{
    commitment::{b_poly_coefficients, ceil_log2, CommitmentCurve},
    srs::{endos, SRS},
};
use ff_fft::DensePolynomial;
use groupmap::GroupMap;
use oracle::{
    poseidon::{ArithmeticSponge, Plonk15SpongeConstants, Sponge, SpongeConstants},
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use plonk_15_wires_circuits::wires::Wire;
use plonk_15_wires_circuits::{
    gate::CircuitGate,
    gates::poseidon::{round_range, ROUNDS_PER_ROW, SPONGE_WIDTH},
    nolookup::constraints::ConstraintSystem,
};
use plonk_15_wires_protocol_dlog::{
    index::{Index, SRSSpec},
    prover::ProverProof,
};
use rand_core::OsRng;
use std::time::Instant;
use std::{io, io::Write};

// const PERIOD: usize = Plonk15SpongeConstants::ROUNDS_FULL + 1;
// const M: usize = PERIOD * (NUM_POS-1);
// const MAX_SIZE: usize = N; // max size of poly chunks
const PUBLIC: usize = 0;

const NUM_POS: usize = 1; // 1360; // number of Poseidon hashes in the circuit
const ROUNDS_PER_HASH: usize = Plonk15SpongeConstants::ROUNDS_FULL;
const POS_ROWS_PER_HASH: usize = ROUNDS_PER_HASH / ROUNDS_PER_ROW;
const N_LOWER_BOUND: usize = (POS_ROWS_PER_HASH + 1) * NUM_POS; // Plonk domain size

#[test]
fn poseidon_vesta_15_wires() {
    let N = 1 << ceil_log2(N_LOWER_BOUND);
    println!("N = {}", N);
    println!("{} {}", ROUNDS_PER_HASH, ROUNDS_PER_ROW);
    assert_eq!(ROUNDS_PER_HASH % ROUNDS_PER_ROW, 0);

    let c = &oracle::pasta::fp::params().round_constants;

    // circuit gates

    let mut i = 0;
    let mut gates: Vec<CircuitGate<Fp>> = Vec::with_capacity(N);

    // custom constraints for Poseidon hash function permutation

    for _ in 0..NUM_POS {
        // ROUNDS_FULL full rounds constraint gates
        for j in 0..POS_ROWS_PER_HASH {
            let wires = array_init(|col| Wire { col, row: i });
            let coeffs = array_init(|r| {
                let round = j * ROUNDS_PER_ROW + r + 1;
                array_init(|k| c[round][k])
            });
            gates.push(CircuitGate::<Fp>::create_poseidon(i, wires, coeffs));
            i += 1;
        }
        let wires = array_init(|col| Wire { col, row: i });
        gates.push(CircuitGate::<Fp>::zero(i, wires));
        i += 1;
    }

    /*
    for j in 0..Plonk15SpongeConstants::ROUNDS_FULL-2
    {
        gates.push(CircuitGate::<Fp>::create_poseidon(i, [Wire{col:0, row:i}, Wire{col:1, row:i}, Wire{col:2, row:i}, Wire{col:3, row:i}, Wire{col:4, row:i}], c[j].clone()));
        i+=1;
    }
    gates.push(CircuitGate::<Fp>::zero(i, [Wire{col:0, row:i}, Wire{col:1, row:i}, Wire{col:2, row:i}, Wire{col:3, row:i}, Wire{col:4, row:i}]));
    i+=1;
    gates.push(CircuitGate::<Fp>::zero(i, [Wire{col:0, row:i}, Wire{col:1, row:i}, Wire{col:2, row:i}, Wire{col:3, row:i}, Wire{col:4, row:i}]));
    i+=1;
    gates.push(CircuitGate::<Fp>::zero(i, [Wire{col:0, row:i}, Wire{col:1, row:i}, Wire{col:2, row:i}, Wire{col:3, row:i}, Wire{col:4, row:i}]));
    */

    let MAX_SIZE = N;
    let srs = SRS::create(MAX_SIZE);

    let (endo_q, _endo_r) = endos::<Other>();
    let index = Index::<Affine>::create(
        ConstraintSystem::<Fp>::create(gates, oracle::pasta::fp::params(), PUBLIC).unwrap(),
        oracle::pasta::fq::params(),
        endo_q,
        SRSSpec::Use(&srs),
    );

    positive(&index);
}

fn positive(index: &Index<Affine>) {
    let rng = &mut OsRng;

    let params = oracle::pasta::fp::params();
    let mut sponge = ArithmeticSponge::<Fp, Plonk15SpongeConstants>::new();

    let mut batch = Vec::new();
    let group_map = <Affine as CommitmentCurve>::Map::setup();

    let N = 1 << ceil_log2(N_LOWER_BOUND);
    let MAX_SIZE = N;

    println!("{}{:?}", "Circuit size: ".yellow(), N);
    println!("{}{:?}", "Polycommitment chunk size: ".yellow(), MAX_SIZE);
    println!(
        "{}{:?}",
        "Number oh Poseidon hashes in the circuit: ".yellow(),
        NUM_POS
    );
    println!(
        "{}{:?}",
        "Full rounds: ".yellow(),
        Plonk15SpongeConstants::ROUNDS_FULL
    );
    println!(
        "{}{:?}",
        "Sbox alpha: ".yellow(),
        Plonk15SpongeConstants::SPONGE_BOX
    );
    println!("{}", "Base curve: vesta".green());
    println!();
    println!("{}", "Prover zk-proof computation".green());
    let mut start = Instant::now();

    for test in 0..1 {
        //  witness for Poseidon permutation custom constraints
        let mut w = [
            vec![Fp::zero(); N],
            vec![Fp::zero(); N],
            vec![Fp::zero(); N],
            vec![Fp::zero(); N],
            vec![Fp::zero(); N],
            vec![Fp::zero(); N],
            vec![Fp::zero(); N],
            vec![Fp::zero(); N],
            vec![Fp::zero(); N],
            vec![Fp::zero(); N],
            vec![Fp::zero(); N],
            vec![Fp::zero(); N],
            vec![Fp::zero(); N],
            vec![Fp::zero(); N],
            vec![Fp::zero(); N],
        ];

        let init = vec![
            Fp::rand(rng),
            Fp::rand(rng),
            Fp::rand(rng),
            Fp::rand(rng),
            Fp::rand(rng),
        ];
        for h in 0..NUM_POS {
            let base = h * (POS_ROWS_PER_HASH + 1);
            for i in 0..SPONGE_WIDTH {
                w[round_range(0)][i][base] = init[i];
            }

            sponge.state = init.clone();

            for i in 0..POS_ROWS_PER_HASH {
                let row = i + base;
                for r in 0..ROUNDS_PER_ROW {
                    let next_row = if r == ROUNDS_PER_ROW - 1 {
                        row + 1
                    } else {
                        row
                    };
                    let abs_round = r + i * ROUNDS_PER_ROW;
                    sponge.full_round(abs_round, &params);
                    w[round_range((r + 1) % ROUNDS_PER_ROW)]
                        .iter_mut()
                        .zip(sponge.state.iter())
                        .for_each(|(w, s)| w[next_row] = *s);
                }
            }
        }

        /*
        sponge.state = init.clone();
        w.iter_mut().zip(sponge.state.iter()).for_each(|(w, s)| w.push(*s));

        // ROUNDS_FULL full rounds
        for j in 0..Plonk15SpongeConstants::ROUNDS_FULL-2
        {
            sponge.full_round(j, &params);
            w.iter_mut().zip(sponge.state.iter()).for_each(|(w, s)| w.push(*s));
        }

        w.iter_mut().for_each(|w| {w.push(Fp::rand(rng)); w.push(Fp::rand(rng))}); */

        // verify the circuit satisfiability by the computed witness
        assert_eq!(index.cs.verify(&w), true);

        let prev = {
            let k = ceil_log2(index.srs.get_ref().g.len());
            let chals: Vec<_> = (0..k).map(|_| Fp::rand(rng)).collect();
            let comm = {
                let b = DensePolynomial::from_coefficients_vec(b_poly_coefficients(&chals));
                index.srs.get_ref().commit_non_hiding(&b, None)
            };
            (chals, comm)
        };

        println!("n vs domain{} {}", N, index.cs.domain.d1.size);

        // add the proof to the batch
        batch.push(
            ProverProof::create::<
                DefaultFqSponge<VestaParameters, Plonk15SpongeConstants>,
                DefaultFrSponge<Fp, Plonk15SpongeConstants>,
            >(&group_map, &w, &index, vec![prev])
            .unwrap(),
        );

        print!("{:?}\r", test);
        io::stdout().flush().unwrap();
    }
    println!("{}{:?}", "Execution time: ".yellow(), start.elapsed());

    let verifier_index = index.verifier_index();

    let lgr_comms = vec![];
    let batch: Vec<_> = batch
        .iter()
        .map(|p| (&verifier_index, &lgr_comms, p))
        .collect();

    // verify the proofs in batch
    println!("{}", "Verifier zk-proofs verification".green());
    start = Instant::now();
    match ProverProof::verify::<
        DefaultFqSponge<VestaParameters, Plonk15SpongeConstants>,
        DefaultFrSponge<Fp, Plonk15SpongeConstants>,
    >(&group_map, &batch)
    {
        Err(error) => panic!("Failure verifying the prover's proofs in batch: {}", error),
        Ok(_) => {
            println!("{}{:?}", "Execution time: ".yellow(), start.elapsed());
        }
    }
}
