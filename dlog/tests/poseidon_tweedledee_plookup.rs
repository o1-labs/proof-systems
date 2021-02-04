/*********************************************************************************************************

This source file benchmarks the constraints for the Poseidon hash permutations

**********************************************************************************************************/

use plonk_plookup_circuits::{wires::Wire, gate::CircuitGate, constraints::ConstraintSystem};
use commitment_dlog::{srs::{SRS, endos}, commitment::{CommitmentCurve, ceil_log2, b_poly_coefficients}};
use algebra::{ tweedle::{dum::{Affine as Other}, dee::{Affine, TweedledeeParameters}, fp::Fp}, UniformRand};
use oracle::{poseidon_5_wires::*, poseidon::{SpongeConstants, Sponge}, sponge_5_wires::{DefaultFqSponge, DefaultFrSponge}};
use plonk_plookup_protocol_dlog::{prover::{ProverProof}, index::{Index, SRSSpec}};
use ff_fft::DensePolynomial;
use std::{io, io::Write};
use groupmap::GroupMap;
use std::time::Instant;
use colored::Colorize;
use rand_core::OsRng;

const PERIOD: usize = PlonkSpongeConstants::ROUNDS_FULL + 1;
const NUM_POS: usize = 256; // number of Poseidon hashes in the circuit
const N: usize = PERIOD * NUM_POS; // Plonk domain size
const M: usize = PERIOD * (NUM_POS-1);
const MAX_SIZE: usize = N; // max size of poly chunks
const PUBLIC : usize = 0;

#[test]
fn poseidon_tweedledee_plookup()
{
    let c = &oracle::tweedle::fp5::params().round_constants;

    // circuit gates

    let mut i = 0;
    let mut gates: Vec<CircuitGate::<Fp>> = Vec::with_capacity(N);

    // custom constraints for Poseidon hash function permutation

    for _ in 0..NUM_POS-1
    {
        // ROUNDS_FULL full rounds constraint gates
        for j in 0..PlonkSpongeConstants::ROUNDS_FULL
        {
            let wires =
            [
                Wire{col:0, row:(i+PERIOD)%M},
                Wire{col:1, row:(i+PERIOD)%M},
                Wire{col:2, row:(i+PERIOD)%M},
                Wire{col:3, row:(i+PERIOD)%M},
                Wire{col:4, row:(i+PERIOD)%M},
            ];
            gates.push(CircuitGate::<Fp>::create_poseidon(i, wires, c[j].clone()));
            i+=1;
        }
        let wires =
        [
            Wire{col:0, row:(i+PERIOD)%M},
            Wire{col:1, row:(i+PERIOD)%M},
            Wire{col:2, row:(i+PERIOD)%M},
            Wire{col:3, row:(i+PERIOD)%M},
            Wire{col:4, row:(i+PERIOD)%M},
        ];
        gates.push(CircuitGate::<Fp>::zero(i, wires));
        i+=1;
    }

    for j in 0..PlonkSpongeConstants::ROUNDS_FULL-2
    {
        gates.push(CircuitGate::<Fp>::create_poseidon(i, [Wire{col:0, row:i}, Wire{col:1, row:i}, Wire{col:2, row:i}, Wire{col:3, row:i}, Wire{col:4, row:i}], c[j].clone()));
        i+=1;
    }
    gates.push(CircuitGate::<Fp>::zero(i, [Wire{col:0, row:i}, Wire{col:1, row:i}, Wire{col:2, row:i}, Wire{col:3, row:i}, Wire{col:4, row:i}]));
    i+=1;
    gates.push(CircuitGate::<Fp>::zero(i, [Wire{col:0, row:i}, Wire{col:1, row:i}, Wire{col:2, row:i}, Wire{col:3, row:i}, Wire{col:4, row:i}]));
    i+=1;
    gates.push(CircuitGate::<Fp>::zero(i, [Wire{col:0, row:i}, Wire{col:1, row:i}, Wire{col:2, row:i}, Wire{col:3, row:i}, Wire{col:4, row:i}]));
    
    let srs = SRS::create(MAX_SIZE);

    let (endo_q, _endo_r) = endos::<Other>();
    let index = Index::<Affine>::create
    (
        ConstraintSystem::<Fp>::create(gates, vec![], oracle::tweedle::fp5::params(), PUBLIC).unwrap(),
        oracle::tweedle::fq5::params(),
        endo_q,
        SRSSpec::Use(&srs)
    );

    positive(&index);
}

fn positive(index: &Index<Affine>)
{
    let rng = &mut OsRng;

    let params = oracle::tweedle::fp5::params();
    let mut sponge = ArithmeticSponge::<Fp, PlonkSpongeConstants>::new();

    let mut batch = Vec::new();
    let group_map = <Affine as CommitmentCurve>::Map::setup();

    println!("{}{:?}", "Circuit size: ".yellow(), N);
    println!("{}{:?}", "Polycommitment chunk size: ".yellow(), MAX_SIZE);
    println!("{}{:?}", "Number oh Poseidon hashes in the circuit: ".yellow(), NUM_POS);
    println!("{}{:?}", "Full rounds: ".yellow(), PlonkSpongeConstants::ROUNDS_FULL);
    println!("{}{:?}", "Sbox alpha: ".yellow(), PlonkSpongeConstants::SPONGE_BOX);
    println!("{}", "Base curve: tweedledee".green());
    println!();
    println!("{}", "Prover zk-proof computation".green());
    let mut start = Instant::now();

    for test in 0..1
    {
        //  witness for Poseidon permutation custom constraints
        let mut w =
        [
            Vec::<Fp>::with_capacity(N),
            Vec::<Fp>::with_capacity(N),
            Vec::<Fp>::with_capacity(N),
            Vec::<Fp>::with_capacity(N),
            Vec::<Fp>::with_capacity(N),
        ];

        let init = vec![Fp::rand(rng), Fp::rand(rng), Fp::rand(rng), Fp::rand(rng), Fp::rand(rng)];
        for _ in 0..NUM_POS-1
        {
            sponge.state = init.clone();
            w.iter_mut().zip(sponge.state.iter()).for_each(|(w, s)| w.push(*s));

            // ROUNDS_FULL full rounds
            for j in 0..PlonkSpongeConstants::ROUNDS_FULL
            {
                sponge.full_round(j, &params);
                w.iter_mut().zip(sponge.state.iter()).for_each(|(w, s)| w.push(*s));
            }
        }

        sponge.state = init.clone();
        w.iter_mut().zip(sponge.state.iter()).for_each(|(w, s)| w.push(*s));

        // ROUNDS_FULL full rounds
        for j in 0..PlonkSpongeConstants::ROUNDS_FULL-2
        {
            sponge.full_round(j, &params);
            w.iter_mut().zip(sponge.state.iter()).for_each(|(w, s)| w.push(*s));
        }

        w.iter_mut().for_each(|w| {w.push(Fp::rand(rng)); w.push(Fp::rand(rng))});

        // verify the circuit satisfiability by the computed witness
        assert_eq!(index.cs.verify(&w), true);

        let prev = {
            let k = ceil_log2(index.srs.get_ref().g.len());
            let chals : Vec<_> = (0..k).map(|_| Fp::rand(rng)).collect();
            let comm = {
                let b = DensePolynomial::from_coefficients_vec(b_poly_coefficients(&chals));
                index.srs.get_ref().commit_non_hiding(&b, None)
            };
            ( chals, comm )
        };

        // add the proof to the batch
        batch.push(ProverProof::create::<DefaultFqSponge<TweedledeeParameters, PlonkSpongeConstants>, DefaultFrSponge<Fp, PlonkSpongeConstants>>(
            &group_map, &w, &index, vec![prev]).unwrap());

        print!("{:?}\r", test);
        io::stdout().flush().unwrap();
    }
    println!("{}{:?}", "Execution time: ".yellow(), start.elapsed());

    let verifier_index = index.verifier_index();

    let lgr_comms = vec![];
    let batch : Vec<_> = batch.iter().map(|p| (&verifier_index, &lgr_comms, p)).collect();

    // verify the proofs in batch
    println!("{}", "Verifier zk-proofs verification".green());
    start = Instant::now();
    match ProverProof::verify::<DefaultFqSponge<TweedledeeParameters, PlonkSpongeConstants>, DefaultFrSponge<Fp, PlonkSpongeConstants>>(&group_map, &batch)
    {
        Err(error) => {panic!("Failure verifying the prover's proofs in batch: {}", error)},
        Ok(_) => {println!("{}{:?}", "Execution time: ".yellow(), start.elapsed());}
    }
}
