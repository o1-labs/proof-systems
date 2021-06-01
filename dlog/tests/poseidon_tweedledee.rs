/*********************************************************************************************************

This source file benchmarks the constraints for the Poseidon hash permutations

**********************************************************************************************************/

use oracle::{poseidon::*, sponge::{DefaultFqSponge, DefaultFrSponge}};
use commitment_dlog::{srs::{SRS, SRSSpec, endos}, commitment::{CommitmentCurve, ceil_log2, b_poly_coefficients}};
use plonk_circuits::{wires::GateWires, gate::CircuitGate, constraints::ConstraintSystem};
use algebra::{ tweedle::{dum::{Affine as Other}, dee::{Affine, TweedledeeParameters}, fp::Fp}, UniformRand};
use plonk_protocol_dlog::{prover::{ProverProof}, index::{Index}};
use ark_poly::DensePolynomial;
use std::{io, io::Write};
use groupmap::GroupMap;
use std::time::Instant;
use colored::Colorize;
use rand_core::OsRng;

const PERIOD: usize = PlonkSpongeConstants::ROUNDS_FULL + 1;
const MAX_SIZE: usize = 40000; // max size of poly chunks
const NUM_POS: usize = 256; // number of Poseidon hashes in the circuit
const N: usize = PERIOD * NUM_POS; // Plonk domain size
const M: usize = PERIOD * (NUM_POS-1);
const PUBLIC : usize = 0;

#[test]
fn poseidon_tweedledee()
{
    let c = &oracle::tweedle::fp::params().round_constants;

    // circuit gates

    let mut i = 0;
    let mut gates: Vec<CircuitGate::<Fp>> = Vec::with_capacity(N);

    // custom constraints for Poseidon hash function permutation

    for _ in 0..NUM_POS-1
    {
        // ROUNDS_FULL full rounds constraint gates
        for j in 0..PlonkSpongeConstants::ROUNDS_FULL
        {
            gates.push(CircuitGate::<Fp>::create_poseidon(GateWires::wires((i, (i+PERIOD)%M), (i+N, N+((i+PERIOD)%M)), (i+2*N, 2*N+((i+PERIOD)%M))), [c[j+1][0],c[j+1][1],c[j+1][2]]));
            i+=1;
        }
        gates.push(CircuitGate::<Fp>::zero(GateWires::wires((i, (i+PERIOD)%M), (i+N, N+((i+PERIOD)%M)), (i+2*N, 2*N+((i+PERIOD)%M)))));
        i+=1;
    }

    for j in 0..PlonkSpongeConstants::ROUNDS_FULL-2
    {
        gates.push(CircuitGate::<Fp>::create_poseidon(GateWires::wires((i, i), (i+N, N+(i)), (i+2*N, 2*N+(i))), [c[j+1][0],c[j+1][1],c[j+1][2]]));
        i+=1;
    }
    gates.push(CircuitGate::<Fp>::zero(GateWires::wires((i, i), (i+N, N+(i)), (i+2*N, 2*N+(i)))));
    i+=1;
    gates.push(CircuitGate::<Fp>::zero(GateWires::wires((i, i), (i+N, N+(i)), (i+2*N, 2*N+(i)))));
    i+=1;
    gates.push(CircuitGate::<Fp>::zero(GateWires::wires((i, i), (i+N, N+(i)), (i+2*N, 2*N+(i)))));

    let srs = SRS::create(MAX_SIZE);

    let (endo_q, _endo_r) = endos::<Other>();
    let index = Index::<Affine>::create
    (
        ConstraintSystem::<Fp>::create(gates, oracle::tweedle::fp::params(), PUBLIC).unwrap(),
        oracle::tweedle::fq::params(),
        endo_q,
        SRSSpec::Use(&srs)
    );

    positive(&index);
}

fn positive(index: &Index<Affine>)
where <Fp as std::str::FromStr>::Err : std::fmt::Debug
{
    let rng = &mut OsRng;

    let params = oracle::tweedle::fp::params();
    let mut sponge = ArithmeticSponge::<Fp, PlonkSpongeConstants>::new();

    let mut batch = Vec::new();
    let group_map = <Affine as CommitmentCurve>::Map::setup();

    println!("{}{:?}", "Circuit size: ".yellow(), N);
    println!("{}{:?}", "Polycommitment chunk size: ".yellow(), MAX_SIZE);
    println!("{}{:?}", "Number of Poseidon hashes in the circuit: ".yellow(), NUM_POS);
    println!("{}{:?}", "Full rounds: ".yellow(), PlonkSpongeConstants::ROUNDS_FULL);
    println!("{}{:?}", "Sbox alpha: ".yellow(), PlonkSpongeConstants::SPONGE_BOX);
    println!("{}", "Base curve: tweedledee".green());
    println!();
    println!("{}", "Prover zk-proof computation".green());
    let mut start = Instant::now();

    for test in 0..1
    {
        let mut l: Vec<Fp> = Vec::with_capacity(N);
        let mut r: Vec<Fp> = Vec::with_capacity(N);
        let mut o: Vec<Fp> = Vec::with_capacity(N);

        let (x, y, z) = (Fp::rand(rng), Fp::rand(rng), Fp::rand(rng));

        //  witness for Poseidon permutation custom constraints
        for _ in 0..NUM_POS-1
        {
            sponge.state = vec![x, y, z];
            l.push(sponge.state[0]);
            r.push(sponge.state[1]);
            o.push(sponge.state[2]);

            // HALF_ROUNDS_FULL full rounds
            for j in 0..PlonkSpongeConstants::ROUNDS_FULL
            {
                sponge.full_round(j + 1, &params);
                l.push(sponge.state[0]);
                r.push(sponge.state[1]);
                o.push(sponge.state[2]);
            }
        }

        sponge.state = vec![x, y, z];
        l.push(sponge.state[0]);
        r.push(sponge.state[1]);
        o.push(sponge.state[2]);

        // HALF_ROUNDS_FULL full rounds
        for j in 0..PlonkSpongeConstants::ROUNDS_FULL-2
        {
            sponge.full_round(j + 1, &params);
            l.push(sponge.state[0]);
            r.push(sponge.state[1]);
            o.push(sponge.state[2]);
        }

        l.push(Fp::rand(rng));
        r.push(Fp::rand(rng));
        o.push(Fp::rand(rng));
        l.push(Fp::rand(rng));
        r.push(Fp::rand(rng));
        o.push(Fp::rand(rng));

        let mut witness = l;
        witness.append(&mut r);
        witness.append(&mut o);

        // verify the circuit satisfiability by the computed witness
        assert_eq!(index.cs.verify(&witness), true);

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
            &group_map, &witness, &index, vec![prev]).unwrap());

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
