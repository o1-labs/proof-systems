/*********************************************************************************************************

This source file benchmark constraints for the Poseidon hash permutations

**********************************************************************************************************/

use commitment_dlog::{srs::SRS, commitment::CommitmentCurve};
use plonk_circuits::{wires::GateWires, gate::CircuitGate, constraints::ConstraintSystem};
use oracle::{poseidon::{ArithmeticSponge, ArithmeticSpongeParams, Sponge}, sponge::{DefaultFqSponge, DefaultFrSponge}};
use algebra::{bn_382::g::{Affine, Bn_382GParameters}, AffineCurve, UniformRand};
use plonk_protocol_dlog::{prover::{ProverProof}, index::{Index, SRSSpec}};
use std::{io, io::Write};
use oracle::poseidon::*;
use groupmap::GroupMap;
use std::time::Instant;
use colored::Colorize;
use rand_core::OsRng;

type Fr = <Affine as AffineCurve>::ScalarField;

const PERIOD: usize = ROUNDS_FULL + 1;
const MAX_SIZE: usize = 10000; // max size of poly chunks
const NUM_POS: usize = 256; // number of Poseidon hashes in the circuit
const N: usize = PERIOD * NUM_POS; // Plonk domain size

#[test]
fn poseidon_bn382()
{
    let c = &oracle::bn_382::fq::params().round_constants;

    // circuit gates

    let mut i = 0;
    let mut gates: Vec<CircuitGate::<Fr>> = Vec::with_capacity(N);

    // custom constraints for Poseidon hash function permutation

    for _ in 0..NUM_POS
    {
        // ROUNDS_FULL full rounds constraint gates
        for j in 0..ROUNDS_FULL
        {
            gates.push(CircuitGate::<Fr>::create_poseidon(GateWires::wires((i, (i+PERIOD)%N), (i+N, N+((i+PERIOD)%N)), (i+2*N, 2*N+((i+PERIOD)%N))), [c[j][0],c[j][1],c[j][2]]));
            i+=1;
        }
        gates.push(CircuitGate::<Fr>::zero(GateWires::wires((i, (i+PERIOD)%N), (i+N, N+((i+PERIOD)%N)), (i+2*N, 2*N+((i+PERIOD)%N)))));
        i+=1;
    }

    let srs = SRS::create(MAX_SIZE);

    let index = Index::<Affine>::create
    (
        ConstraintSystem::<Fr>::create(gates, 0).unwrap(),
        MAX_SIZE,
        oracle::bn_382::fq::params() as ArithmeticSpongeParams<Fr>,
        oracle::bn_382::fp::params(),
        SRSSpec::Use(&srs)
    );
    
    positive(&index);
}

fn positive(index: &Index<Affine>)
where <Fr as std::str::FromStr>::Err : std::fmt::Debug
{
    let rng = &mut OsRng;

    let params: ArithmeticSpongeParams<Fr> = oracle::bn_382::fq::params();
    let mut sponge = ArithmeticSponge::<Fr>::new();

    let mut batch = Vec::new();
    let group_map = <Affine as CommitmentCurve>::Map::setup();

    println!("{}{:?}", "Circuit size: ".yellow(), N);
    println!("{}{:?}", "Polycommitment chunk size: ".yellow(), MAX_SIZE);
    println!("{}{:?}", "Number oh Poseidon hashes in the circuit: ".yellow(), NUM_POS);
    println!("{}{:?}", "Full rounds: ".yellow(), ROUNDS_FULL);
    println!("{}{:?}", "Sbox alpha: ".yellow(), SPONGE_BOX);
    println!("{}", "Base curve: bn_382".green());
    println!();
    println!("{}", "Prover zk-proof computation".green());
    let mut start = Instant::now();

    for test in 0..1
    {
        let mut l: Vec<Fr> = Vec::with_capacity(N);
        let mut r: Vec<Fr> = Vec::with_capacity(N);
        let mut o: Vec<Fr> = Vec::with_capacity(N);

        let (x, y, z) = (Fr::rand(rng), Fr::rand(rng), Fr::rand(rng));
        
        //  witness for Poseidon permutation custom constraints
        for _ in 0..NUM_POS
        {
            sponge.state = vec![x, y, z];
            l.push(sponge.state[0]);
            r.push(sponge.state[1]);
            o.push(sponge.state[2]);

            // HALF_ROUNDS_FULL full rounds
            for j in 0..ROUNDS_FULL
            {
                sponge.full_round(j, &params);
                l.push(sponge.state[0]);
                r.push(sponge.state[1]);
                o.push(sponge.state[2]);
            }
        }
        let mut witness = l;
        witness.append(&mut r);
        witness.append(&mut o);

        // verify the circuit satisfiability by the computed witness
        assert_eq!(index.cs.verify(&witness), true);

        // add the proof to the batch
        batch.push(ProverProof::create::<DefaultFqSponge<Bn_382GParameters>, DefaultFrSponge<Fr>>(
            &group_map, &witness, &index).unwrap());

        print!("{:?}\r", test);
        io::stdout().flush().unwrap();
    }
    println!("{}{:?}", "Execution time: ".yellow(), start.elapsed());

    let verifier_index = index.verifier_index();
    // verify the proofs in batch
    println!("{}", "Verifier zk-proofs verification".green());
    start = Instant::now();
    match ProverProof::verify::<DefaultFqSponge<Bn_382GParameters>, DefaultFrSponge<Fr>>(&group_map, &batch, &verifier_index)
    {
        Err(error) => {panic!("Failure verifying the prover's proofs in batch: {}", error)},
        Ok(_) => {println!("{}{:?}", "Execution time: ".yellow(), start.elapsed());}
    }
}
