/*********************************************************************************************************

This source file benchmark constraints for the Poseidon hash permutations

**********************************************************************************************************/

use plonk_circuits::{wires::GateWires, gate::CircuitGate, constraints::ConstraintSystem};
use commitment_dlog::{srs::{endos, SRS}, commitment::{CommitmentCurve, ceil_log2, product, b_poly_coefficients}};
use oracle::{poseidon::{ArithmeticSponge, ArithmeticSpongeParams, Sponge, PlonkSpongeConstants as SC}, sponge::{DefaultFqSponge, DefaultFrSponge}};
use algebra::{Field, bn_382::{G1Affine as Other}, bn_382::g::{Affine, Bn_382GParameters}, AffineCurve, UniformRand};
use plonk_protocol_dlog::{prover::{ProverProof}, index::{Index, SRSSpec}};
use ff_fft::DensePolynomial;
use std::{io, io::Write};
use oracle::poseidon::*;
use groupmap::GroupMap;
use std::time::Instant;
use colored::Colorize;
use rand_core::OsRng;

type Fr = <Affine as AffineCurve>::ScalarField;

const PERIOD: usize = SC::ROUNDS_FULL + 1;
const MAX_SIZE: usize = 10000; // max size of poly chunks
const NUM_POS: usize = 256; // number of Poseidon hashes in the circuit
const N: usize = PERIOD * NUM_POS; // Plonk domain size
const PUBLIC : usize = 0;

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
        for j in 0..SC::ROUNDS_FULL
        {
            gates.push(CircuitGate::<Fr>::create_poseidon(GateWires::wires((i, (i+PERIOD)%N), (i+N, N+((i+PERIOD)%N)), (i+2*N, 2*N+((i+PERIOD)%N))), [c[j][0],c[j][1],c[j][2]]));
            i+=1;
        }
        gates.push(CircuitGate::<Fr>::zero(GateWires::wires((i, (i+PERIOD)%N), (i+N, N+((i+PERIOD)%N)), (i+2*N, 2*N+((i+PERIOD)%N)))));
        i+=1;
    }

    let srs = SRS::create(MAX_SIZE);

    let (endo_q, _) = endos::<Other>();
    let index = Index::<Affine>::create
    (
        ConstraintSystem::<Fr>::create(gates, oracle::bn_382::fq::params() as ArithmeticSpongeParams<Fr>, PUBLIC).unwrap(),
        oracle::bn_382::fp::params(),
        endo_q,
        SRSSpec::Use(&srs)
    );

    positive(&index);
}

fn positive(index: &Index<Affine>)
where <Fr as std::str::FromStr>::Err : std::fmt::Debug
{
    let rng = &mut OsRng;

    let params: ArithmeticSpongeParams<Fr> = oracle::bn_382::fq::params();
    let mut sponge = ArithmeticSponge::<Fr, SC>::new();

    let mut batch = Vec::new();
    let group_map = <Affine as CommitmentCurve>::Map::setup();

    println!("{}{:?}", "Circuit size: ".yellow(), N);
    println!("{}{:?}", "Polycommitment chunk size: ".yellow(), MAX_SIZE);
    println!("{}{:?}", "Number oh Poseidon hashes in the circuit: ".yellow(), NUM_POS);
    println!("{}{:?}", "Full rounds: ".yellow(), SC::ROUNDS_FULL);
    println!("{}{:?}", "Sbox alpha: ".yellow(), SC::SPONGE_BOX);
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
            for j in 0..SC::ROUNDS_FULL
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

        let prev = {
            let k = ceil_log2(index.srs.get_ref().g.len());
            let chals : Vec<_> = (0..k).map(|_| Fr::rand(rng)).collect();
            let comm = {
                let b = DensePolynomial::from_coefficients_vec(b_poly_coefficients(&chals));
                index.srs.get_ref().commit(&b, None)
            };
            ( chals, comm )
        };

        // add the proof to the batch
        batch.push(ProverProof::create::<DefaultFqSponge<Bn_382GParameters, SC>, DefaultFrSponge<Fr, SC>>(
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
    match ProverProof::verify::<DefaultFqSponge<Bn_382GParameters, SC>, DefaultFrSponge<Fr, SC>>(&group_map, &batch)
    {
        Err(error) => {panic!("Failure verifying the prover's proofs in batch: {}", error)},
        Ok(_) => {println!("{}{:?}", "Execution time: ".yellow(), start.elapsed());}
    }
}
