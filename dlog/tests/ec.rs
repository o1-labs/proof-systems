use colored::Colorize;
use commitment_dlog::{
    commitment::{b_poly_coefficients, ceil_log2, CommitmentCurve},
    srs::{endos, SRS},
};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{BigInteger, Field, PrimeField, BitIteratorLE, UniformRand, Zero, One};
use ark_poly::{univariate::DensePolynomial, Radix2EvaluationDomain as D, EvaluationDomain};
use plonk_15_wires_circuits::{
    polynomials::endosclmul,
    gate::{CircuitGate, GateType, LookupInfo, LookupsUsed},
    expr::{PolishToken, Constants, Expr, Column, Linearization},
    gates::poseidon::ROUNDS_PER_ROW,
    nolookup::constraints::{zk_w3, ConstraintSystem},
    nolookup::scalars::{ProofEvaluations, LookupEvaluations},
    wires::*,
};
use mina_curves::pasta::{
    fp::{Fp as F},
    pallas::{Affine as Other, Projective as OtherProjective},
    vesta::{Affine, VestaParameters},
};
use plonk_15_wires_protocol_dlog::{
    index::{Index},
    prover::ProverProof,
};
use rand::{rngs::StdRng, SeedableRng};
use array_init::array_init;
use std::fmt::{Formatter, Display};
use groupmap::GroupMap;
use oracle::{
    poseidon::{ArithmeticSponge, PlonkSpongeConstants15W, Sponge, SpongeConstants},
    sponge::{ScalarChallenge, DefaultFqSponge, DefaultFrSponge},
};
use std::{rc::Rc, time::Instant};

const PUBLIC: usize = 0;

type SpongeParams = PlonkSpongeConstants15W;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<F, SpongeParams>;

// Tests add and double gates
#[test]
fn ec_test() {
    let fp_sponge_params = oracle::pasta::fp::params();

    let num_doubles = 100;
    let num_additions = 100;
    let num_infs = 100;

    let mut gates = vec![];

    for row in 0..(num_doubles + num_additions + num_infs) {
        gates.push(
            CircuitGate {
                row,
                typ: GateType::CompleteAdd,
                wires: Wire::new(row),
                c: vec![],
            });
    }

    let cs = ConstraintSystem::<F>::create(
        gates, vec![], fp_sponge_params, PUBLIC).unwrap();
    let n = cs.domain.d1.size as usize;

    let mut srs = SRS::create(cs.domain.d1.size as usize);
    srs.add_lagrange_basis(cs.domain.d1);

    let fq_sponge_params = oracle::pasta::fq::params();
    let (endo_q, endo_r) = endos::<Other>();
    let srs = Rc::new(srs);

    let index = Index::<Affine>::create(cs, fq_sponge_params, endo_q, srs);

    let mut witness: [Vec<F>; COLUMNS] = array_init(|_| vec![F::zero(); n]);

    let verifier_index = index.verifier_index();
    let group_map = <Affine as CommitmentCurve>::Map::setup();

    let lgr_comms = vec![];
    let rng = &mut StdRng::from_seed([0; 32]);

    let start = Instant::now();
    let mut g = Other::prime_subgroup_generator();

    for row in 0..num_doubles {
        let g2 = g + g;
        witness[0][row] = g.x;
        witness[1][row] = g.y;
        witness[2][row] = g2.x;
        witness[3][row] = g2.y;
        witness[4][row] = g.y.inverse().unwrap();
        g = g2;
    }

    let ps = {
        let p = Other::prime_subgroup_generator().into_projective().mul(
            <Other as AffineCurve>::ScalarField::rand(rng).into_repr()).into_affine();
        let mut res = vec![];
        let mut acc = p;
        for i in 0..num_additions {
            res.push(acc);
            acc = acc + p;
        }
        res
    };

    let qs = {
        let q = Other::prime_subgroup_generator().into_projective().mul(
            <Other as AffineCurve>::ScalarField::rand(rng).into_repr()).into_affine();
        let mut res = vec![];
        let mut acc = q;
        for i in 0..num_additions {
            res.push(acc);
            acc = acc + q;
        }
        res
    };

    for i in 0..num_doubles {
        let p = ps[i];


        let row = i;
        let p2 = p + p;
        let (x1, y1) = (p.x, p.y);
        let x1_squared = x1.square();
        // 2 * s * y1 = -3 * x1^2
        let s = (x1_squared.double() + x1_squared) / y1.double();
        witness[0][row] = p.x;
        witness[1][row] = p.y;
        witness[2][row] = p.x;
        witness[3][row] = p.y;
        witness[4][row] = p2.x;
        witness[5][row] = p2.y;
        witness[6][row] = F::zero();
        witness[7][row] = F::one();
        witness[8][row] = s;
        witness[9][row] = F::zero();
        witness[10][row] = F::zero();
    }

    for i in 0..num_additions {
        let p = ps[i];
        let q = qs[i];

        let row = num_doubles + i;

        let pq = p + q;
        let (x1, y1) = (p.x, p.y);
        let (x2, y2) = (q.x, q.y);
        // (x2 - x1) * s = y2 - y1
        let s = (y2 - y1) / (x2 - x1);
        witness[0][row] = x1;
        witness[1][row] = y1;
        witness[2][row] = x2;
        witness[3][row] = y2;
        witness[4][row] = pq.x;
        witness[5][row] = pq.y;
        witness[6][row] = F::zero();
        witness[7][row] = F::zero();
        witness[8][row] = s;
        witness[9][row] = F::zero();
        witness[10][row] = (x2 - x1).inverse().unwrap();
    }

    for i in 0..num_infs {
        let p = ps[i];
        let q = -p;

        let row = num_doubles + num_additions + i;
        let p2 = p + p;
        let (x1, y1) = (p.x, p.y);
        let x1_squared = x1.square();
        // 2 * s * y1 = -3 * x1^2
        let s = (x1_squared.double() + x1_squared) / y1.double();
        witness[0][row] = p.x;
        witness[1][row] = p.y;
        witness[2][row] = q.x;
        witness[3][row] = q.y;
        witness[4][row] = p2.x;
        witness[5][row] = p2.y;
        witness[6][row] = F::one();
        witness[7][row] = F::one();
        witness[8][row] = s;
        witness[9][row] = (q.y - p.y).inverse().unwrap();
        witness[10][row] = F::zero();
    }

    index.cs.verify(&witness).unwrap();

    let start = Instant::now();
    let proof =
        ProverProof::create::<BaseSponge, ScalarSponge>(
            &group_map,
            &witness,
            &index,
            vec![]).unwrap();
    println!("{}{:?}", "Prover time: ".yellow(), start.elapsed());

    let batch: Vec<_> = vec![(&verifier_index, &lgr_comms, &proof)];
    let start = Instant::now();
    match ProverProof::verify::<BaseSponge, ScalarSponge>(&group_map, &batch) {
        Err(error) => panic!("Failure verifying the prover's proofs in batch: {}", error),
        Ok(_) => {
            println!("{}{:?}", "Verifier time: ".yellow(), start.elapsed());
        }
    }
}

