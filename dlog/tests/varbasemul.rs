use colored::Colorize;
use commitment_dlog::{
    commitment::{b_poly_coefficients, ceil_log2, CommitmentCurve},
    srs::{endos, SRS},
};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{BigInteger, Field, PrimeField, BitIteratorLE, UniformRand, Zero, One};
use ark_poly::{univariate::DensePolynomial, Radix2EvaluationDomain as D, EvaluationDomain};
use plonk_15_wires_circuits::{
    polynomials::varbasemul,
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
    index::{Index, SRSSpec},
    prover::ProverProof,
};
use rand::{rngs::StdRng, SeedableRng};
use array_init::array_init;
use std::fmt::{Formatter, Display};
use groupmap::GroupMap;
use oracle::{
    poseidon::{ArithmeticSponge, PlonkSpongeConstants15W, Sponge, SpongeConstants},
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use std::{rc::Rc, time::Instant};

const PUBLIC: usize = 0;

type SpongeParams = PlonkSpongeConstants15W;
type BaseSponge = DefaultFqSponge<VestaParameters, SpongeParams>;
type ScalarSponge = DefaultFrSponge<F, SpongeParams>;

#[test]
fn varbase_mul_test() {
    let fp_sponge_params = oracle::pasta::fp::params();

    let num_bits = F::size_in_bits();
    let chunks = num_bits / 5;

    let num_scalars = 10;

    assert_eq!(num_bits % 5, 0);

    let mut gates = vec![];

    for i in 0..(chunks * num_scalars) {
        let row = 2 * i;
        gates.push(
            CircuitGate {
                row,
                typ: GateType::Vbmul,
                wires: Wire::new(row),
                c: vec![],
            });
        gates.push(
            CircuitGate {
                row: row + 1,
                typ: GateType::Zero,
                wires: Wire::new(row + 1),
                c: vec![]
            });
    }

    let cs = ConstraintSystem::<F>::create(
        gates, vec![], fp_sponge_params, PUBLIC).unwrap();
    let n = cs.domain.d1.size as usize;

    let mut srs = SRS::create(cs.domain.d1.size as usize);
    srs.add_lagrange_basis(cs.domain.d1);

    let fq_sponge_params = oracle::pasta::fq::params();
    let (endo_q, _endo_r) = endos::<Other>();
    let srs = Rc::new(srs);

    let index = Index::<Affine>::create(cs, fq_sponge_params, endo_q, srs);

    let mut witness: [Vec<F>; COLUMNS] = array_init(|_| vec![F::zero(); n]);

    let verifier_index = index.verifier_index();
    let group_map = <Affine as CommitmentCurve>::Map::setup();

    let lgr_comms = vec![];
    let rng = &mut StdRng::from_seed([0; 32]);

    let rows_per_scalar = 2 * (255 / 5);

    let start = Instant::now();
    for i in 0..num_scalars {
        let x = F::rand(rng);
        let bits_lsb: Vec<_> = BitIteratorLE::new(x.into_repr()).take(num_bits).collect();
        let x_ = <Other as AffineCurve>::ScalarField::from_repr(<F as PrimeField>::BigInt::from_bits_le(&bits_lsb[..])).unwrap();

        let base = Other::prime_subgroup_generator();
        let g = Other::prime_subgroup_generator().into_projective();
        let acc = (g + g).into_affine();
        let acc = (acc.x, acc.y);

        let bits_msb: Vec<_> =
            bits_lsb.iter().take(num_bits).map(|x| *x).rev().collect();

        let mut res =
            varbasemul::witness(
                &mut witness,
                i * rows_per_scalar,
                (base.x, base.y),
                &bits_msb,
                acc);

        let shift = <Other as AffineCurve>::ScalarField::from(2).pow(&[(bits_msb.len()) as u64]);
        let expected =
            g.mul((<Other as AffineCurve>::ScalarField::one() + shift + x_.double()).into_repr())
            .into_affine();

        assert_eq!(x_.into_repr(), res.n.into_repr());
        assert_eq!((expected.x, expected.y), res.acc);
    }
    println!("{}{:?}", "Witness generation time: ".yellow(), start.elapsed());

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
