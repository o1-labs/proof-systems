//! This module tests polynomial commitments, batched openings and
//! verification of a batch of batched opening proofs of polynomial commitments

use ark_ff::{UniformRand, Zero};
use commitment_dlog::{commitment::CommitmentCurve, srs::SRS};
use mina_curves::pasta::{
    vesta::{Affine, VestaParameters},
    Fp,
};
use o1_utils::ExtendedDensePolynomial;

use oracle::poseidon::PlonkSpongeConstants15W as SC;
use oracle::sponge::DefaultFqSponge;
use oracle::FqSponge;

use ark_poly::{univariate::DensePolynomial, UVPolynomial};
use colored::Colorize;
use groupmap::GroupMap;
use rand::Rng;
use std::time::{Duration, Instant};

#[test]
fn dlog_commitment_test()
where
    <Fp as std::str::FromStr>::Err: std::fmt::Debug,
{
    let rng = &mut rand::thread_rng();
    let mut random = rand::thread_rng();

    let size = 1 << 7;
    let srs = SRS::<Affine>::create(size);

    let group_map = <Affine as CommitmentCurve>::Map::setup();
    let sponge = DefaultFqSponge::<VestaParameters, SC>::new(oracle::pasta::fq::params());

    let mut commit = Duration::new(0, 0);
    let mut open = Duration::new(0, 0);

    let prfs = (0..7)
        .map(|_| {
            let length = (0..11)
                .map(|_| {
                    let polysize = 500;
                    let len: usize = random.gen();
                    (len % polysize) + 1
                })
                .collect::<Vec<_>>();
            println!("{}{:?}", "sizes: ".bright_cyan(), length);

            let a = length
                .iter()
                .map(|s| {
                    if *s == 0 {
                        DensePolynomial::<Fp>::zero()
                    } else {
                        DensePolynomial::<Fp>::rand(s - 1, rng)
                    }
                })
                .collect::<Vec<_>>();
            let bounds = a
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    if i % 2 == 0 {
                        Some(v.coeffs.len())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();

            let x = (0..7).map(|_| Fp::rand(rng)).collect::<Vec<Fp>>();
            let polymask = Fp::rand(rng);
            let evalmask = Fp::rand(rng);

            let mut start = Instant::now();
            let comm = (0..a.len())
                .map(|i| {
                    (
                        srs.commit(&a[i].clone(), bounds[i], rng),
                        x.iter().map(|xx| a[i].eval(*xx, size)).collect::<Vec<_>>(),
                        bounds[i],
                    )
                })
                .collect::<Vec<_>>();
            commit += start.elapsed();

            start = Instant::now();
            let polys: Vec<_> = (0..a.len())
                .map(|i| (&a[i], bounds[i], (comm[i].0).1.clone()))
                .collect();
            let proof = srs.open::<DefaultFqSponge<VestaParameters, SC>, _>(
                &group_map,
                &polys,
                &x,
                polymask,
                evalmask,
                sponge.clone(),
                rng,
            );
            open += start.elapsed();

            (sponge.clone(), x.clone(), polymask, evalmask, comm, proof)
        })
        .collect::<Vec<_>>();

    let mut proofs = prfs
        .iter()
        .map(|proof| {
            (
                proof.0.clone(),
                proof.1.clone(),
                proof.2,
                proof.3,
                proof
                    .4
                    .iter()
                    .map(|poly| (&(poly.0).0, poly.1.iter().collect::<Vec<_>>(), poly.2))
                    .collect::<Vec<_>>(),
                &proof.5,
            )
        })
        .collect::<Vec<_>>();

    println!("{}{:?}", "commitment time: ".yellow(), commit);
    println!("{}{:?}", "open time: ".magenta(), open);

    let start = Instant::now();
    assert!(srs.verify::<DefaultFqSponge<VestaParameters, SC>, _>(&group_map, &mut proofs, rng));
    println!("{}{:?}", "verification time: ".green(), start.elapsed());
}
