//! This module tests polynomial commitments, batched openings and
//! verification of a batch of batched opening proofs of polynomial commitments

use ark_ff::{UniformRand, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Radix2EvaluationDomain};
use groupmap::GroupMap;
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi as SC, sponge::DefaultFqSponge, FqSponge,
};
use o1_utils::ExtendedDensePolynomial as _;
use poly_commitment::{
    commitment::{combined_inner_product, BatchEvaluationProof, CommitmentCurve, Evaluation},
    ipa::SRS,
    utils::DensePolynomialOrEvaluations,
    SRS as _,
};
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
    let srs = SRS::<Vesta>::create(size);

    let group_map = <Vesta as CommitmentCurve>::Map::setup();

    let sponge = DefaultFqSponge::<VestaParameters, SC>::new(
        mina_poseidon::pasta::fq_kimchi::static_params(),
    );

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
            println!("sized: {:?}", length);

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

            // TODO @volhovm remove?
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
                    let n = a[i].len();
                    let num_chunks = if n == 0 {
                        1
                    } else {
                        n / srs.g.len() + if n % srs.g.len() == 0 { 0 } else { 1 }
                    };
                    (
                        srs.commit(&a[i].clone(), num_chunks, rng),
                        x.iter()
                            .map(|xx| {
                                a[i].to_chunked_polynomial(num_chunks, size)
                                    .evaluate_chunks(*xx)
                            })
                            .collect::<Vec<_>>(),
                        bounds[i],
                    )
                })
                .collect::<Vec<_>>();
            commit += start.elapsed();

            start = Instant::now();
            let polys: Vec<(
                DensePolynomialOrEvaluations<_, Radix2EvaluationDomain<_>>,
                _,
            )> = (0..a.len())
                .map(|i| {
                    (
                        DensePolynomialOrEvaluations::DensePolynomial(&a[i]),
                        (comm[i].0).blinders.clone(),
                    )
                })
                .collect();
            let proof = srs.open::<DefaultFqSponge<VestaParameters, SC>, _, _>(
                &group_map,
                &polys,
                &x,
                polymask,
                evalmask,
                sponge.clone(),
                rng,
            );
            open += start.elapsed();

            let combined_inner_product = {
                let es: Vec<_> = comm
                    .iter()
                    .map(|(_, evaluations, _)| evaluations.clone())
                    .collect();
                combined_inner_product(&polymask, &evalmask, &es)
            };

            (
                sponge.clone(),
                x,
                polymask,
                evalmask,
                comm,
                proof,
                combined_inner_product,
            )
        })
        .collect::<Vec<_>>();

    let mut proofs = prfs
        .iter()
        .map(|proof| BatchEvaluationProof {
            sponge: proof.0.clone(),
            evaluation_points: proof.1.clone(),
            polyscale: proof.2,
            evalscale: proof.3,
            evaluations: proof
                .4
                .iter()
                .map(|poly| Evaluation {
                    commitment: (poly.0).commitment.clone(),
                    evaluations: poly.1.clone(),
                })
                .collect::<Vec<_>>(),
            opening: &proof.5,
            combined_inner_product: proof.6,
        })
        .collect::<Vec<_>>();

    println!("commitment time: {:?}", commit);
    println!("open time: {:?}", open);

    let start = Instant::now();
    assert!(srs.verify::<DefaultFqSponge<VestaParameters, SC>, _>(&group_map, &mut proofs, rng));
    println!("verification time: {:?}", start.elapsed());
}
