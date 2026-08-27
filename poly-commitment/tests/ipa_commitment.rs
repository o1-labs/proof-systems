use ark_ff::{One, UniformRand, Zero};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations, Polynomial,
    Radix2EvaluationDomain as D, Radix2EvaluationDomain,
};
use groupmap::GroupMap;
use mina_curves::pasta::{Fp, Pallas, Vesta as VestaG, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi as SC, pasta::FULL_ROUNDS, sponge::DefaultFqSponge,
    FqSponge,
};
use o1_utils::ExtendedDensePolynomial;
use poly_commitment::{
    commitment::{combined_inner_product, BatchEvaluationProof, CommitmentCurve, Evaluation},
    ipa::SRS,
    pbt_srs,
    utils::DensePolynomialOrEvaluations,
    PolyComm, SRS as _,
};
use rand::Rng;
use std::{
    array,
    time::{Duration, Instant},
};

#[test]
fn test_lagrange_commitments() {
    let n = 64;
    let domain = D::<Fp>::new(n).unwrap();

    let srs = SRS::<VestaG>::create(n);
    srs.get_lagrange_basis(domain);

    let num_chunks = domain.size() / srs.g.len();

    let expected_lagrange_commitments: Vec<_> = (0..n)
        .map(|i| {
            let mut e = vec![Fp::zero(); n];
            e[i] = Fp::one();
            let p = Evaluations::<Fp, D<Fp>>::from_vec_and_domain(e, domain).interpolate();
            srs.commit_non_hiding(&p, num_chunks)
        })
        .collect();

    let computed_lagrange_commitments = srs.get_lagrange_basis_from_domain_size(domain.size());
    for i in 0..n {
        assert_eq!(
            computed_lagrange_commitments[i],
            expected_lagrange_commitments[i],
        );
    }
}

#[test]
// This tests with two chunks.
fn test_chunked_lagrange_commitments() {
    let n = 64;
    let divisor = 4;
    let domain = D::<Fp>::new(n).unwrap();

    let srs = SRS::<VestaG>::create(n / divisor);
    srs.get_lagrange_basis(domain);

    let num_chunks = domain.size() / srs.g.len();
    assert!(num_chunks == divisor);

    let expected_lagrange_commitments: Vec<_> = (0..n)
        .map(|i| {
            // Generating the i-th element of the lagrange basis
            let mut e = vec![Fp::zero(); n];
            e[i] = Fp::one();
            let p = Evaluations::<Fp, D<Fp>>::from_vec_and_domain(e, domain).interpolate();
            // Committing, and requesting [num_chunks] chunks.
            srs.commit_non_hiding(&p, num_chunks)
        })
        .collect();

    let computed_lagrange_commitments = srs.get_lagrange_basis_from_domain_size(domain.size());
    for i in 0..n {
        assert_eq!(
            computed_lagrange_commitments[i],
            expected_lagrange_commitments[i],
        );
    }
}

#[test]
// TODO @volhovm I don't understand what this test does and
// whether it is worth leaving.
/// Same as test_chunked_lagrange_commitments, but with a slight
/// offset in the SRS
fn test_offset_chunked_lagrange_commitments() {
    let n = 64;
    let domain = D::<Fp>::new(n).unwrap();

    let srs = SRS::<VestaG>::create(n / 2 + 1);
    srs.get_lagrange_basis(domain);

    // Is this even taken into account?...
    let num_chunks = domain.size().div_ceil(srs.g.len());
    assert!(num_chunks == 2);

    let expected_lagrange_commitments: Vec<_> = (0..n)
        .map(|i| {
            let mut e = vec![Fp::zero(); n];
            e[i] = Fp::one();
            let p = Evaluations::<Fp, D<Fp>>::from_vec_and_domain(e, domain).interpolate();
            srs.commit_non_hiding(&p, num_chunks) // this requires max = Some(64)
        })
        .collect();

    let computed_lagrange_commitments = srs.get_lagrange_basis_from_domain_size(domain.size());
    for i in 0..n {
        assert_eq!(
            computed_lagrange_commitments[i],
            expected_lagrange_commitments[i],
        );
    }
}

#[test]
fn test_opening_proof() {
    // create two polynomials
    let coeffs: [Fp; 10] = array::from_fn(|i| Fp::from(i as u32));
    let poly1 = DensePolynomial::<Fp>::from_coefficients_slice(&coeffs);
    let poly2 = DensePolynomial::<Fp>::from_coefficients_slice(&coeffs[..5]);

    // create an SRS
    let srs = SRS::<VestaG>::create(20);
    let mut rng = &mut o1_utils::tests::make_test_rng(None);

    // commit the two polynomials
    let commitment1 = srs.commit(&poly1, 1, rng);
    let commitment2 = srs.commit(&poly2, 1, rng);

    // create an aggregated opening proof
    let (u, v) = (Fp::rand(rng), Fp::rand(rng));
    let group_map = <VestaG as CommitmentCurve>::Map::setup();
    let sponge = DefaultFqSponge::<_, SC, FULL_ROUNDS>::new(
        mina_poseidon::pasta::fq_kimchi::static_params(),
    );

    let polys: Vec<(
        DensePolynomialOrEvaluations<_, Radix2EvaluationDomain<_>>,
        PolyComm<_>,
    )> = vec![
        (
            DensePolynomialOrEvaluations::DensePolynomial(&poly1),
            commitment1.blinders,
        ),
        (
            DensePolynomialOrEvaluations::DensePolynomial(&poly2),
            commitment2.blinders,
        ),
    ];
    // Generate a random number of evaluation point
    let nb_elem: u32 = rng.gen_range(1..7);
    let elm: Vec<Fp> = (0..nb_elem).map(|_| Fp::rand(&mut rng)).collect();
    let opening_proof = srs.open(&group_map, &polys, &elm, v, u, sponge.clone(), rng);

    // evaluate the polynomials at the points
    let poly1_chunked_evals: Vec<Vec<Fp>> = elm
        .iter()
        .map(|elmi| {
            poly1
                .to_chunked_polynomial(1, srs.g.len())
                .evaluate_chunks(*elmi)
        })
        .collect();

    fn sum(c: &[Fp]) -> Fp {
        c.iter().fold(Fp::zero(), |a, &b| a + b)
    }

    for (i, chunks) in poly1_chunked_evals.iter().enumerate() {
        assert_eq!(sum(chunks), poly1.evaluate(&elm[i]))
    }

    let poly2_chunked_evals: Vec<Vec<Fp>> = elm
        .iter()
        .map(|elmi| {
            poly2
                .to_chunked_polynomial(1, srs.g.len())
                .evaluate_chunks(*elmi)
        })
        .collect();

    for (i, chunks) in poly2_chunked_evals.iter().enumerate() {
        assert_eq!(sum(chunks), poly2.evaluate(&elm[i]))
    }

    let evaluations = vec![
        Evaluation {
            commitment: commitment1.commitment,
            evaluations: poly1_chunked_evals,
        },
        Evaluation {
            commitment: commitment2.commitment,
            evaluations: poly2_chunked_evals,
        },
    ];

    let combined_inner_product = {
        let es: Vec<_> = evaluations
            .iter()
            .map(|Evaluation { evaluations, .. }| evaluations.clone())
            .collect();
        combined_inner_product(&v, &u, &es)
    };

    {
        // create the proof
        let mut batch = vec![BatchEvaluationProof {
            sponge,
            evaluation_points: elm,
            polyscale: v,
            evalscale: u,
            evaluations,
            opening: &opening_proof,
            combined_inner_product,
        }];

        assert!(srs.verify(&group_map, &mut batch, rng));
    }
}

// Testing how many chunks are generated with different polynomial sizes and
// different number of chunks requested.
#[test]
fn test_regression_commit_non_hiding_expected_number_of_chunks() {
    pbt_srs::test_regression_commit_non_hiding_expected_number_of_chunks::<VestaG, SRS<VestaG>>();
    pbt_srs::test_regression_commit_non_hiding_expected_number_of_chunks::<Pallas, SRS<Pallas>>()
}

#[test]
fn test_dlog_commitment() {
    let rng = &mut rand::thread_rng();
    let mut random = rand::thread_rng();

    let size = 1 << 7;
    let srs = SRS::<VestaG>::create(size);

    let group_map = <VestaG as CommitmentCurve>::Map::setup();

    let sponge = DefaultFqSponge::<VestaParameters, SC, FULL_ROUNDS>::new(
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
            let proof = srs
                .open::<DefaultFqSponge<VestaParameters, SC, FULL_ROUNDS>, _, _, FULL_ROUNDS>(
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
    let result = srs.verify::<DefaultFqSponge<VestaParameters, SC, FULL_ROUNDS>, _, FULL_ROUNDS>(
        &group_map,
        &mut proofs,
        rng,
    );
    assert!(result);
    println!("verification time: {:?}", start.elapsed());
}
