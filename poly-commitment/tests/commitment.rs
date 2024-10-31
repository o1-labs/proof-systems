use ark_ff::{One, UniformRand, Zero};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations, Polynomial,
    Radix2EvaluationDomain, Radix2EvaluationDomain as D,
};
use colored::Colorize;
use groupmap::GroupMap;
use mina_curves::pasta::{Fp, Vesta, Vesta as VestaG, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi as SC, sponge::DefaultFqSponge, FqSponge,
};
use o1_utils::ExtendedDensePolynomial as _;
use poly_commitment::{
    commitment::{
        combined_inner_product, BatchEvaluationProof, CommitmentCurve, Evaluation, PolyComm,
    },
    evaluation_proof::DensePolynomialOrEvaluations,
    srs::SRS,
    SRS as SRSTrait,
};
use rand::{CryptoRng, Rng, SeedableRng};
use std::{array, iter::Iterator, time::Instant};

fn test_randomised<RNG: Rng + CryptoRng>(mut rng: &mut RNG) {
    let group_map = <Vesta as CommitmentCurve>::Map::setup();
    // create an SRS optimized for polynomials of degree 2^7 - 1
    let srs = SRS::<Vesta>::create(1 << 7);

    // TODO: move to bench

    let (proofs, time_commit, time_open) =
        poly_commitment::commitment::test_common::generate_random_opening_proof(
            &mut rng, &group_map, &srs,
        );

    println!("{} {:?}", "total commitment time:".yellow(), time_commit);
    println!(
        "{} {:?}",
        "total evaluation proof creation time:".magenta(),
        time_open
    );

    let timer = Instant::now();

    // batch verify all the proofs
    let mut batch: Vec<_> = proofs.iter().map(|p| p.verify_type()).collect();
    assert!(srs.verify::<DefaultFqSponge<VestaParameters, SC>, _>(&group_map, &mut batch, &mut rng));

    // TODO: move to bench
    println!(
        "{} {:?}",
        "batch verification time:".green(),
        timer.elapsed()
    );
}

#[test]
/// Tests polynomial commitments, batched openings and
/// verification of a batch of batched opening proofs of polynomial commitments
fn test_commit()
where
    <Fp as std::str::FromStr>::Err: std::fmt::Debug,
{
    // setup
    let mut rng = o1_utils::tests::make_test_rng(None);
    test_randomised(&mut rng)
}

#[test]
/// Deterministic tests of polynomial commitments, batched openings and
/// verification of a batch of batched opening proofs of polynomial commitments
fn test_commit_deterministic()
where
    <Fp as std::str::FromStr>::Err: std::fmt::Debug,
{
    // Seed deliberately chosen to exercise zero commitments
    let seed = [
        17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];

    let mut rng = <rand_chacha::ChaCha20Rng as SeedableRng>::from_seed(seed);
    test_randomised(&mut rng)
}

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
    let num_chunks = (domain.size() + srs.g.len() - 1) / srs.g.len();
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
    let rng = &mut o1_utils::tests::make_test_rng(None);

    // commit the two polynomials
    let commitment1 = srs.commit(&poly1, 1, rng);
    let commitment2 = srs.commit(&poly2, 1, rng);

    // create an aggregated opening proof
    let (u, v) = (Fp::rand(rng), Fp::rand(rng));
    let group_map = <VestaG as CommitmentCurve>::Map::setup();
    let sponge = DefaultFqSponge::<_, SC>::new(mina_poseidon::pasta::fq_kimchi::static_params());

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
    let elm = vec![Fp::rand(rng), Fp::rand(rng)];

    let opening_proof = srs.open(&group_map, &polys, &elm, v, u, sponge.clone(), rng);

    // evaluate the polynomials at these two points
    let poly1_chunked_evals = vec![
        poly1
            .to_chunked_polynomial(1, srs.g.len())
            .evaluate_chunks(elm[0]),
        poly1
            .to_chunked_polynomial(1, srs.g.len())
            .evaluate_chunks(elm[1]),
    ];

    fn sum(c: &[Fp]) -> Fp {
        c.iter().fold(Fp::zero(), |a, &b| a + b)
    }

    assert_eq!(sum(&poly1_chunked_evals[0]), poly1.evaluate(&elm[0]));
    assert_eq!(sum(&poly1_chunked_evals[1]), poly1.evaluate(&elm[1]));

    let poly2_chunked_evals = vec![
        poly2
            .to_chunked_polynomial(1, srs.g.len())
            .evaluate_chunks(elm[0]),
        poly2
            .to_chunked_polynomial(1, srs.g.len())
            .evaluate_chunks(elm[1]),
    ];

    assert_eq!(sum(&poly2_chunked_evals[0]), poly2.evaluate(&elm[0]));
    assert_eq!(sum(&poly2_chunked_evals[1]), poly2.evaluate(&elm[1]));

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

    // verify the proof
    let mut batch = vec![BatchEvaluationProof {
        sponge,
        evaluation_points: elm.clone(),
        polyscale: v,
        evalscale: u,
        evaluations,
        opening: &opening_proof,
        combined_inner_product,
    }];

    assert!(srs.verify(&group_map, &mut batch, rng));
}
