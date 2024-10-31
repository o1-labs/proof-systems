use ark_bn254::{Config, Fr as ScalarField, G1Affine as G1, G2Affine as G2};
use ark_ec::bn::Bn;
use ark_ff::UniformRand;
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Polynomial,
    Radix2EvaluationDomain as D,
};
use poly_commitment::{
    commitment::Evaluation,
    evaluation_proof::DensePolynomialOrEvaluations,
    pairing_proof::{PairingProof, PairingSRS},
    srs::SRS,
    SRS as _,
};

#[test]
fn test_pairing_proof() {
    let n = 64;
    let domain = D::<ScalarField>::new(n).unwrap();

    let rng = &mut o1_utils::tests::make_test_rng(None);

    let x = ScalarField::rand(rng);

    let srs = SRS::<G1>::create_trusted_setup(x, n);
    let verifier_srs = SRS::<G2>::create_trusted_setup(x, 3);
    srs.get_lagrange_basis(domain);

    let srs = PairingSRS {
        full_srs: srs,
        verifier_srs,
    };

    let polynomials: Vec<_> = (0..4)
        .map(|_| {
            let coeffs = (0..63).map(|_| ScalarField::rand(rng)).collect();
            DensePolynomial::from_coefficients_vec(coeffs)
        })
        .collect();

    let comms: Vec<_> = polynomials
        .iter()
        .map(|p| srs.full_srs.commit(p, 1, rng))
        .collect();

    let polynomials_and_blinders: Vec<(DensePolynomialOrEvaluations<_, D<_>>, _)> = polynomials
        .iter()
        .zip(comms.iter())
        .map(|(p, comm)| {
            let p = DensePolynomialOrEvaluations::DensePolynomial(p);
            (p, comm.blinders.clone())
        })
        .collect();

    let evaluation_points = vec![ScalarField::rand(rng), ScalarField::rand(rng)];

    let evaluations: Vec<_> = polynomials
        .iter()
        .zip(comms)
        .map(|(p, commitment)| {
            let evaluations = evaluation_points
                .iter()
                .map(|x| {
                    // Inputs are chosen to use only 1 chunk
                    vec![p.evaluate(x)]
                })
                .collect();
            Evaluation {
                commitment: commitment.commitment,
                evaluations,
            }
        })
        .collect();

    let polyscale = ScalarField::rand(rng);

    let pairing_proof = PairingProof::<Bn<Config>>::create(
        &srs,
        polynomials_and_blinders.as_slice(),
        &evaluation_points,
        polyscale,
    )
    .unwrap();

    let res = pairing_proof.verify(&srs, &evaluations, polyscale, &evaluation_points);
    assert!(res);
}
