use ark_bn254::{Config, Fr as ScalarField, G1Affine as G1, G2Affine as G2};
use ark_ec::{bn::Bn, AffineRepr};
use ark_ff::UniformRand;
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Polynomial,
    Radix2EvaluationDomain as D,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use poly_commitment::{
    commitment::Evaluation,
    ipa::{DensePolynomialOrEvaluations, SRS},
    kzg::{KZGProof, PairingSRS},
    SRS as _,
};

#[test]
fn test_kzg_proof() {
    let n = 64;
    let domain = D::<ScalarField>::new(n).unwrap();

    let mut rng = o1_utils::tests::make_test_rng(None);
    let x = ScalarField::rand(&mut rng);

    let mut srs = unsafe { SRS::<G1>::create_trusted_setup(x, n) };
    let verifier_srs = unsafe { SRS::<G2>::create_trusted_setup(x, 3) };
    srs.add_lagrange_basis(domain);

    let srs = PairingSRS {
        full_srs: srs,
        verifier_srs,
    };

    let polynomials: Vec<_> = (0..4)
        .map(|_| {
            let coeffs = (0..63).map(|_| ScalarField::rand(&mut rng)).collect();
            DensePolynomial::from_coefficients_vec(coeffs)
        })
        .collect();

    let comms: Vec<_> = polynomials
        .iter()
        .map(|p| srs.full_srs.commit(p, 1, &mut rng))
        .collect();

    let polynomials_and_blinders: Vec<(DensePolynomialOrEvaluations<_, D<_>>, _)> = polynomials
        .iter()
        .zip(comms.iter())
        .map(|(p, comm)| {
            let p = DensePolynomialOrEvaluations::DensePolynomial(p);
            (p, comm.blinders.clone())
        })
        .collect();

    let evaluation_points = vec![ScalarField::rand(&mut rng), ScalarField::rand(&mut rng)];

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

    let polyscale = ScalarField::rand(&mut rng);

    let kzg_proof = KZGProof::<Bn<Config>>::create(
        &srs,
        polynomials_and_blinders.as_slice(),
        &evaluation_points,
        polyscale,
    )
    .unwrap();

    let res = kzg_proof.verify(&srs, &evaluations, polyscale, &evaluation_points);
    assert!(res);
}

/// Our points in G2 are not actually in the correct subgroup and serialize well.
#[test]
fn check_srs_g2_valid_and_serializes() {
    type BN254 = Bn<Config>;
    type BN254G2BaseField = <G2 as AffineRepr>::BaseField;
    type Fp = ark_bn254::Fr;

    let mut rng = o1_utils::tests::make_test_rng(None);

    let x = Fp::rand(&mut rng);
    let srs: PairingSRS<BN254> = unsafe { PairingSRS::create(x, 1 << 5) };

    let mut vec: Vec<u8> = vec![0u8; 1024];

    for actual in [
        srs.verifier_srs.h,
        srs.verifier_srs.g[0],
        srs.verifier_srs.g[1],
    ] {
        // Check it's valid
        assert!(!actual.is_zero());
        assert!(actual.is_on_curve());
        assert!(actual.is_in_correct_subgroup_assuming_on_curve());

        // Check it serializes well
        let actual_y: BN254G2BaseField = actual.y;
        let res = actual_y.serialize_compressed(vec.as_mut_slice());
        assert!(res.is_ok());
        let expected: BN254G2BaseField =
            CanonicalDeserialize::deserialize_compressed(vec.as_slice()).unwrap();
        assert!(expected == actual_y, "serialization failed");
    }
}
