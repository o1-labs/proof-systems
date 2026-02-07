use ark_bn254::{Config, Fr as ScalarField, G1Affine as G1, G2Affine as G2};
use ark_ec::{bn::Bn, AffineRepr};
use ark_ff::UniformRand;
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Polynomial,
    Radix2EvaluationDomain as D,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use mina_curves::pasta::{Fp, Vesta as VestaG};
use poly_commitment::{
    commitment::Evaluation,
    ipa::SRS,
    kzg::{combine_evaluations, KZGProof, PairingSRS},
    pbt_srs,
    utils::DensePolynomialOrEvaluations,
    PolyComm, SRS as _,
};

#[test]
fn test_combine_evaluations() {
    let nb_of_chunks = 1;

    // we ignore commitments
    let dummy_commitments = PolyComm::<VestaG> {
        chunks: vec![VestaG::zero(); nb_of_chunks],
    };

    let polyscale = Fp::from(2);
    // Using only one evaluation. Starting with eval_p1
    {
        let eval_p1 = Evaluation {
            commitment: dummy_commitments.clone(),
            evaluations: vec![
                // Eval at first point. Only one chunk.
                vec![Fp::from(1)],
                // Eval at second point. Only one chunk.
                vec![Fp::from(2)],
            ],
        };

        let output = combine_evaluations::<VestaG>(&[eval_p1], polyscale);
        // We have 2 evaluation points.
        assert_eq!(output.len(), 2);
        // polyscale is not used.
        let exp_output = [Fp::from(1), Fp::from(2)];
        output.iter().zip(exp_output.iter()).for_each(|(o, e)| {
            assert_eq!(o, e);
        });
    }

    // And after that eval_p2
    {
        let eval_p2 = Evaluation {
            commitment: dummy_commitments.clone(),
            evaluations: vec![
                // Eval at first point. Only one chunk.
                vec![Fp::from(3)],
                // Eval at second point. Only one chunk.
                vec![Fp::from(4)],
            ],
        };

        let output = combine_evaluations::<VestaG>(&[eval_p2], polyscale);
        // We have 2 evaluation points
        assert_eq!(output.len(), 2);
        // polyscale is not used.
        let exp_output = [Fp::from(3), Fp::from(4)];
        output.iter().zip(exp_output.iter()).for_each(|(o, e)| {
            assert_eq!(o, e);
        });
    }

    // Now with two evaluations
    {
        let eval_p1 = Evaluation {
            commitment: dummy_commitments.clone(),
            evaluations: vec![
                // Eval at first point. Only one chunk.
                vec![Fp::from(1)],
                // Eval at second point. Only one chunk.
                vec![Fp::from(2)],
            ],
        };

        let eval_p2 = Evaluation {
            commitment: dummy_commitments.clone(),
            evaluations: vec![
                // Eval at first point. Only one chunk.
                vec![Fp::from(3)],
                // Eval at second point. Only one chunk.
                vec![Fp::from(4)],
            ],
        };

        let output = combine_evaluations::<VestaG>(&[eval_p1, eval_p2], polyscale);
        // We have 2 evaluation points
        assert_eq!(output.len(), 2);
        let exp_output = [Fp::from(1 + 3 * 2), Fp::from(2 + 4 * 2)];
        output.iter().zip(exp_output.iter()).for_each(|(o, e)| {
            assert_eq!(o, e);
        });
    }

    // Now with two evaluations and two chunks
    {
        let eval_p1 = Evaluation {
            commitment: dummy_commitments.clone(),
            evaluations: vec![
                // Eval at first point.
                vec![Fp::from(1), Fp::from(3)],
                // Eval at second point.
                vec![Fp::from(2), Fp::from(4)],
            ],
        };

        let eval_p2 = Evaluation {
            commitment: dummy_commitments.clone(),
            evaluations: vec![
                // Eval at first point.
                vec![Fp::from(5), Fp::from(7)],
                // Eval at second point.
                vec![Fp::from(6), Fp::from(8)],
            ],
        };

        let output = combine_evaluations::<VestaG>(&[eval_p1, eval_p2], polyscale);
        // We have 2 evaluation points
        assert_eq!(output.len(), 2);
        let o1 = Fp::from(1 + 3 * 2 + 5 * 4 + 7 * 8);
        let o2 = Fp::from(2 + 4 * 2 + 6 * 4 + 8 * 8);
        let exp_output = [o1, o2];
        output.iter().zip(exp_output.iter()).for_each(|(o, e)| {
            assert_eq!(o, e);
        });
    }
}

#[test]
fn test_kzg_proof() {
    let n = 64;
    let domain = D::<ScalarField>::new(n).unwrap();

    let mut rng = o1_utils::tests::make_test_rng(None);
    let x = ScalarField::rand(&mut rng);

    let srs = SRS::<G1>::create_trusted_setup_with_toxic_waste(x, n);
    let verifier_srs = SRS::<G2>::create_trusted_setup_with_toxic_waste(x, 3);
    srs.get_lagrange_basis(domain);

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

    let srs: PairingSRS<BN254> = PairingSRS::create(1 << 5);

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

// Testing how many chunks are generated with different polynomial sizes and
// different number of chunks requested.
#[test]
fn test_regression_commit_non_hiding_expected_number_of_chunks() {
    type BN254 = Bn<Config>;
    type Srs = PairingSRS<BN254>;

    pbt_srs::test_regression_commit_non_hiding_expected_number_of_chunks::<G1, Srs>();
}
