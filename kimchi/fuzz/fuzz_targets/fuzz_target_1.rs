#![no_main]
use kimchi::{
    poly_commitment::{
        commitment::{CommitmentCurve, Evaluation, BatchEvaluationProof, combined_inner_product},
        evaluation_proof::DensePolynomialOrEvaluations,
        srs::SRS,
        PolyComm,
    },
    mina_curves::pasta::{Fp, Vesta},
    mina_poseidon::{
        sponge::{FqSponge, DefaultFqSponge}, 
        constants::PlonkSpongeConstantsKimchi
    },
    groupmap::GroupMap,
    o1_utils::dense_polynomial::ExtendedDensePolynomial
};
use ark_poly::{UVPolynomial, Polynomial, Radix2EvaluationDomain, univariate::DensePolynomial};
use ark_ff::{UniformRand, Zero};
use std::array;
use rand::prelude::*;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let coeffs: [Fp; 10] = array::from_fn(|i| Fp::from(i as u32));
    let poly1 = DensePolynomial::<Fp>::from_coefficients_slice(&coeffs);
    let poly2 = DensePolynomial::<Fp>::from_coefficients_slice(&coeffs[..5]);

    let srs = SRS::<Vesta>::create(20);
    if data.len() == 32 {
        let rng = &mut StdRng::from_seed(data[..32].try_into().unwrap());

        let commitment = srs.commit(&poly1, None, rng);
        let upperbound = poly2.degree() + 1;
        let bounded_commitment = srs.commit(&poly2, Some(upperbound), rng);

        let (u, v) = (Fp::rand(rng), Fp::rand(rng));
        let group_map = <Vesta as CommitmentCurve>::Map::setup();
        let sponge =
            DefaultFqSponge::<_, PlonkSpongeConstantsKimchi>::new(kimchi::mina_poseidon::pasta::fq_kimchi::static_params());

        let polys: Vec<(
            DensePolynomialOrEvaluations<_, Radix2EvaluationDomain<_>>,
            Option<usize>,
            PolyComm<_>,
        )> = vec![
            (
                DensePolynomialOrEvaluations::DensePolynomial(&poly1),
                None,
                commitment.blinders,
            ),
            (
                DensePolynomialOrEvaluations::DensePolynomial(&poly2),
                Some(upperbound),
                bounded_commitment.blinders,
            ),
        ];
        let elm = vec![Fp::rand(rng), Fp::rand(rng)];

        let opening_proof = srs.open(&group_map, &polys, &elm, v, u, sponge.clone(), rng);

        let poly1_chunked_evals = vec![
            poly1
                .to_chunked_polynomial(srs.g.len())
                .evaluate_chunks(elm[0]),
            poly1
                .to_chunked_polynomial(srs.g.len())
                .evaluate_chunks(elm[1]),
        ];

        fn sum(c: &[Fp]) -> Fp {
            c.iter().fold(Fp::zero(), |a, &b| a + b)
        }

        assert_eq!(sum(&poly1_chunked_evals[0]), poly1.evaluate(&elm[0]));
        assert_eq!(sum(&poly1_chunked_evals[1]), poly1.evaluate(&elm[1]));

        let poly2_chunked_evals = vec![
            poly2
                .to_chunked_polynomial(srs.g.len())
                .evaluate_chunks(elm[0]),
            poly2
                .to_chunked_polynomial(srs.g.len())
                .evaluate_chunks(elm[1]),
        ];

        assert_eq!(sum(&poly2_chunked_evals[0]), poly2.evaluate(&elm[0]));
        assert_eq!(sum(&poly2_chunked_evals[1]), poly2.evaluate(&elm[1]));

        let evaluations = vec![
            Evaluation {
                commitment: commitment.commitment,
                evaluations: poly1_chunked_evals,
                degree_bound: None,
            },
            Evaluation {
                commitment: bounded_commitment.commitment,
                evaluations: poly2_chunked_evals,
                degree_bound: Some(upperbound),
            },
        ];

        let combined_inner_product = {
            let es: Vec<_> = evaluations
                .iter()
                .map(
                    |Evaluation {
                         commitment,
                         evaluations,
                         degree_bound,
                     }| {
                        let bound: Option<usize> = (|| {
                            let b = (*degree_bound)?;
                            let x = commitment.shifted?;
                            if x.is_zero() {
                                None
                            } else {
                                Some(b)
                            }
                        })();
                        (evaluations.clone(), bound)
                    },
                )
                .collect();
            combined_inner_product(&elm, &v, &u, &es, srs.g.len())
        };

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
});
