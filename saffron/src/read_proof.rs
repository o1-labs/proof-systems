//! This module defines the read proof prover and verifier. Given a
//! query vector q, a vector of data d, and a commitment to this data
//! C, the prover will return an answer a and a proof that the answers
//! correspond to the data committed in C at the specified indexes in
//! the query.
//!
//! The folding version is TBD
//! We call data the data vector that is stored and queried
//! We call answer the vector such that `answer[i] = data[i] * query[i]`

use crate::{Curve, CurveFqSponge, CurveFrSponge, ScalarField};
use ark_ff::{Field, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Polynomial,
    Radix2EvaluationDomain as R2D,
};
use kimchi::{circuits::domains::EvaluationDomains, curve::KimchiCurve, plonk_sponge::FrSponge};
use mina_poseidon::FqSponge;
use poly_commitment::{
    commitment::{combined_inner_product, BatchEvaluationProof, CommitmentCurve, Evaluation},
    ipa::{OpeningProof, SRS},
    utils::DensePolynomialOrEvaluations,
    PolyComm, SRS as _,
};
use rand::{CryptoRng, RngCore};
use tracing::instrument;

fn to_polynomial(evals: &[ScalarField], domain: R2D<ScalarField>) -> DensePolynomial<ScalarField> {
    let evals = Evaluations::from_vec_and_domain(evals.to_vec(), domain);
    evals.interpolate_by_ref()
}

fn to_polynomial_and_commitment(
    evals: &[ScalarField],
    domain: R2D<ScalarField>,
    srs: &SRS<Curve>,
) -> (DensePolynomial<ScalarField>, Curve) {
    let poly = to_polynomial(evals, domain);
    let comm: Curve = srs.commit_non_hiding(&poly, 1).chunks[0];
    (poly, comm)
}

// #[serde_as]
#[derive(Debug, Clone)]
// TODO? serialize, deserialize
pub struct ReadProof {
    // Commitment to the query vector
    pub query_comm: Curve,
    // Commitment to the answer
    pub answer_comm: Curve,
    // Commitment of quotient polynomial T (aka t_comm)
    pub quotient_comm: Curve,

    // Evaluation of data polynomial at the required challenge point
    pub data_eval: ScalarField,
    // Evaluation of query polynomial at the required challenge point
    pub query_eval: ScalarField,
    // Evaluation of answer polynomial at the required challenge point
    pub answer_eval: ScalarField,

    // Polynomial commitment’s proof for the validity of returned evaluations
    pub opening_proof: OpeningProof<Curve>,
}

#[instrument(skip_all, level = "debug")]
pub fn prove<RNG>(
    srs: &SRS<Curve>,
    domain: EvaluationDomains<ScalarField>,
    group_map: &<Curve as CommitmentCurve>::Map,
    rng: &mut RNG,
    // data is the data that is stored and queried
    data: &[ScalarField],
    // data[i] is queried if query[i] ≠ 0
    query: &[ScalarField],
    // answer[i] = data[i] * query[i]
    answer: &[ScalarField],
    // Commitment to data
    data_comm: &Curve,
) -> ReadProof
where
    RNG: RngCore + CryptoRng,
{
    let mut fq_sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());

    let data_poly = to_polynomial(data, domain.d1);
    let data_comm: PolyComm<Curve> = PolyComm {
        chunks: vec![*data_comm],
    };

    let (query_poly, query_comm) = to_polynomial_and_commitment(query, domain.d1, srs);

    let (answer_poly, answer_comm) = to_polynomial_and_commitment(answer, domain.d1, srs);

    fq_sponge.absorb_g(&[data_comm.chunks[0], query_comm, answer_comm]);

    // coefficient form, over d4? d2?
    // quotient_Poly has degree d1
    let quotient_poly: DensePolynomial<ScalarField> = {
        let data_d2 = data_poly.evaluate_over_domain_by_ref(domain.d2);
        let query_d2 = query_poly.evaluate_over_domain_by_ref(domain.d2);
        let answer_d2 = answer_poly.evaluate_over_domain_by_ref(domain.d2);

        // q×d - a
        let numerator_eval: Evaluations<ScalarField, R2D<ScalarField>> =
            &(&data_d2 * &query_d2) - &answer_d2;

        let numerator_eval_interpolated = numerator_eval.interpolate();

        let fail_final_q_division = || {
            panic!("Division by vanishing poly must not fail at this point, we checked it before")
        };
        // We compute the polynomial t(X) by dividing the constraints polynomial
        // by the vanishing polynomial, i.e. Z_H(X).
        let (quotient, res) = numerator_eval_interpolated.divide_by_vanishing_poly(domain.d1);
        // As the constraints must be verified on H, the rest of the division
        // must be equal to 0 as the constraints polynomial and Z_H(X) are both
        // equal on H.
        if !res.is_zero() {
            fail_final_q_division();
        }

        quotient
    };

    // commit to the quotient polynomial $t$.
    // num_chunks = 1 because our constraint is degree 2, which makes the quotient polynomial of degree d1
    let quotient_comm = srs.commit_non_hiding(&quotient_poly, 1).chunks[0];
    fq_sponge.absorb_g(&[quotient_comm]);

    // aka zeta
    let evaluation_point = fq_sponge.challenge();

    // Fiat Shamir - absorbing evaluations
    let mut fr_sponge = CurveFrSponge::new(Curve::sponge_params());
    fr_sponge.absorb(&fq_sponge.clone().digest());

    let data_eval = data_poly.evaluate(&evaluation_point);
    let query_eval = query_poly.evaluate(&evaluation_point);
    let answer_eval = answer_poly.evaluate(&evaluation_point);
    let quotient_eval = quotient_poly.evaluate(&evaluation_point);

    for eval in [data_eval, query_eval, answer_eval, quotient_eval].into_iter() {
        fr_sponge.absorb(&eval);
    }

    let (_, endo_r) = Curve::endos();
    // Generate scalars used as combiners for sub-statements within our IPA opening proof.
    let polyscale = fr_sponge.challenge().to_field(endo_r);
    let evalscale = fr_sponge.challenge().to_field(endo_r);

    // Creating the polynomials for the batch proof
    // Gathering all polynomials to use in the opening proof
    let opening_proof_inputs: Vec<_> = {
        let coefficients_form =
            DensePolynomialOrEvaluations::<_, R2D<ScalarField>>::DensePolynomial;
        let non_hiding = |n_chunks| PolyComm {
            chunks: vec![ScalarField::zero(); n_chunks],
        };

        vec![
            (coefficients_form(&data_poly), non_hiding(1)),
            (coefficients_form(&query_poly), non_hiding(1)),
            (coefficients_form(&answer_poly), non_hiding(1)),
            (coefficients_form(&quotient_poly), non_hiding(1)),
        ]
    };

    let opening_proof = srs.open(
        group_map,
        opening_proof_inputs.as_slice(),
        &[evaluation_point],
        polyscale,
        evalscale,
        fq_sponge,
        rng,
    );

    ReadProof {
        query_comm,
        answer_comm,
        quotient_comm,
        data_eval,
        query_eval,
        answer_eval,
        opening_proof,
    }
}

pub fn verify<RNG>(
    srs: &SRS<Curve>,
    domain: EvaluationDomains<ScalarField>,
    group_map: &<Curve as CommitmentCurve>::Map,
    rng: &mut RNG,
    // Commitment to data
    data_comm: &Curve,
    proof: &ReadProof,
) -> bool
where
    RNG: RngCore + CryptoRng,
{
    let mut fq_sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());
    fq_sponge.absorb_g(&[*data_comm, proof.query_comm, proof.answer_comm]);
    fq_sponge.absorb_g(&[proof.quotient_comm]);

    let evaluation_point = fq_sponge.challenge();

    let mut fr_sponge = CurveFrSponge::new(Curve::sponge_params());
    fr_sponge.absorb(&fq_sponge.clone().digest());

    let vanishing_poly_at_zeta = domain.d1.vanishing_polynomial().evaluate(&evaluation_point);
    let quotient_eval = {
        (proof.data_eval * proof.query_eval - proof.answer_eval)
            * vanishing_poly_at_zeta
                .inverse()
                .unwrap_or_else(|| panic!("Inverse fails only with negligible probability"))
    };

    for eval in [
        proof.data_eval,
        proof.query_eval,
        proof.answer_eval,
        quotient_eval,
    ]
    .into_iter()
    {
        fr_sponge.absorb(&eval);
    }

    let (_, endo_r) = Curve::endos();
    // Generate scalars used as combiners for sub-statements within our IPA opening proof.
    let polyscale = fr_sponge.challenge().to_field(endo_r);
    let evalscale = fr_sponge.challenge().to_field(endo_r);

    let coms_and_evaluations = vec![
        Evaluation {
            commitment: PolyComm {
                chunks: vec![*data_comm],
            },
            evaluations: vec![vec![proof.data_eval]],
        },
        Evaluation {
            commitment: PolyComm {
                chunks: vec![proof.query_comm],
            },
            evaluations: vec![vec![proof.query_eval]],
        },
        Evaluation {
            commitment: PolyComm {
                chunks: vec![proof.answer_comm],
            },
            evaluations: vec![vec![proof.answer_eval]],
        },
        Evaluation {
            commitment: PolyComm {
                chunks: vec![proof.quotient_comm],
            },
            evaluations: vec![vec![quotient_eval]],
        },
    ];
    let combined_inner_product = {
        let evaluations: Vec<_> = coms_and_evaluations
            .iter()
            .map(|Evaluation { evaluations, .. }| evaluations.clone())
            .collect();

        combined_inner_product(&polyscale, &evalscale, evaluations.as_slice())
    };

    srs.verify(
        group_map,
        &mut [BatchEvaluationProof {
            sponge: fq_sponge,
            evaluation_points: vec![evaluation_point],
            polyscale,
            evalscale,
            evaluations: coms_and_evaluations,
            opening: &proof.opening_proof,
            combined_inner_product,
        }],
        rng,
    )
}

#[cfg(test)]
mod tests {
    use super::{prove, verify, ReadProof};
    use crate::{Curve, ScalarField, SRS_SIZE};
    use ark_ec::AffineRepr;
    use ark_ff::{One, UniformRand};
    use ark_poly::{univariate::DensePolynomial, Evaluations};
    use kimchi::{circuits::domains::EvaluationDomains, groupmap::GroupMap};
    use mina_curves::pasta::{Fp, Vesta};
    use poly_commitment::{commitment::CommitmentCurve, SRS as _};
    use proptest::prelude::*;

    #[test]
    fn test_read_proof_completeness_soundness() {
        let mut rng = o1_utils::tests::make_test_rng(None);

        let srs = poly_commitment::precomputed_srs::get_srs_test();
        let group_map = <Vesta as CommitmentCurve>::Map::setup();
        let domain: EvaluationDomains<ScalarField> = EvaluationDomains::create(srs.size()).unwrap();

        let data: Vec<ScalarField> = {
            let mut data = vec![];
            (0..SRS_SIZE).for_each(|_| data.push(Fp::rand(&mut rng)));
            data
        };

        let data_poly: DensePolynomial<ScalarField> =
            Evaluations::from_vec_and_domain(data.clone(), domain.d1).interpolate();
        let data_comm: Curve = srs.commit_non_hiding(&data_poly, 1).chunks[0];

        let query: Vec<ScalarField> = {
            let mut query = vec![];
            (0..SRS_SIZE).for_each(|_| query.push(Fp::from(rand::thread_rng().gen::<f64>() < 0.1)));
            query
        };

        let answer: Vec<ScalarField> = data.iter().zip(query.iter()).map(|(d, q)| *d * q).collect();

        let proof = prove(
            &srs,
            domain,
            &group_map,
            &mut rng,
            data.as_slice(),
            query.as_slice(),
            answer.as_slice(),
            &data_comm,
        );
        let res = verify(&srs, domain, &group_map, &mut rng, &data_comm, &proof);

        assert!(res, "Completeness: Proof must verify");

        let proof_malformed_1 = ReadProof {
            answer_comm: Curve::zero(),
            ..proof.clone()
        };

        let res_1 = verify(
            &srs,
            domain,
            &group_map,
            &mut rng,
            &data_comm,
            &proof_malformed_1,
        );

        assert!(!res_1, "Soundness: Malformed proof #1 must NOT verify");

        let proof_malformed_2 = ReadProof {
            query_eval: ScalarField::one(),
            ..proof.clone()
        };

        let res_2 = verify(
            &srs,
            domain,
            &group_map,
            &mut rng,
            &data_comm,
            &proof_malformed_2,
        );

        assert!(!res_2, "Soundness: Malformed proof #2 must NOT verify");
    }
}
