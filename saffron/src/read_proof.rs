//! This module defines the read proof prover and verifier. Given a
//! query vector q, a vector of data d, and a commitment to this data
//! C, the prover will return an answer a and a proof that the answers
//! correspond to the data committed in C at the specified indexes in
//! the query.
//!
//! The folding version is TBD
//! We call data is the data vector that is stored and queried
//! We call answer the vector such that answer[i] = data[i] * query[i]

use crate::{Curve, CurveFqSponge, CurveFrSponge, ScalarField};
use ark_ec::AffineRepr;
use ark_ff::{One, Zero};
use ark_poly::{
    univariate::DensePolynomial, Evaluations, Polynomial, Radix2EvaluationDomain as R2D,
};
use kimchi::{circuits::domains::EvaluationDomains, curve::KimchiCurve, plonk_sponge::FrSponge};
use mina_poseidon::FqSponge;
use poly_commitment::{
    commitment::CommitmentCurve,
    ipa::{OpeningProof, SRS},
    utils::DensePolynomialOrEvaluations,
    PolyComm, SRS as _,
};
use rand::rngs::OsRng;
use tracing::instrument;

// #[serde_as]
#[derive(Debug, Clone)]
// TODO? serialize, deserialize
struct ReadProof {
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
    // Evaluation of answer polynomial at the required challenge point
    pub quotient_eval: ScalarField,

    // Polynomial commitment’s proof for the validity of returned evaluations
    pub opening_proof: OpeningProof<Curve>,
}

#[instrument(skip_all, level = "debug")]
pub fn prove(
    domain: EvaluationDomains<ScalarField>,
    srs: &SRS<Curve>,
    group_map: &<Curve as CommitmentCurve>::Map,
    rng: &mut OsRng,
    // data is the data that is stored and queried
    data: &[ScalarField],
    // data[i] is queried if query[i] ≠ 0
    query: &[ScalarField],
    // answer[i] = data[i] * query[i]
    answer: &[ScalarField],
    // Commitment to data
    data_comm: &Curve,
) -> ReadProof {
    let (_, endo_r) = Curve::endos();

    let mut fq_sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());

    let data_d1 = Evaluations::from_vec_and_domain(data.to_vec(), domain.d1);
    let data_poly: DensePolynomial<ScalarField> = data_d1.clone().interpolate();
    let data_comm: PolyComm<Curve> = PolyComm {
        chunks: vec![data_comm.clone()],
    };

    let query_d1 = Evaluations::from_vec_and_domain(query.to_vec(), domain.d1);
    let query_poly: DensePolynomial<ScalarField> = query_d1.clone().interpolate();
    let query_comm: PolyComm<Curve> = srs.commit_non_hiding(&query_poly, 1);

    let answer_d1 = Evaluations::from_vec_and_domain(answer.to_vec(), domain.d1);
    let answer_poly: DensePolynomial<ScalarField> = answer_d1.clone().interpolate();
    let answer_comm: PolyComm<Curve> = srs.commit_non_hiding(&answer_poly, 1);

    // coefficient form, over d4? d2?
    // quotient_Poly has degree d1
    let quotient_poly: DensePolynomial<ScalarField> = {
        // TODO: do not re-interpolate, we already did d1
        let data_d2 = Evaluations::from_vec_and_domain(data.to_vec(), domain.d2);
        let query_d2 = Evaluations::from_vec_and_domain(query.to_vec(), domain.d2);
        let answer_d2 = Evaluations::from_vec_and_domain(answer.to_vec(), domain.d2);

        // q×d - a
        let numerator_eval: Evaluations<ScalarField, R2D<ScalarField>> =
            &(&data_d2 * &query_d2) - &answer_d2;

        let numerator_eval_interpolated = numerator_eval.interpolate();

        let fail_final_q_division = || {
            panic!("Division by vanishing poly must not fail at this point, we checked it before")
        };
        // We compute the polynomial t(X) by dividing the constraints polynomial
        // by the vanishing polynomial, i.e. Z_H(X).
        let (quotient, res) = numerator_eval_interpolated
            .divide_by_vanishing_poly(domain.d1)
            .unwrap_or_else(fail_final_q_division);
        // As the constraints must be verified on H, the rest of the division
        // must be equal to 0 as the constraints polynomial and Z_H(X) are both
        // equal on H.
        if !res.is_zero() {
            fail_final_q_division();
        }

        quotient
    };

    // commit to the quotient polynomial $t$.
    // num_chunks = 1 because our constraint is degree 2
    let quotient_comm = srs.commit_non_hiding(&quotient_poly, 1).chunks[0];
    fq_sponge.absorb_g(&[quotient_comm]);

    // aka zeta
    let evaluation_point = fq_sponge.squeeze(2);

    // Fiat Shamir - absorbing evaluations
    let fq_sponge_before_evaluations = fq_sponge.clone();
    let mut fr_sponge = CurveFrSponge::new(Curve::sponge_params());
    fr_sponge.absorb(&fq_sponge.digest());

    let data_eval = data_poly.evaluate(&evaluation_point);
    let query_eval = query_poly.evaluate(&evaluation_point);
    let answer_eval = answer_poly.evaluate(&evaluation_point);

    let quotient_eval = quotient_poly.evaluate(&evaluation_point);

    for eval in [data_eval, query_eval, answer_eval, quotient_eval].into_iter() {
        fr_sponge.absorb(&eval);
    }

    let v_chal = fr_sponge.challenge();
    let v = v_chal.to_field(endo_r);
    let u_chal = fr_sponge.challenge();
    let u = u_chal.to_field(endo_r);

    // Creating the polynomials for the batch proof
    let coefficients_form = DensePolynomialOrEvaluations::<_, R2D<ScalarField>>::DensePolynomial;
    let non_hiding = |n_chunks| PolyComm {
        chunks: vec![ScalarField::zero(); n_chunks],
    };
    let hiding = |n_chunks| PolyComm {
        chunks: vec![ScalarField::one(); n_chunks],
    };

    // Gathering all polynomials to use in the opening proof
    let mut opening_proof_inputs: Vec<_> = vec![
        (coefficients_form(&data_poly), non_hiding(1)),
        (coefficients_form(&query_poly), non_hiding(1)),
        (coefficients_form(&answer_poly), non_hiding(1)),
        (coefficients_form(&quotient_poly), non_hiding(1)),
    ];

    // TODO: these evaluations should probably be added to the sponge for the opening proof

    let opening_proof = srs.open(
        group_map,
        opening_proof_inputs.as_slice(),
        &[evaluation_point],
        u,
        v,
        fq_sponge_before_evaluations,
        rng,
    );

    ReadProof {
        query_comm: query_comm.chunks[0],
        answer_comm: answer_comm.chunks[0],
        quotient_comm,
        data_eval,
        query_eval,
        answer_eval,
        quotient_eval,
        opening_proof,
    }
}
