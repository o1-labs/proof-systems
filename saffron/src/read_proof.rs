//! This module defines the read proof prover and verifier. Given a
//! query vector q, a vector of data d, and a commitment to this data
//! C, the prover will return an answer a and a proof that the answers
//! correspond to the data committed in C at the specified indexes in
//! the query.
//!
//! The folding version is TBD
//! We call data is the data vector that is stored and queried
//! We call answer the vector such that answer[i] = data[i] * query[i]

use crate::{
    blob::FieldBlob, utils, BaseField, Curve, CurveFqSponge, CurveFrSponge, ScalarField, SRS_SIZE,
};
use ark_ec::AffineRepr;
use ark_ff::{One, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, Polynomial,
    Radix2EvaluationDomain as R2D, Radix2EvaluationDomain,
};
use kimchi::{circuits::domains::EvaluationDomains, curve::KimchiCurve, plonk_sponge::FrSponge};
use mina_poseidon::FqSponge;
use poly_commitment::{
    commitment::{BatchEvaluationProof, CommitmentCurve, Evaluation},
    ipa::{OpeningProof, SRS},
    utils::DensePolynomialOrEvaluations,
    PolyComm, SRS as _,
};
use rand::rngs::OsRng;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use tracing::instrument;

// #[serde_as]
#[derive(Debug, Clone)]
// TODO? serialize, deserialize
struct ReadProof {
    // #[serde_as(as = "o1_utils::serialization::SerdeAs")]
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
        let numerator_d2 = (); // a - q×d

        let numerator_poly: DensePolynomial<ScalarField> = todo!(); // interpolation
        todo!()
    };

    let quotient_comm = Curve::zero(); // commit quotient
    fq_sponge.absorb_g(&[quotient_comm]);

    // aka zeta
    let evaluation_point = fq_sponge.squeeze(2);

    // Fiat Shamir - absorbing evaluations
    let fq_sponge_before_evaluations = fq_sponge.clone();
    let mut fr_sponge = CurveFrSponge::new(Curve::sponge_params());
    fr_sponge.absorb(&fq_sponge.digest());

    let eval_data = data_poly.evaluate(&evaluation_point);
    let eval_query = query_poly.evaluate(&evaluation_point);
    let eval_answer = answer_poly.evaluate(&evaluation_point);

    let eval_quotient = quotient_poly.evaluate(&evaluation_point);

    for eval in [eval_data, eval_query, eval_answer, eval_quotient].into_iter() {
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
        fq_sponge,
        rng,
    );

    ReadProof {
        quotient_comm,
        data_eval: eval_data,
        query_eval: eval_query,
        answer_eval: eval_answer,
        quotient_eval: eval_quotient,
        opening_proof,
    }
}
