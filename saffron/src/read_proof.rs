//! This module defines the read proof prover and verifier. Given a query vector q, a vector of data d, and a commitment to this data C, the prover will return an answer a and a proof that the answers correspond to the data committed in C at the specified indexes in the query.
//! The folding version is TBD
//! We call data is the data vector that is stored and queried
//! We call answer the vector such that answer[i] = data[i] * query[i]

use crate::{blob::FieldBlob, utils, Curve, CurveFqSponge, CurveFrSponge, ScalarField, SRS_SIZE};
use ark_ec::AffineRepr;
use ark_ff::{One, Zero};
use ark_poly::{
    EvaluationDomain, Evaluations, Polynomial, Radix2EvaluationDomain as D, Radix2EvaluationDomain,
};
use kimchi::{curve::KimchiCurve, plonk_sponge::FrSponge};
use mina_poseidon::FqSponge;
use poly_commitment::{
    commitment::{BatchEvaluationProof, CommitmentCurve, Evaluation},
    ipa::{OpeningProof, SRS},
    utils::DensePolynomialOrEvaluations,
    PolyComm,
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
    // Commitment of quotient polynomial T
    pub cm_quotient: Curve,
    // Evaluation of data polynomial at the required challenge point
    pub data: ScalarField,
    // Evaluation of query polynomial at the required challenge point
    pub query: ScalarField,
    // Evaluation of answer polynomial at the required challenge point
    pub answer: ScalarField,
    // Evaluation of answer polynomial at the required challenge point
    pub quotient: ScalarField,
    // Polynomial commitment’s proof for the validity of returned evaluations
    pub opening_proof: OpeningProof<Curve>,
}

#[instrument(skip_all, level = "debug")]
pub fn prove(
    domain: EvaluationDomains<Fp>,
    srs: &SRS<Curve>,
    group_map: &<Curve as CommitmentCurve>::Map,
    rng: &mut OsRng,
    // data is the data that is stored and queried
    data: &ScalarField,
    // data[i] is queried if query[i] ≠ 0
    query: &ScalarField,
    // answer[i] = data[i] * query[i]
    answer: &ScalarField,
) -> ReadProof {
    let mut fq_sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());
    let data_d2 = data
        .interpolate_by_ref()
        .evaluate_over_domain_by_ref(domain.d2); // eval over ×2 domain ; evaluate_over_domain_by_ref
    let query_d2 = ();
    let answer_d2 = ();
    let numerator_d2 = (); // a - q×d
    let numerator_poly = (); // interpolation
    let quotient = (); // division
    let cm_quotient = Curve::zero(); // commit quotient

    fq_sponge.absorb_g(&[cm_quotient]);
    let evaluation_point = fq_sponge.squeeze(2);

    let eval_data = ScalarField::one(); // eval data at eval_point
    let eval_query = ScalarField::one(); // eval query at eval_point
    let eval_answer = ScalarField::one(); // eval answer at eval_point
    let eval_quotient = ScalarField::one(); // eval quotient at eval_point

    // TODO: these evaluations should probably be added to the sponge for the opening proof

    let opening_proof =
        srs.open(
            group_map,
            &[
                (
                    DensePolynomialOrEvaluations::<
                        <Curve as AffineRepr>::ScalarField,
                        D<ScalarField>,
                    >::DensePolynomial(&smth),
                    PolyComm {
                        chunks: vec![ScalarField::zero()],
                    },
                ),
            ],
            &[evaluation_point],
            ScalarField::one(), // Single evaluation, so we don't care
            ScalarField::one(), // Single evaluation, so we don't care
            fq_sponge,
            rng,
        );

    ReadProof {
        cm_quotient,
        data: eval_data,
        query: eval_query,
        answer: eval_answer,
        quotient: eval_quotient,
        opening_proof,
    }
}
