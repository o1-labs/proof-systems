//! This module defines the read proof prover and verifier. Given a
//! query vector q, a vector of data d, and a commitment to this data
//! C, the prover will return an answer a and a proof that the answers
//! correspond to the data committed in C at the specified indexes in
//! the query.
//!
//! The folding version is TBD
//! We call data the data vector that is stored and queried
//! We call answer the vector such that `answer[i] = data[i] * query[i]`

use crate::{
    commitment::*,
    utils::{evals_to_polynomial, evals_to_polynomial_and_commitment},
    Curve, CurveFqSponge, CurveFrSponge, ScalarField,
};
use ark_ff::{Field, One, Zero};
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
    PolyComm,
};
use rand::{CryptoRng, RngCore};
use tracing::instrument;

/// Indexes of the data to be read ; this will be stored onchain
/// Note: indexes are represented with u16, matching indexes from 0 to 2¹⁶ - 1. If the SRS is made bigger, the integer type has to handle this
pub struct Query {
    pub query: Vec<u16>,
}

impl Query {
    fn to_evals_vector(&self, domain_size: usize) -> Vec<ScalarField> {
        let mut evals = vec![ScalarField::zero(); domain_size];
        for i in self.query.iter() {
            evals[*i as usize] = ScalarField::one();
        }
        evals
    }
    fn to_polynomial(&self, domain: R2D<ScalarField>) -> DensePolynomial<ScalarField> {
        evals_to_polynomial(self.to_evals_vector(domain.size as usize), domain)
    }
    pub fn to_commitment(&self, domain: R2D<ScalarField>, srs: &SRS<Curve>) -> Curve {
        let evals = self.to_evals_vector(domain.size as usize);
        let (_poly, comm) = evals_to_polynomial_and_commitment(evals, domain, srs);
        comm
    }
    // This function should be used for the chain to compute the commitment
    pub fn to_commitment_sparse(&self, srs: &SRS<Curve>) -> Curve {
        let query_evals: Vec<ScalarField> = self.query.iter().map(|_| ScalarField::one()).collect();
        let indexes: Vec<u64> = self.query.iter().map(|i| *i as u64).collect();
        commit_sparse(srs, &query_evals, &indexes)
    }
    pub fn to_answer_sparse(&self, data: &[ScalarField]) -> Vec<ScalarField> {
        self.query.iter().map(|i| data[*i as usize]).collect()
    }
    fn to_answer_evals(&self, data: &[ScalarField], domain_size: usize) -> Vec<ScalarField> {
        let mut evals = vec![ScalarField::zero(); domain_size];
        for i in self.query.iter() {
            evals[*i as usize] = data[*i as usize];
        }
        evals
    }
    fn commit_answers(&self, answer: &[ScalarField], srs: &SRS<Curve>) -> Commitment<Curve> {
        let indexes: Vec<u64> = self.query.iter().map(|i| *i as u64).collect();
        commit_sparse(srs, answer, &indexes)
    }
}

// #[serde_as]
#[derive(Debug, Clone)]
// TODO? serialize, deserialize
pub struct ReadProof {
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
    query: &Query,
    // Commitment to data
    data_comm: &Commitment<Curve>,
    // Commitment to query
    query_comm: &Curve,
) -> ReadProof
where
    RNG: RngCore + CryptoRng,
{
    let mut fq_sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());

    let data_poly = evals_to_polynomial(data.to_vec(), domain.d1);

    let query_poly = query.to_polynomial(domain.d1);

    let (answer_poly, answer_comm) = {
        let answer = query.to_answer_evals(data, domain.d1.size());
        evals_to_polynomial_and_commitment(answer, domain.d1, srs)
    };

    fq_sponge.absorb_g(&[data_comm.cm, *query_comm, answer_comm]);

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

        // We compute the polynomial t(X) by dividing the constraints polynomial
        // by the vanishing polynomial, i.e. Z_H(X).
        let (quotient, res) = numerator_eval_interpolated.divide_by_vanishing_poly(domain.d1);
        // As the constraints must be verified on H, the rest of the division
        // must be equal to 0 as the constraints polynomial and Z_H(X) are both
        // equal on H.
        if !res.is_zero() {
            panic!("Division by vanishing polynomial gave a non-zero rest.");
        }

        quotient
    };

    // commit to the quotient polynomial $t$.
    // num_chunks = 1 because our constraint is degree 2, which makes the quotient polynomial of degree d1
    let quotient_comm = commit_to_poly(srs, &quotient_poly);
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
    data_comm: &Commitment<Curve>,
    // Commitment to query
    query_comm: &Curve,
    proof: &ReadProof,
) -> bool
where
    RNG: RngCore + CryptoRng,
{
    let mut fq_sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());
    fq_sponge.absorb_g(&[
        data_comm.cm,
        *query_comm,
        proof.answer_comm,
        proof.quotient_comm,
    ]);

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
                chunks: vec![data_comm.cm],
            },
            evaluations: vec![vec![proof.data_eval]],
        },
        Evaluation {
            commitment: PolyComm {
                chunks: vec![*query_comm],
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

/// Checks that the provided answer is consistent with the proof
/// Here, we just recompute the commitment
/// TODO: could we just recompute the evaluation ?
pub fn verify_answer(
    srs: &SRS<Curve>,
    query: &Query,
    answer: &[ScalarField],
    proof: &ReadProof,
) -> bool {
    let answer_comm = query.commit_answers(answer, srs);
    answer_comm == proof.answer_comm
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commitment::{commit_to_poly, Commitment},
        Curve, ScalarField, SRS_SIZE,
    };
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
        let data_comm = Commitment {
            cm: commit_to_poly(&srs, &data_poly),
        };

        let query: Query = {
            let mut query = vec![];
            (0..SRS_SIZE).for_each(|i| {
                if rand::thread_rng().gen::<f64>() < 0.1 {
                    query.push(i as u16)
                }
            });
            Query { query }
        };

        let query_comm = query.to_commitment(domain.d1, &srs);

        let query_comm_sparse = query.to_commitment_sparse(&SRS);

        assert!(
            query_comm == query_comm_sparse,
            "Query commitment: commitment should be the same whatever the computation method is."
        );

        let proof = prove(
            &srs,
            domain,
            &group_map,
            &mut rng,
            data.as_slice(),
            &query,
            &data_comm,
            &query_comm,
        );
        let res = verify(
            &srs,
            domain,
            &group_map,
            &mut rng,
            &data_comm,
            &query_comm,
            &proof,
        );

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
            &query_comm,
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
            &query_comm,
            &proof_malformed_2,
        );

        assert!(!res_2, "Soundness: Malformed proof #2 must NOT verify");

        let mut wrong_query = query.query.clone();
        wrong_query.truncate(query.query.len() - 2);

        let proof_for_wrong_query = prove(
            &SRS,
            *DOMAIN,
            &GROUP_MAP,
            &mut rng,
            data.as_slice(),
            &Query { query: wrong_query },
            &data_comm,
            &query_comm,
        );
        let res_3 = verify(
            &SRS,
            *DOMAIN,
            &GROUP_MAP,
            &mut rng,
            &data_comm,
            &query_comm,
            &proof_for_wrong_query,
        );

        assert!(!res_3, "Soundness: Truncated query must NOT verify");

        let mut answer = query.to_answer_sparse(&data);

        let res_4 = verify_answer(&SRS, &query, &answer, &proof);

        assert!(res_4, "Completeness: Answer must be consistent with proof");

        answer[0] = ScalarField::one();

        let res_5 = verify_answer(&SRS, &query, &answer, &proof);

        assert!(!res_5, "Soundness: Wrong answer must NOT verify");
    }
}

#[cfg(feature = "ocaml_types")]
pub mod caml {
    use super::*;
    use kimchi_stubs::arkworks::{group_affine::CamlGVesta, pasta_fp::CamlFp};
    use poly_commitment::ipa::caml::CamlOpeningProof;

    #[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlReadProof {
        pub answer_comm: CamlGVesta,
        pub quotient_comm: CamlGVesta,
        pub data_eval: CamlFp,
        pub query_eval: CamlFp,
        pub answer_eval: CamlFp,
        pub opening_proof: CamlOpeningProof<CamlGVesta, CamlFp>,
    }

    impl From<ReadProof> for CamlReadProof {
        fn from(proof: ReadProof) -> Self {
            Self {
                answer_comm: proof.answer_comm.into(),
                quotient_comm: proof.quotient_comm.into(),
                data_eval: proof.data_eval.into(),
                query_eval: proof.query_eval.into(),
                answer_eval: proof.answer_eval.into(),
                opening_proof: proof.opening_proof.into(),
            }
        }
    }

    impl From<CamlReadProof> for ReadProof {
        fn from(proof: CamlReadProof) -> Self {
            Self {
                answer_comm: proof.answer_comm.into(),
                quotient_comm: proof.quotient_comm.into(),
                data_eval: proof.data_eval.into(),
                query_eval: proof.query_eval.into(),
                answer_eval: proof.answer_eval.into(),
                opening_proof: proof.opening_proof.into(),
            }
        }
    }
}
