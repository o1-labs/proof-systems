//! This module defines the read proof prover and verifier. Given a
//! query vector q, a vector of data d, and a commitment to this data
//! C, the prover will return an answer a and a proof that the answers
//! correspond to the data committed in C at the specified indexes in
//! the query.
//!
//! The folding version is TBD
//! We call data the data vector that is stored and queried
//! We call answer the vector such that `answer[i] = data[i] * query[i]`
//!
//! The considered protocol involves a user, the chain and the storage provider
//! and behaves as following:
//! 1. The user sends a request to the chain, containing a commitment to a data
//!    handled by the storage provider with a query that specifies which indexes
//!    to read.
//! 2. The chains includes the query if it’s valid and computes the commitment
//!    to the query.
//! 3. The state replicator fetch the request with the data & query commitments
//!    on the chain, computes the corresponding answer & proof, and sends it to
//!    the chain.
//! 4. The chain includes the proof if it verifies, and if it’s consistent with
//!    the provided answer.

use crate::{
    commitment::*,
    storage::Data,
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

/// Answer to a query regarding some data
pub struct Answer {
    answer: Vec<ScalarField>,
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
    pub fn to_commitment(&self, domain: R2D<ScalarField>, srs: &SRS<Curve>) -> Commitment<Curve> {
        let evals = self.to_evals_vector(domain.size as usize);
        let (_poly, comm) = evals_to_polynomial_and_commitment(evals, domain, srs);
        comm
    }
    // This function should be used for the chain to compute the commitment
    pub fn to_commitment_sparse(&self, srs: &SRS<Curve>) -> Commitment<Curve> {
        let query_evals: Vec<ScalarField> = self.query.iter().map(|_| ScalarField::one()).collect();
        let indexes: Vec<u64> = self.query.iter().map(|i| *i as u64).collect();
        commit_sparse(srs, &query_evals, &indexes)
    }
    pub fn to_answer(&self, data: &Data<ScalarField>) -> Answer {
        Answer {
            answer: self.query.iter().map(|i| data.data[*i as usize]).collect(),
        }
    }
    fn to_answer_evals(&self, data: &[ScalarField], domain_size: usize) -> Vec<ScalarField> {
        let mut evals = vec![ScalarField::zero(); domain_size];
        for i in self.query.iter() {
            evals[*i as usize] = data[*i as usize];
        }
        evals
    }
}

impl Answer {
    fn to_commitment(&self, query: &Query, srs: &SRS<Curve>) -> Commitment<Curve> {
        let indexes: Vec<u64> = query.query.iter().map(|i| *i as u64).collect();
        commit_sparse(srs, &self.answer, &indexes)
    }
}

// #[serde_as]
#[derive(Debug, Clone)]
// TODO? serialize, deserialize
pub struct ReadProof {
    // Commitment to the answer
    pub answer_comm: Commitment<Curve>,
    // Commitment of quotient polynomial T (aka t_comm)
    pub quotient_comm: Commitment<Curve>,

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
    data: &Data<ScalarField>,
    // data[i] is queried if query[i] ≠ 0
    query: &Query,
    // Commitment to data
    data_comm: &Commitment<Curve>,
    // Commitment to query
    query_comm: &Commitment<Curve>,
) -> ReadProof
where
    RNG: RngCore + CryptoRng,
{
    let data = &data.data;

    let mut fq_sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());

    let data_poly = evals_to_polynomial(data.to_vec(), domain.d1);

    let query_poly = query.to_polynomial(domain.d1);

    let (answer_poly, answer_comm) = {
        let answer = query.to_answer_evals(data, domain.d1.size());
        evals_to_polynomial_and_commitment(answer, domain.d1, srs)
    };

    fq_sponge.absorb_g(&[data_comm.cm, query_comm.cm, answer_comm.cm]);

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
    fq_sponge.absorb_g(&[quotient_comm.cm]);

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
    query_comm: &Commitment<Curve>,
    proof: &ReadProof,
) -> bool
where
    RNG: RngCore + CryptoRng,
{
    let mut fq_sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());
    fq_sponge.absorb_g(&[data_comm.cm, query_comm.cm, proof.answer_comm.cm]);
    fq_sponge.absorb_g(&[proof.quotient_comm.cm]);

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
                chunks: vec![query_comm.cm],
            },
            evaluations: vec![vec![proof.query_eval]],
        },
        Evaluation {
            commitment: PolyComm {
                chunks: vec![proof.answer_comm.cm],
            },
            evaluations: vec![vec![proof.answer_eval]],
        },
        Evaluation {
            commitment: PolyComm {
                chunks: vec![proof.quotient_comm.cm],
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
pub fn verify_answer(srs: &SRS<Curve>, query: &Query, answer: &Answer, proof: &ReadProof) -> bool {
    let answer_comm = answer.to_commitment(query, srs);
    answer_comm == proof.answer_comm
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commitment::{commit_to_poly, Commitment},
        env, Curve, ScalarField, SRS_SIZE,
    };
    use ark_ec::AffineRepr;
    use ark_ff::{One, UniformRand};
    use ark_poly::univariate::DensePolynomial;
    use kimchi::{circuits::domains::EvaluationDomains, groupmap::GroupMap};
    use mina_curves::pasta::{Fp, Vesta};
    use once_cell::sync::Lazy;
    use poly_commitment::{commitment::CommitmentCurve, ipa::SRS, SRS as _};
    use proptest::prelude::*;

    static SRS: Lazy<SRS<Vesta>> = Lazy::new(|| {
        if let Ok(srs) = std::env::var("SRS_FILEPATH") {
            env::get_srs_from_cache(srs)
        } else {
            SRS::create(SRS_SIZE)
        }
    });

    static DOMAIN: Lazy<EvaluationDomains<ScalarField>> =
        Lazy::new(|| EvaluationDomains::<ScalarField>::create(SRS_SIZE).unwrap());

    static GROUP_MAP: Lazy<<Vesta as CommitmentCurve>::Map> =
        Lazy::new(<Vesta as CommitmentCurve>::Map::setup);

    #[test]
    fn test_read_proof_completeness_soundness() {
        let mut rng = o1_utils::tests::make_test_rng(None);

        let data = {
            let mut data = vec![];
            (0..SRS_SIZE).for_each(|_| data.push(Fp::rand(&mut rng)));
            Data { data }
        };

        let data_poly: DensePolynomial<ScalarField> = data.to_polynomial(DOMAIN.d1);
        let data_comm = commit_to_poly(&SRS, &data_poly);

        let query: Query = {
            let mut query = vec![];
            (0..SRS_SIZE).for_each(|i| {
                if rand::thread_rng().gen::<f64>() < 0.1 {
                    query.push(i as u16)
                }
            });
            Query { query }
        };

        let query_comm = query.to_commitment(DOMAIN.d1, &SRS);

        let query_comm_sparse = query.to_commitment_sparse(&SRS);

        assert!(
            query_comm == query_comm_sparse,
            "Query commitment: commitment should be the same whatever the computation method is."
        );

        let proof = prove(
            &SRS,
            *DOMAIN,
            &GROUP_MAP,
            &mut rng,
            &data,
            &query,
            &data_comm,
            &query_comm,
        );
        let res = verify(
            &SRS,
            *DOMAIN,
            &GROUP_MAP,
            &mut rng,
            &data_comm,
            &query_comm,
            &proof,
        );

        assert!(res, "Completeness: Proof must verify");

        let proof_malformed_1 = ReadProof {
            answer_comm: Commitment { cm: Curve::zero() },
            ..proof.clone()
        };

        let res_1 = verify(
            &SRS,
            *DOMAIN,
            &GROUP_MAP,
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
            &SRS,
            *DOMAIN,
            &GROUP_MAP,
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
            &data,
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

        let mut answer = query.to_answer(&data);

        let res_4 = verify_answer(&SRS, &query, &answer, &proof);

        assert!(res_4, "Completeness: Answer must be consistent with proof");

        answer.answer[0] = ScalarField::one();

        let res_5 = verify_answer(&SRS, &query, &answer, &proof);

        assert!(!res_5, "Soundness: Wrong answer must NOT verify");
    }
}

#[cfg(feature = "ocaml_types")]
pub mod caml {
    use super::*;
    use crate::{
        commitment::caml::CamlSaffronCommitment, read_proof, storage::caml::CamlSaffronData, BaseField,
    };
    use kimchi::groupmap::GroupMap;
    use kimchi_stubs::{
        arkworks::{group_affine::CamlGVesta, pasta_fp::CamlFp},
        field_vector::fp::CamlFpVector,
        srs::fp::CamlFpSrs,
    };
    use poly_commitment::{ipa::caml::CamlOpeningProof, SRS};

    #[derive(ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
    pub struct CamlSaffronReadProof {
        pub answer_comm: CamlSaffronCommitment,
        pub quotient_comm: CamlSaffronCommitment,
        pub data_eval: CamlFp,
        pub query_eval: CamlFp,
        pub answer_eval: CamlFp,
        pub opening_proof: CamlOpeningProof<CamlGVesta, CamlFp>,
    }

    impl From<ReadProof> for CamlSaffronReadProof {
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

    impl From<CamlSaffronReadProof> for ReadProof {
        fn from(proof: CamlSaffronReadProof) -> Self {
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

    // ocaml::Int are represented as usize, so extra attention is needed to
    // convert into u16
    pub fn caml_int_to_u16(caml_int: ocaml::Int) -> u16 {
        match u16::try_from(caml_int) {
            Ok(u) => u,
            Err(_) => panic!("OCaml int out of range for u16: {}", caml_int),
        }
    }

    #[ocaml_gen::func]
    #[ocaml::func]
    pub fn caml_saffron_read_prove(
        caml_srs: CamlFpSrs,
        caml_data: CamlSaffronData,
        caml_query: Vec<ocaml::Int>,
        caml_data_comm: CamlSaffronCommitment,
        caml_query_comm: CamlSaffronCommitment,
    ) -> CamlSaffronReadProof {
        let srs = caml_srs.0;
        let data: Data<ScalarField> = caml_data.into();
        let query: Query = Query {
            query: caml_query.into_iter().map(caml_int_to_u16).collect(),
        };
        let data_comm: Commitment<Curve> = caml_data_comm.into();
        let query_comm: Commitment<Curve> = caml_query_comm.into();

        let srs_size = srs.max_poly_size();
        let domain = EvaluationDomains::<ScalarField>::create(srs_size).unwrap();

        let group_map = GroupMap::<BaseField>::setup();

        let mut rng = rand::thread_rng();

        let read_proof = read_proof::prove(
            &srs,
            domain,
            &group_map,
            &mut rng,
            &data,
            &query,
            &data_comm,
            &query_comm,
        );
        read_proof.into()
    }

    #[ocaml_gen::func]
    #[ocaml::func]
    pub fn caml_saffron_read_verify(
        caml_srs: CamlFpSrs,
        caml_data_comm: CamlSaffronCommitment,
        caml_query_comm: CamlSaffronCommitment,
        caml_proof: CamlSaffronReadProof,
    ) -> bool {
        let srs = caml_srs.0;
        let data_comm: Commitment<Curve> = caml_data_comm.into();
        let query_comm: Commitment<Curve> = caml_query_comm.into();
        let proof: ReadProof = caml_proof.into();

        let srs_size = srs.max_poly_size();
        let domain = EvaluationDomains::<ScalarField>::create(srs_size).unwrap();

        let group_map = GroupMap::<BaseField>::setup();

        let mut rng = rand::thread_rng();

        read_proof::verify(
            &srs,
            domain,
            &group_map,
            &mut rng,
            &data_comm,
            &query_comm,
            &proof,
        )
    }

    #[ocaml_gen::func]
    #[ocaml::func]
    pub fn caml_saffron_read_answer_verify(
        caml_srs: CamlFpSrs,
        caml_query: Vec<ocaml::Int>,
        caml_answer: CamlFpVector,
        caml_proof: CamlSaffronReadProof,
    ) -> bool {
        let srs = caml_srs.0;
        let query: Query = Query {
            query: caml_query.into_iter().map(caml_int_to_u16).collect(),
        };
        let answer = Answer {
            answer: caml_answer.as_slice().into(),
        };
        let proof = caml_proof.into();

        read_proof::verify_answer(&srs, &query, &answer, &proof)
    }
}
