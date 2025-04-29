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
    PolyComm, SRS as _,
};
use rand::{CryptoRng, RngCore};
use tracing::instrument;

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

pub fn precompute_quotient_helpers(
    srs: &SRS<Curve>,
    domain: EvaluationDomains<ScalarField>,
    indices: Vec<usize>,
) -> Vec<(DensePolynomial<ScalarField>, Curve)> {
    use ark_ff::{One, UniformRand};
    let mut rng = o1_utils::tests::make_test_rng(None);
    println!("Generating helpers");
    let n = domain.d1.size();

    {
        let bases_var1: DensePolynomial<ScalarField> =
            srs.lagrange_basis_raw(domain.d1, vec![5])[0].clone();

        let mut base_eval_vec = vec![ScalarField::zero(); n];
        base_eval_vec[5] = ScalarField::one();

        let base_eval = Evaluations::from_vec_and_domain(base_eval_vec, domain.d1);
        let base_poly: DensePolynomial<ScalarField> = base_eval.interpolate();

        assert!(bases_var1 == base_poly);
    }

    let mut helpers: Vec<_> = vec![];

    let fail_final_q_division = || panic!("Division by vanishing poly must not fail");

    let indices = vec![500, 1000];

    for i in indices.iter() {
        println!("Generating helpers {:?}", i);
        let mut base_eval_vec = vec![ScalarField::zero(); n];
        base_eval_vec[*i] = ScalarField::one();

        let base_eval = Evaluations::from_vec_and_domain(base_eval_vec, domain.d1);
        let base_poly: DensePolynomial<ScalarField> = base_eval.interpolate();

        let base_d2 = base_poly.evaluate_over_domain_by_ref(domain.d2);
        let numerator_eval = &(&base_d2 * &base_d2) - &base_d2;

        let numerator_eval_interpolated = numerator_eval.interpolate();

        let (quotient, res) = numerator_eval_interpolated
            .divide_by_vanishing_poly(domain.d1)
            .unwrap_or_else(fail_final_q_division);

        if !res.is_zero() {
            fail_final_q_division();
        }

        let comm = srs.commit_non_hiding(&quotient, 1).chunks[0];

        println!("Comm: {:?}", comm);

        helpers.push((quotient, comm))
    }

    {
        let data: Vec<ScalarField> = {
            //let mut data = vec![];
            //(0..srs.size())
            //    .into_iter()
            //    .for_each(|_| data.push(ScalarField::rand(&mut rng)));
            let mut data = vec![ScalarField::zero(); srs.size()];
            data[500] = ScalarField::from(123 as u64);
            //data[1000] = ScalarField::from(456 as u64);
            data
        };

        let data_poly: DensePolynomial<ScalarField> =
            Evaluations::from_vec_and_domain(data.clone(), domain.d1).interpolate();
        let data_comm: Curve = srs.commit_non_hiding(&data_poly, 1).chunks[0];

        let query: Vec<ScalarField> = {
            let mut query = vec![ScalarField::zero(); srs.size()];
            query[500] = ScalarField::one();
            //query[1000] = ScalarField::one();
            //let mut query = vec![];
            //(0..SRS_SIZE)
            //    .into_iter()
            //    .for_each(|_| query.push(Fp::from(rand::thread_rng().gen::<f64>() < 0.001)));
            query
        };

        let answer: Vec<ScalarField> = data
            .clone()
            .iter()
            .zip(query.iter())
            .map(|(d, q)| *d * q)
            .collect();

        let (query_sparse, answer_sparse) = {
            let mut res1 = vec![];
            let mut res2 = vec![];
            for i in 0..srs.size() {
                if !query[i].is_zero() {
                    res1.push(i);
                    res2.push(answer[i]);
                }
            }
            (res1, res2)
        };

        let quotient_poly: DensePolynomial<ScalarField> = {
            let query_d1 = Evaluations::from_vec_and_domain(query.to_vec(), domain.d1);
            let query_poly: DensePolynomial<ScalarField> = query_d1.clone().interpolate();
            let query_comm: PolyComm<Curve> = srs.commit_non_hiding(&query_poly, 1);

            let answer_d1 = Evaluations::from_vec_and_domain(answer.to_vec(), domain.d1);
            let answer_poly: DensePolynomial<ScalarField> = answer_d1.clone().interpolate();
            let answer_comm: PolyComm<Curve> = srs.commit_non_hiding(&answer_poly, 1);

            let data_d2 = data_poly.evaluate_over_domain_by_ref(domain.d2);
            let query_d2 = query_poly.evaluate_over_domain_by_ref(domain.d2);
            let answer_d2 = answer_poly.evaluate_over_domain_by_ref(domain.d2);

            let numerator_eval: Evaluations<ScalarField, R2D<ScalarField>> =
                &(&data_d2 * &query_d2) - &answer_d2;

            let numerator_eval_interpolated = numerator_eval.clone().interpolate();

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

        let quotient_poly_eval = &quotient_poly.evaluate_over_domain_by_ref(domain.d1);

        let quotient_comm_alt: Curve = query_sparse
            .iter()
            .zip(answer_sparse.iter())
            .enumerate()
            .map(|(i, (query_ix, answer))| helpers[i].1 * answer)
            .fold(<Curve as AffineRepr>::Group::zero(), |acc, new| acc + &new)
            .into();

        // commit to the quotient polynomial $t$.
        // num_chunks = 1 because our constraint is degree 2
        let quotient_comm = srs.commit_non_hiding(&quotient_poly, 1);
        assert!(quotient_comm.chunks.len() == 1);
        let quotient_comm = quotient_comm.chunks[0];

        let quotient_evals_alt: Evaluations<ScalarField, R2D<ScalarField>> =
            &helpers[0].0.evaluate_over_domain_by_ref(domain.d1) * answer_sparse[0];
        //                + &(&helpers[1].0.evaluate_over_domain_by_ref(domain.d1) * answer_sparse[1]);
        let quotient_poly_alt: DensePolynomial<ScalarField> =
            quotient_evals_alt.clone().interpolate();

        let evaluation_point = ScalarField::from(12345);

        let quotient_eval = quotient_poly.evaluate(&evaluation_point);
        let quotient_eval_alt = quotient_poly_alt.evaluate(&evaluation_point);
        println!("quotient_eval: {}", quotient_eval);
        println!("quotient_eval_alt: {}", quotient_eval_alt);

        println!("quotient_comm: {}", quotient_comm);
        println!("quotient_comm_alt: {}", quotient_comm_alt);

        assert!(quotient_eval == quotient_eval_alt && quotient_comm == quotient_comm_alt);
    }

    println!("Helpers geneated");

    helpers
}

pub fn precompute_quotient_helpers_alt(
    srs: &SRS<Curve>,
    domain: EvaluationDomains<ScalarField>,
    indices: Vec<usize>,
) -> Vec<(DensePolynomial<ScalarField>, Curve)> {
    use ark_ff::{One, UniformRand};
    let mut rng = o1_utils::tests::make_test_rng(None);
    println!("Generating helpers");
    let n = domain.d1.size();

    {
        let bases_var1: DensePolynomial<ScalarField> =
            srs.lagrange_basis_raw(domain.d1, vec![5])[0].clone();

        let mut base_eval_vec = vec![ScalarField::zero(); n];
        base_eval_vec[5] = ScalarField::one();

        let base_eval = Evaluations::from_vec_and_domain(base_eval_vec, domain.d1);
        let base_poly: DensePolynomial<ScalarField> = base_eval.interpolate();

        assert!(bases_var1 == base_poly);
    }

    let mut helpers: Vec<_> = vec![];

    let fail_final_q_division = || panic!("Division by vanishing poly must not fail");

    let indices = vec![500, 1000];

    for i in indices.iter() {
        println!("Generating helpers {:?}", i);
        let mut base_eval_vec = vec![ScalarField::zero(); n];
        base_eval_vec[*i] = ScalarField::one();

        let base_eval = Evaluations::from_vec_and_domain(base_eval_vec, domain.d1);
        let base_poly: DensePolynomial<ScalarField> = base_eval.interpolate();

        let base_d2 = base_poly.evaluate_over_domain_by_ref(domain.d2);
        let numerator_eval = &(&base_d2 * &base_d2) - &base_d2;

        let numerator_eval_interpolated = numerator_eval.interpolate();

        let (quotient, res) = numerator_eval_interpolated
            .divide_by_vanishing_poly(domain.d1)
            .unwrap_or_else(fail_final_q_division);

        if !res.is_zero() {
            fail_final_q_division();
        }

        let comm = srs.commit_non_hiding(&quotient, 1).chunks[0];

        println!("Comm: {:?}", comm);

        helpers.push((quotient, comm))
    }

    {
        let data: Vec<ScalarField> = {
            //let mut data = vec![];
            //(0..srs.size())
            //    .into_iter()
            //    .for_each(|_| data.push(ScalarField::rand(&mut rng)));
            let mut data = vec![ScalarField::zero(); srs.size()];
            data[500] = ScalarField::from(123 as u64);
            //data[1000] = ScalarField::from(456 as u64);
            data
        };

        let data_poly: DensePolynomial<ScalarField> =
            Evaluations::from_vec_and_domain(data.clone(), domain.d1).interpolate();
        let data_comm: Curve = srs.commit_non_hiding(&data_poly, 1).chunks[0];

        let query: Vec<ScalarField> = {
            let mut query = vec![ScalarField::zero(); srs.size()];
            query[500] = ScalarField::one();
            //query[1000] = ScalarField::one();
            //let mut query = vec![];
            //(0..SRS_SIZE)
            //    .into_iter()
            //    .for_each(|_| query.push(Fp::from(rand::thread_rng().gen::<f64>() < 0.001)));
            query
        };

        let answer: Vec<ScalarField> = data
            .clone()
            .iter()
            .zip(query.iter())
            .map(|(d, q)| *d * q)
            .collect();

        let (query_sparse, answer_sparse) = {
            let mut res1 = vec![];
            let mut res2 = vec![];
            for i in 0..srs.size() {
                if !query[i].is_zero() {
                    res1.push(i);
                    res2.push(answer[i]);
                }
            }
            (res1, res2)
        };

        let quotient_poly: DensePolynomial<ScalarField> = {
            let query_d1 = Evaluations::from_vec_and_domain(query.to_vec(), domain.d1);
            let query_poly: DensePolynomial<ScalarField> = query_d1.clone().interpolate();
            let query_comm: PolyComm<Curve> = srs.commit_non_hiding(&query_poly, 1);

            let answer_d1 = Evaluations::from_vec_and_domain(answer.to_vec(), domain.d1);
            let answer_poly: DensePolynomial<ScalarField> = answer_d1.clone().interpolate();
            let answer_comm: PolyComm<Curve> = srs.commit_non_hiding(&answer_poly, 1);

            let data_d2 = data_poly.evaluate_over_domain_by_ref(domain.d2);
            let query_d2 = query_poly.evaluate_over_domain_by_ref(domain.d2);
            let answer_d2 = answer_poly.evaluate_over_domain_by_ref(domain.d2);

            let numerator_eval: Evaluations<ScalarField, R2D<ScalarField>> =
                &(&data_d2 * &query_d2) - &answer_d2;

            let numerator_eval_interpolated = numerator_eval.clone().interpolate();

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

        let quotient_poly_eval = &quotient_poly.evaluate_over_domain_by_ref(domain.d1);

        let quotient_comm_alt: Curve = query_sparse
            .iter()
            .zip(answer_sparse.iter())
            .enumerate()
            .map(|(i, (query_ix, answer))| helpers[i].1 * answer)
            .fold(<Curve as AffineRepr>::Group::zero(), |acc, new| acc + &new)
            .into();

        // commit to the quotient polynomial $t$.
        // num_chunks = 1 because our constraint is degree 2
        let quotient_comm = srs.commit_non_hiding(&quotient_poly, 1);
        assert!(quotient_comm.chunks.len() == 1);
        let quotient_comm = quotient_comm.chunks[0];

        let quotient_evals_alt: Evaluations<ScalarField, R2D<ScalarField>> =
            &helpers[0].0.evaluate_over_domain_by_ref(domain.d1) * answer_sparse[0];
        //                + &(&helpers[1].0.evaluate_over_domain_by_ref(domain.d1) * answer_sparse[1]);
        let quotient_poly_alt: DensePolynomial<ScalarField> =
            quotient_evals_alt.clone().interpolate();

        let evaluation_point = ScalarField::from(12345);

        let quotient_eval = quotient_poly.evaluate(&evaluation_point);
        let quotient_eval_alt = quotient_poly_alt.evaluate(&evaluation_point);
        println!("quotient_eval: {}", quotient_eval);
        println!("quotient_eval_alt: {}", quotient_eval_alt);

        println!("quotient_comm: {}", quotient_comm);
        println!("quotient_comm_alt: {}", quotient_comm_alt);

        assert!(quotient_eval == quotient_eval_alt && quotient_comm == quotient_comm_alt);
    }

    println!("Helpers geneated");

    helpers
}

#[instrument(skip_all, level = "debug")]
pub fn prove<RNG>(
    domain: EvaluationDomains<ScalarField>,
    srs: &SRS<Curve>,
    group_map: &<Curve as CommitmentCurve>::Map,
    rng: &mut RNG,
    quotient_helpers: Vec<(DensePolynomial<ScalarField>, Curve)>,
    // data[i] is queried if query[i] ≠ 0
    data: &[ScalarField],
    // data[i] is queried if query[i] ≠ 0
    query_sparse: Vec<usize>,
    // answer[i] = data[i] * query[i]
    answer_sparse: Vec<ScalarField>,
    // Commitment to data
    data_comm: &Curve,
) -> ReadProof
where
    RNG: RngCore + CryptoRng,
{
    let (_, endo_r) = Curve::endos();

    let mut fq_sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());

    let data_d1 = Evaluations::from_vec_and_domain(data.to_vec(), domain.d1);
    let data_poly: DensePolynomial<ScalarField> = data_d1.clone().interpolate();
    let data_comm: PolyComm<Curve> = PolyComm {
        chunks: vec![data_comm.clone()],
    };

    let (query, answer) = {
        let mut query = vec![Zero::zero(); domain.d1.size()];
        let mut answer = vec![Zero::zero(); domain.d1.size()];
        for (query_ix, answer_val) in query_sparse.iter().zip(answer_sparse.iter()) {
            query[*query_ix] = One::one();
            answer[*query_ix] = answer_val.clone();
        }
        (query, answer)
    };

    let query_d1 = Evaluations::from_vec_and_domain(query.to_vec(), domain.d1);
    let query_poly: DensePolynomial<ScalarField> = query_d1.clone().interpolate();
    let query_comm: PolyComm<Curve> = srs.commit_non_hiding(&query_poly, 1);

    let answer_d1 = Evaluations::from_vec_and_domain(answer.to_vec(), domain.d1);
    let answer_poly: DensePolynomial<ScalarField> = answer_d1.clone().interpolate();
    let answer_comm: PolyComm<Curve> = srs.commit_non_hiding(&answer_poly, 1);

    assert!(answer_d1.evals[1000] == ScalarField::from(123));

    fq_sponge.absorb_g(&[
        data_comm.chunks[0],
        query_comm.chunks[0],
        answer_comm.chunks[0],
    ]);

    let quotient_comm_alt: Curve = query_sparse
        .iter()
        .zip(answer_sparse.iter())
        .enumerate()
        .map(|(i, (query_ix, answer))| quotient_helpers[i].1 * answer)
        .fold(<Curve as AffineRepr>::Group::zero(), |acc, new| acc + &new)
        .into();

    // coefficient form, over d4? d2?
    // quotient_Poly has degree d1
    let quotient_poly: DensePolynomial<ScalarField> = {
        // TODO: do not re-interpolate, we already did d1

        // this is in the evaluation form
        // d(w_d2^i)
        let data_d2 = data_poly.evaluate_over_domain_by_ref(domain.d2);
        //let data_d2 = data_poly_d1.extrapolate_over(d1...d2);

        let query_d2 = query_poly.evaluate_over_domain_by_ref(domain.d2);
        let answer_d2 = answer_poly.evaluate_over_domain_by_ref(domain.d2);

        // q×d - a
        let numerator_eval: Evaluations<ScalarField, R2D<ScalarField>> =
            &(&data_d2 * &query_d2) - &answer_d2;

        // in the coefficent form? length d2?
        let numerator_eval_interpolated = numerator_eval.clone().interpolate();

        //for i in 0..numerator_eval.evals.len() {
        //    if !numerator_eval.evals[i].is_zero() {
        //        println!(
        //            "numerator_eval evals #{:?} is non zero: {:?}",
        //            i, numerator_eval.evals[i]
        //        )
        //    }
        //}
        println!("Prover, answer d2 at line 1000: {}", answer_d2.evals[1000]);
        println!("Prover, answer d2 at line 2000: {}", answer_d2.evals[2000]);

        println!(
            "Prover, numerator d2 at line 500: {}",
            numerator_eval.evals[500]
        );
        println!(
            "Prover, numerator d2 at line 2000: {}",
            numerator_eval.evals[2000]
        );
        println!(
            "Prover, numerator_interpolated at line 500: {}",
            numerator_eval_interpolated.coeffs[500]
        );
        println!(
            "Prover, numerator_interpolated at line 1000: {}",
            numerator_eval_interpolated.coeffs[1000]
        );

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

    let quotient_poly_eval = &quotient_poly.evaluate_over_domain_by_ref(domain.d1);

    println!(
        "Prover, quotient poly at line 500: {}",
        quotient_poly_eval.evals[500]
    );
    println!(
        "Prover, quotient poly at line 1000: {}",
        quotient_poly_eval.evals[1000]
    );

    let quotient_evals_alt: Evaluations<ScalarField, R2D<ScalarField>> =
        &quotient_helpers[0].0.evaluate_over_domain_by_ref(domain.d1) * answer_sparse[0];
    let quotient_poly_alt: DensePolynomial<ScalarField> = quotient_evals_alt.clone().interpolate();

    println!(
        "Prover, quotient alt poly at line 500: {}",
        quotient_evals_alt.evals[500]
    );
    println!(
        "Prover, quotient alt poly at line 1000: {}",
        quotient_evals_alt.evals[1000]
    );

    // commit to the quotient polynomial $t$.
    // num_chunks = 1 because our constraint is degree 2
    let quotient_comm = srs.commit_non_hiding(&quotient_poly, 1);
    assert!(quotient_comm.chunks.len() == 1);
    let quotient_comm = quotient_comm.chunks[0];

    assert!(
        quotient_comm == quotient_comm_alt,
        "Commitments must be equal: {:?} vs {:?}",
        quotient_comm,
        quotient_comm_alt
    );

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
    let quotient_eval_alt = quotient_poly_alt.evaluate(&evaluation_point);
    println!("Prover, quotient_eval: {}", quotient_eval);
    println!("Prover, quotient_eval_alt: {}", quotient_eval_alt);

    for eval in [data_eval, query_eval, answer_eval, quotient_eval].into_iter() {
        fr_sponge.absorb(&eval);
    }

    let polyscale_chal = fr_sponge.challenge();
    let polyscale = polyscale_chal.to_field(endo_r);
    let evalscale_chal = fr_sponge.challenge();
    let evalscale = evalscale_chal.to_field(endo_r);

    // Creating the polynomials for the batch proof
    let coefficients_form = DensePolynomialOrEvaluations::<_, R2D<ScalarField>>::DensePolynomial;
    let non_hiding = |n_chunks| PolyComm {
        chunks: vec![ScalarField::zero(); n_chunks],
    };

    // Gathering all polynomials to use in the opening proof
    let opening_proof_inputs: Vec<_> = vec![
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
        polyscale,
        evalscale,
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
        opening_proof,
    }
}

pub fn verify<RNG>(
    domain: EvaluationDomains<ScalarField>,
    srs: &SRS<Curve>,
    group_map: &<Curve as CommitmentCurve>::Map,
    rng: &mut RNG,
    // Commitment to data
    data_comm: &Curve,
    proof: &ReadProof,
) -> bool
where
    RNG: RngCore + CryptoRng,
{
    let (_, endo_r) = Curve::endos();

    let mut fq_sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());
    fq_sponge.absorb_g(&[*data_comm, proof.query_comm, proof.answer_comm]);
    fq_sponge.absorb_g(&[proof.quotient_comm]);

    let evaluation_point = fq_sponge.squeeze(2);

    let fq_sponge_before_evaluations = fq_sponge.clone();
    let mut fr_sponge = CurveFrSponge::new(Curve::sponge_params());
    fr_sponge.absorb(&fq_sponge.digest());

    let vanishing_poly_at_zeta = domain.d1.vanishing_polynomial().evaluate(&evaluation_point);
    let quotient_eval = {
        &(proof.data_eval * proof.query_eval - proof.answer_eval)
            * &vanishing_poly_at_zeta.inverse().unwrap()
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

    let polyscale_chal = fr_sponge.challenge();
    let polyscale = polyscale_chal.to_field(endo_r);
    let evalscale_chal = fr_sponge.challenge();
    let evalscale = evalscale_chal.to_field(endo_r);

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
        let es: Vec<_> = coms_and_evaluations
            .iter()
            .map(|Evaluation { evaluations, .. }| evaluations.clone())
            .collect();

        combined_inner_product(&polyscale, &evalscale, es.as_slice())
    };

    srs.verify(
        group_map,
        &mut [BatchEvaluationProof {
            sponge: fq_sponge_before_evaluations,
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
    use crate::{env, Curve, ScalarField, SRS_SIZE};
    use ark_ec::AffineRepr;
    use ark_ff::{One, UniformRand};
    use ark_poly::{univariate::DensePolynomial, Evaluations};
    use ark_std::Zero;
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
    fn test_read_proof_helpers() {
        let _quotient_helpers =
            crate::read_proof::precompute_quotient_helpers_alt(&SRS, *DOMAIN, vec![500]);
    }

    #[test]
    fn test_read_proof_completeness() {
        let mut rng = o1_utils::tests::make_test_rng(None);

        let data: Vec<ScalarField> = {
            //let mut data = vec![];
            //(0..SRS_SIZE)
            //    .into_iter()
            //    .for_each(|_| data.push(Fp::rand(&mut rng)));
            let mut data = vec![Fp::zero(); SRS_SIZE];
            data[1000] = ScalarField::from(123 as u64);
            data
        };

        let data_poly: DensePolynomial<ScalarField> =
            Evaluations::from_vec_and_domain(data.clone(), (*DOMAIN).d1).interpolate();
        let data_comm: Curve = SRS.commit_non_hiding(&data_poly, 1).chunks[0];

        let query: Vec<ScalarField> = {
            let mut query = vec![ScalarField::zero(); SRS_SIZE];
            query[1000] = ScalarField::one();
            //let mut query = vec![];
            //(0..SRS_SIZE)
            //    .into_iter()
            //    .for_each(|_| query.push(Fp::from(rand::thread_rng().gen::<f64>() < 0.001)));
            query
        };

        let answer: Vec<ScalarField> = data
            .clone()
            .iter()
            .zip(query.iter())
            .map(|(d, q)| *d * q)
            .collect();

        println!("Answer vector first element: {}", answer[1000]);

        let (query_sparse, answer_sparse) = {
            let mut res1 = vec![];
            let mut res2 = vec![];
            for i in 0..SRS_SIZE {
                if !query[i].is_zero() {
                    res1.push(i);
                    res2.push(answer[i]);
                }
            }
            (res1, res2)
        };

        let quotient_helpers =
            crate::read_proof::precompute_quotient_helpers(&SRS, *DOMAIN, query_sparse.clone());

        //let proof = prove(
        //    *DOMAIN,
        //    &SRS,
        //    &GROUP_MAP,
        //    &mut rng,
        //    quotient_helpers,
        //    data.as_slice(),
        //    query_sparse,
        //    answer_sparse,
        //    &data_comm,
        //);
        //let res = verify(*DOMAIN, &SRS, &GROUP_MAP, &mut rng, &data_comm, &proof);

        //assert!(res, "Proof must verify");
    }

    #[test]
    fn test_read_proof_soundness() {
        let mut rng = o1_utils::tests::make_test_rng(None);

        let data: Vec<ScalarField> = {
            let mut data = vec![];
            (0..SRS_SIZE)
                .into_iter()
                .for_each(|_| data.push(Fp::rand(&mut rng)));
            data
        };

        let data_poly: DensePolynomial<ScalarField> =
            Evaluations::from_vec_and_domain(data.clone(), (*DOMAIN).d1).interpolate();
        let data_comm: Curve = SRS.commit_non_hiding(&data_poly, 1).chunks[0];

        let query: Vec<ScalarField> = {
            let mut query = vec![];
            (0..SRS_SIZE)
                .into_iter()
                .for_each(|_| query.push(Fp::from(rand::thread_rng().gen::<f64>() < 0.001)));
            query
        };

        let answer: Vec<ScalarField> = data
            .clone()
            .iter()
            .zip(query.iter())
            .map(|(d, q)| *d * q)
            .collect();

        let (query_sparse, answer_sparse) = {
            let mut res1 = vec![];
            let mut res2 = vec![];
            for i in 0..SRS_SIZE {
                if !query[i].is_zero() {
                    res1.push(i);
                    res2.push(answer[i]);
                }
            }
            (res1, res2)
        };

        let quotient_helpers =
            crate::read_proof::precompute_quotient_helpers(&SRS, *DOMAIN, query_sparse.clone());

        let proof = prove(
            *DOMAIN,
            &SRS,
            &GROUP_MAP,
            &mut rng,
            quotient_helpers,
            data.as_slice(),
            query_sparse,
            answer_sparse,
            &data_comm,
        );

        let proof_malformed_1 = ReadProof {
            answer_comm: Curve::zero(),
            ..proof.clone()
        };

        let res_1 = verify(
            *DOMAIN,
            &SRS,
            &GROUP_MAP,
            &mut rng,
            &data_comm,
            &proof_malformed_1,
        );

        assert!(!res_1, "Malformed proof #1 must NOT verify");

        let proof_malformed_2 = ReadProof {
            query_eval: ScalarField::one(),
            ..proof.clone()
        };

        let res_2 = verify(
            *DOMAIN,
            &SRS,
            &GROUP_MAP,
            &mut rng,
            &data_comm,
            &proof_malformed_2,
        );

        assert!(!res_2, "Malformed proof #2 must NOT verify");
    }
}
