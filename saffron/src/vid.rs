use crate::{Curve, CurveFqSponge, CurveFrSponge, ScalarField, SRS_SIZE};
use ark_ec::AffineRepr;
use ark_ff::{Field, One, Zero};
use ark_poly::{
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    DenseUVPolynomial, EvaluationDomain, Evaluations, Polynomial, Radix2EvaluationDomain as R2D,
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
use rayon::iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};

#[derive(Debug, Clone)]
pub struct VIDProof {
    pub quotient_comm: Vec<Curve>,

    pub quotient_evals: Vec<ScalarField>,

    pub combined_data_eval: ScalarField,

    pub opening_proof: OpeningProof<Curve>,
}

//pub fn precompute_quotient_helpers_alt(
//    srs: &SRS<Curve>,
//    domain: EvaluationDomains<ScalarField>,
//    indices: Vec<usize>,
//) -> Vec<(DensePolynomial<ScalarField>, Curve)> {
//    use ark_ff::{One, UniformRand};
//    let mut rng = o1_utils::tests::make_test_rng(None);
//    println!("Generating helpers");
//    let n = domain.d1.size();
//
//    {
//        let bases_var1: DensePolynomial<ScalarField> =
//            srs.lagrange_basis_raw(domain.d1, vec![5])[0].clone();
//
//        let mut base_eval_vec = vec![ScalarField::zero(); n];
//        base_eval_vec[5] = ScalarField::one();
//
//        let base_eval = Evaluations::from_vec_and_domain(base_eval_vec, domain.d1);
//        let base_poly: DensePolynomial<ScalarField> = base_eval.interpolate();
//
//        assert!(bases_var1 == base_poly);
//    }
//
//    let mut helpers: Vec<_> = vec![];
//
//    let fail_final_q_division = || panic!("Division by vanishing poly must not fail");
//
//    let indices = vec![500, 1000];
//
//    for i in indices.iter() {
//        println!("Generating helpers {:?}", i);
//        let mut base_eval_vec = vec![ScalarField::zero(); n];
//        base_eval_vec[*i] = ScalarField::one();
//
//        let base_eval = Evaluations::from_vec_and_domain(base_eval_vec, domain.d1);
//        let base_poly: DensePolynomial<ScalarField> = base_eval.interpolate();
//
//        let base_d2 = base_poly.evaluate_over_domain_by_ref(domain.d2);
//        let numerator_eval = &(&base_d2 * &base_d2) - &base_d2;
//
//        let numerator_eval_interpolated = numerator_eval.interpolate();
//
//        let (quotient, res) = numerator_eval_interpolated
//            .divide_by_vanishing_poly(domain.d1)
//            .unwrap_or_else(fail_final_q_division);
//
//        if !res.is_zero() {
//            fail_final_q_division();
//        }
//
//        let comm = srs.commit_non_hiding(&quotient, 1).chunks[0];
//
//        println!("Comm: {:?}", comm);
//
//        helpers.push((quotient, comm))
//    }
//
//    println!("Helpers geneated");
//
//    helpers
//}

pub fn prove_vid_ipa<RNG>(
    srs: &SRS<Curve>,
    domain: EvaluationDomains<ScalarField>,
    group_map: &<Curve as CommitmentCurve>::Map,
    rng: &mut RNG,
    indices: &[usize],
    data: &[Evaluations<ScalarField, R2D<ScalarField>>],
    data_comms: &[Curve],
) -> VIDProof
where
    RNG: RngCore + CryptoRng,
{
    let mut fq_sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());

    fq_sponge.absorb_g(&data_comms);

    let recombination_point = fq_sponge.challenge();
    println!("Prover, recombination point: {:?}", recombination_point);

    // TODO extend over D2

    let combined_data: Vec<ScalarField> = {
        let mut initial: Vec<ScalarField> = data[data.len() - 1].evals.to_vec();

        (0..data.len() - 1).rev().for_each(|chunk_ix| {
            initial.par_iter_mut().enumerate().for_each(|(idx, acc)| {
                *acc *= recombination_point;
                *acc += data[chunk_ix].evals[idx];
            })
        });

        initial
    };

    let combined_data_poly: DensePolynomial<ScalarField> =
        Evaluations::from_vec_and_domain(combined_data, domain.d1).interpolate_by_ref();

    let omegas: Vec<ScalarField> = indices
        .iter()
        .map(|i| domain.d2.group_gen.pow([*i as u64]))
        .collect();

    let quotient_poly: DensePolynomial<ScalarField> = {
        let combined_data_d2 = combined_data_poly.evaluate_over_domain_by_ref(domain.d2);

        // p(X) - \prod L_i(X) e_i
        let numerator_eval: Evaluations<ScalarField, R2D<ScalarField>> = {
            let mut res = combined_data_d2;
            for i in indices {
                res.evals[*i] = ScalarField::zero();
            }
            res
        };

        let numerator_eval_interpolated = numerator_eval.interpolate();

        let divisor: DensePolynomial<ScalarField> = omegas
            .iter()
            .map(|omega| DensePolynomial {
                coeffs: vec![-omega.clone(), ScalarField::one()],
            })
            .reduce(|a, b| a * b)
            .unwrap();

        let fail_final_q_division = || panic!("Division by poly must not fail");
        // We compute the polynomial t(X) by dividing the constraints polynomial
        // by the vanishing polynomial, i.e. Z_H(X).
        let (quotient, res) = DenseOrSparsePolynomial::divide_with_q_and_r(
            &From::from(numerator_eval_interpolated),
            &From::from(divisor),
        )
        .unwrap();

        // As the constraints must be verified on H, the rest of the division
        // must be equal to 0 as the constraints polynomial and Z_H(X) are both
        // equal on H.
        if !res.is_zero() {
            fail_final_q_division();
        }

        quotient
    };

    println!("Degree of quotient poly: {:?}", quotient_poly.degree());

    let (quotient_poly_1, quotient_poly_2) = {
        let mut quotient_poly_1 = quotient_poly.clone();
        let quotient_poly_2 = DensePolynomial {
            coeffs: quotient_poly_1.coeffs()[srs.size()..].to_vec(),
        };
        quotient_poly_1.coeffs.truncate(srs.size());
        (quotient_poly_1, quotient_poly_2)
    };

    // commit to the quotient polynomial $t$.
    // num_chunks = 1 because our constraint is degree 2, which makes the quotient polynomial of degree d1
    let quotient_comm: Vec<Curve> = srs.commit_non_hiding(&quotient_poly, 2).chunks;
    fq_sponge.absorb_g(&quotient_comm);

    // aka zeta
    let evaluation_point = fq_sponge.challenge();
    println!("Prover, evaluation point: {:?}", evaluation_point);
    println!(
        "Prover, evaluation point^4, ^5: {:?}, {:?}",
        evaluation_point.pow([4]),
        evaluation_point.pow([5])
    );

    // Fiat Shamir - absorbing evaluations
    let mut fr_sponge = CurveFrSponge::new(Curve::sponge_params());
    fr_sponge.absorb(&fq_sponge.clone().digest());

    let combined_data_eval = combined_data_poly.evaluate(&evaluation_point);
    let quotient_eval = quotient_poly.evaluate(&evaluation_point);
    let quotient_eval_1 = quotient_poly_1.evaluate(&evaluation_point);
    let quotient_eval_2 = quotient_poly_2.evaluate(&evaluation_point);
    println!("Prover, quotient eval: {:?}", quotient_eval);
    println!("Prover, quotient eval 1: {:?}", quotient_eval_1);
    println!("Prover, quotient eval 2: {:?}", quotient_eval_2);

    for eval in [combined_data_eval, quotient_eval_1, quotient_eval_2].into_iter() {
        fr_sponge.absorb(&eval);
    }

    let (_, endo_r) = Curve::endos();
    // Generate scalars used as combiners for sub-statements within our IPA opening proof.
    //let polyscale = ScalarField::one();
    //let evalscale = ScalarField::one();
    let polyscale = fr_sponge.challenge().to_field(endo_r);
    let evalscale = fr_sponge.challenge().to_field(endo_r);
    println!(
        "Prover, polyscale {:?}, evalscale {:?}",
        polyscale, evalscale
    );

    // Creating the polynomials for the batch proof
    // Gathering all polynomials to use in the opening proof
    let opening_proof_inputs: Vec<_> = {
        let coefficients_form =
            DensePolynomialOrEvaluations::<_, R2D<ScalarField>>::DensePolynomial;
        let non_hiding = |n_chunks| PolyComm {
            chunks: vec![ScalarField::zero(); n_chunks],
        };

        vec![
            (coefficients_form(&combined_data_poly), non_hiding(1)),
            (coefficients_form(&quotient_poly_1), non_hiding(1)),
            (coefficients_form(&quotient_poly_2), non_hiding(1)),
        ]
    };

    let opening_proof = srs.open(
        group_map,
        opening_proof_inputs.as_slice(),
        &[evaluation_point],
        polyscale,
        evalscale,
        fq_sponge.clone(),
        rng,
    );

    //    // sanity checking
    //    {
    //        let combined_data_commitment_v =
    //            crate::utils::aggregate_commitments(recombination_point, data_comms);
    //
    //        let combined_data_commitment = srs.commit_non_hiding(&combined_data_poly, 1).chunks[0];
    //
    //        assert!(combined_data_commitment_v == combined_data_commitment);
    //
    //        let coms_and_evaluations = vec![
    //            //Evaluation {
    //            //    commitment: PolyComm {
    //            //        chunks: vec![combined_data_commitment],
    //            //    },
    //            //    evaluations: vec![vec![combined_data_eval.clone()]],
    //            //},
    //            Evaluation {
    //                commitment: PolyComm {
    //                    chunks: vec![quotient_comm[0].clone()],
    //                },
    //                evaluations: vec![vec![quotient_eval_1.clone()]],
    //            },
    //            Evaluation {
    //                commitment: PolyComm {
    //                    chunks: vec![quotient_comm[1].clone()],
    //                },
    //                evaluations: vec![vec![quotient_eval_2.clone()]],
    //            },
    //        ];
    //        let combined_inner_product = {
    //            let evaluations: Vec<_> = coms_and_evaluations
    //                .iter()
    //                .map(|Evaluation { evaluations, .. }| evaluations.clone())
    //                .collect();
    //
    //            combined_inner_product(&polyscale, &evalscale, evaluations.as_slice())
    //        };
    //        println!(
    //            "Prover, combined_inner_product_2: {:?}",
    //            combined_inner_product
    //        );
    //
    //        assert!(srs.verify(
    //            group_map,
    //            &mut [BatchEvaluationProof {
    //                sponge: fq_sponge.clone(),
    //                evaluation_points: vec![evaluation_point],
    //                polyscale,
    //                evalscale,
    //                evaluations: coms_and_evaluations,
    //                opening: &opening_proof,
    //                combined_inner_product,
    //            }],
    //            rng,
    //        ));
    //    }

    VIDProof {
        quotient_comm,
        quotient_evals: vec![quotient_eval_1, quotient_eval_2],
        combined_data_eval,
        opening_proof,
    }
}

pub fn verify_vid_ipa<RNG>(
    srs: &SRS<Curve>,
    domain: EvaluationDomains<ScalarField>,
    bases_d2: &[DensePolynomial<ScalarField>],
    group_map: &<Curve as CommitmentCurve>::Map,
    rng: &mut RNG,
    indices: &[usize],
    proof: &VIDProof,
    data_comms: &[Curve],
    data: &[Vec<ScalarField>],
) -> bool
where
    RNG: RngCore + CryptoRng,
{
    let mut fq_sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());
    fq_sponge.absorb_g(&data_comms);

    let recombination_point = fq_sponge.challenge();
    println!("Verifier, recombination point: {:?}", recombination_point);

    let combined_data_commitment =
        crate::utils::aggregate_commitments(recombination_point, data_comms);

    fq_sponge.absorb_g(&proof.quotient_comm);

    let evaluation_point = fq_sponge.challenge();
    println!("Verifier, evaluation point: {:?}", evaluation_point);

    let mut fr_sponge = CurveFrSponge::new(Curve::sponge_params());
    fr_sponge.absorb(&fq_sponge.clone().digest());

    let omegas: Vec<ScalarField> = indices
        .iter()
        .map(|i| domain.d2.group_gen.pow([*i as u64]))
        .collect();

    let combined_data: Vec<ScalarField> = {
        let mut initial: Vec<ScalarField> = data[data.len() - 1].clone();

        (0..data.len() - 1).rev().for_each(|chunk_ix| {
            initial.par_iter_mut().enumerate().for_each(|(idx, acc)| {
                *acc *= recombination_point;
                *acc += data[chunk_ix][idx];
            })
        });

        initial
    };

    let quotient_eval = {
        let divisor_poly_at_zeta: ScalarField = omegas
            .iter()
            .map(|omega| &evaluation_point - &omega)
            .reduce(|a, b| a * b)
            .unwrap();

        let mut eval = -proof.combined_data_eval;
        for (lagrange, data_eval) in bases_d2.iter().zip(combined_data.iter()) {
            eval += lagrange.evaluate(&evaluation_point) * data_eval;
        }
        eval = ScalarField::zero() - eval;
        eval = eval * divisor_poly_at_zeta.inverse().unwrap();
        eval
    };
    println!("Verifier, quotient eval: {:?}", quotient_eval);

    assert!(
        quotient_eval
            == proof.quotient_evals[0]
                + evaluation_point.pow([srs.size() as u64]) * proof.quotient_evals[1]
    );

    for eval in [
        proof.combined_data_eval,
        proof.quotient_evals[0],
        proof.quotient_evals[1],
    ]
    .into_iter()
    {
        fr_sponge.absorb(&eval);
    }

    let (_, endo_r) = Curve::endos();
    // Generate scalars used as combiners for sub-statements within our IPA opening proof.
    let polyscale = fr_sponge.challenge().to_field(endo_r);
    let evalscale = fr_sponge.challenge().to_field(endo_r);
    println!(
        "Verifier, polyscale {:?}, evalscale {:?}",
        polyscale, evalscale
    );

    let coms_and_evaluations = vec![
        Evaluation {
            commitment: PolyComm {
                chunks: vec![combined_data_commitment],
            },
            evaluations: vec![vec![proof.combined_data_eval]],
        },
        Evaluation {
            commitment: PolyComm {
                chunks: vec![proof.quotient_comm[0].clone()],
            },
            evaluations: vec![vec![proof.quotient_evals[0].clone()]],
        },
        Evaluation {
            commitment: PolyComm {
                chunks: vec![proof.quotient_comm[1].clone()],
            },
            evaluations: vec![vec![proof.quotient_evals[1].clone()]],
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
    use super::*;

    use crate::{Curve, ScalarField};
    use ark_ec::AffineRepr;
    use ark_ff::One;
    use ark_std::UniformRand;
    use kimchi::{circuits::domains::EvaluationDomains, groupmap::GroupMap};
    use mina_curves::pasta::Vesta;
    use poly_commitment::commitment::CommitmentCurve;
    use rand::rngs::OsRng;

    fn generate_unique_u64(count: usize, max_value: usize) -> Vec<usize> {
        use rand::{seq::SliceRandom, Rng};
        use std::collections::HashSet;
        let mut rng = rand::thread_rng();
        let mut unique_values = HashSet::new();

        while unique_values.len() < count {
            unique_values.insert(rng.gen_range(0..max_value));
        }

        unique_values.into_iter().collect()
    }

    #[test]
    fn test_run_vid() {
        let mut rng = OsRng;

        let srs = poly_commitment::precomputed_srs::get_srs_test();
        let domain: EvaluationDomains<ScalarField> =
            EvaluationDomains::<ScalarField>::create(srs.size()).unwrap();

        let group_map = <Vesta as CommitmentCurve>::Map::setup();

        let all_indices: Vec<usize> = (0..1 << 17).collect();
        let verifier_indices: Vec<usize> = generate_unique_u64(512, 1 << 17);

        println!("Generating bases");
        let bases_d2: Vec<DensePolynomial<ScalarField>> =
            srs.lagrange_basis_raw(domain.d2, &verifier_indices);
        println!("Generating bases DONE");

        println!("Creating data");
        let number_of_coms = 16;
        let data: Vec<Vec<ScalarField>> = (0..number_of_coms)
            .map(|_| {
                (0..domain.d1.size)
                    .map(|_| ScalarField::rand(&mut rng))
                    .collect()
            })
            .collect();

        let data_evals: Vec<Evaluations<ScalarField, R2D<ScalarField>>> = data
            .into_iter()
            .map(|col| Evaluations::from_vec_and_domain(col, domain.d1))
            .collect();

        println!("Committing to data");
        let data_comms: Vec<Curve> = data_evals
            .iter()
            .map(|data_col| {
                srs.commit_evaluations_non_hiding(domain.d1, data_col)
                    .chunks[0]
            })
            .collect();

        println!("Calling the prover");

        let proof = prove_vid_ipa(
            &srs,
            domain,
            &group_map,
            &mut rng,
            &verifier_indices,
            &data_evals,
            &data_comms,
        );

        let expanded_data_at_ixs: Vec<Vec<ScalarField>> = data_evals
            .iter()
            .map(|column_evals| {
                let expanded = column_evals
                    .interpolate_by_ref()
                    .evaluate_over_domain_by_ref(domain.d2);
                verifier_indices
                    .iter()
                    .map(|&i| expanded[i].clone())
                    .collect()
            })
            .collect();

        let res = verify_vid_ipa(
            &srs,
            domain,
            &bases_d2,
            &group_map,
            &mut rng,
            &verifier_indices,
            &proof,
            &data_comms,
            &expanded_data_at_ixs,
        );
        assert!(res, "proof must verify")
    }
}
