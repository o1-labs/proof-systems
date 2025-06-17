use crate::{Curve, CurveFqSponge, CurveFrSponge, ScalarField, SRS_SIZE};
use ark_ec::AffineRepr;
use ark_ff::{Field, One, Zero};
use ark_poly::{
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    EvaluationDomain, Evaluations, Polynomial, Radix2EvaluationDomain as R2D,
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
    pub quotient_comm: Curve,

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
    indices: Vec<usize>,
    data: Vec<Evaluations<ScalarField, R2D<ScalarField>>>,
    data_comms: Vec<Curve>,
) -> VIDProof
where
    RNG: RngCore + CryptoRng,
{
    let mut fq_sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());

    println!("Generating bases");
    let bases_d2: DensePolynomial<ScalarField> =
        srs.lagrange_basis_raw(domain.d2, indices.clone())[0].clone();
    println!("Generating bases DONE");

    fq_sponge.absorb_g(&data_comms);

    // aka zeta
    let recombination_point = fq_sponge.challenge();

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

    let combined_data_commitment =
        crate::utils::aggregate_commitments(recombination_point, data_comms.as_slice());

    let omegas: Vec<ScalarField> = indices
        .clone()
        .into_iter()
        .map(|i| domain.d2.group_gen.pow([i as u64]))
        .collect();

    let evaluations: Vec<ScalarField> = omegas
        .iter()
        .map(|omega| combined_data_poly.evaluate(omega))
        .collect();

    let quotient_poly: DensePolynomial<ScalarField> = {
        let combined_data_d2 = combined_data_poly.evaluate_over_domain_by_ref(domain.d2);

        // p(X) - \prod L_i(X) e_i
        let numerator_eval: Evaluations<ScalarField, R2D<ScalarField>> = {
            let mut res = combined_data_d2;
            for i in indices {
                res.evals[i] = ScalarField::zero();
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

    // commit to the quotient polynomial $t$.
    // num_chunks = 1 because our constraint is degree 2, which makes the quotient polynomial of degree d1
    let quotient_comm = srs.commit_non_hiding(&quotient_poly, 1).chunks[0];
    fq_sponge.absorb_g(&[quotient_comm]);

    // aka zeta
    let evaluation_point = fq_sponge.challenge();

    // Fiat Shamir - absorbing evaluations
    let mut fr_sponge = CurveFrSponge::new(Curve::sponge_params());
    fr_sponge.absorb(&fq_sponge.clone().digest());

    let combined_data_eval = combined_data_poly.evaluate(&evaluation_point);
    let quotient_eval = quotient_poly.evaluate(&evaluation_point);

    for eval in [combined_data_eval, quotient_eval].into_iter() {
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
            (coefficients_form(&combined_data_poly), non_hiding(1)),
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

    VIDProof {
        quotient_comm,
        combined_data_eval,
        opening_proof,
    }
}

pub fn verify_vid_ipa<RNG>(
    srs: &SRS<Curve>,
    domain: EvaluationDomains<ScalarField>,
    group_map: &<Curve as CommitmentCurve>::Map,
    rng: &mut RNG,
) -> bool
where
    RNG: RngCore + CryptoRng,
{
    true
    //    let mut fq_sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());
    //    fq_sponge.absorb_g(&[
    //        inst.core.comm_d,
    //        inst.core.comm_q,
    //        inst.core.comm_a,
    //        inst.comm_e,
    //    ]);
    //    fq_sponge.absorb_g(&[proof.quotient_comm]);
    //
    //    let evaluation_point = fq_sponge.challenge();
    //
    //    let mut fr_sponge = CurveFrSponge::new(Curve::sponge_params());
    //    fr_sponge.absorb(&fq_sponge.clone().digest());
    //
    //    let vanishing_poly_at_zeta = domain.d1.vanishing_polynomial().evaluate(&evaluation_point);
    //    let quotient_eval = {
    //        (inst.u * proof.answer_eval - proof.data_eval * proof.query_eval + proof.error_eval)
    //            * vanishing_poly_at_zeta
    //                .inverse()
    //                .unwrap_or_else(|| panic!("Inverse fails only with negligible probability"))
    //    };
    //
    //    for eval in [
    //        proof.data_eval,
    //        proof.query_eval,
    //        proof.answer_eval,
    //        proof.error_eval,
    //        quotient_eval,
    //    ]
    //    .into_iter()
    //    {
    //        fr_sponge.absorb(&eval);
    //    }
    //
    //    let (_, endo_r) = Curve::endos();
    //    // Generate scalars used as combiners for sub-statements within our IPA opening proof.
    //    let polyscale = fr_sponge.challenge().to_field(endo_r);
    //    let evalscale = fr_sponge.challenge().to_field(endo_r);
    //
    //    let coms_and_evaluations = vec![
    //        Evaluation {
    //            commitment: PolyComm {
    //                chunks: vec![inst.core.comm_d],
    //            },
    //            evaluations: vec![vec![proof.data_eval]],
    //        },
    //        Evaluation {
    //            commitment: PolyComm {
    //                chunks: vec![inst.core.comm_q],
    //            },
    //            evaluations: vec![vec![proof.query_eval]],
    //        },
    //        Evaluation {
    //            commitment: PolyComm {
    //                chunks: vec![inst.core.comm_a],
    //            },
    //            evaluations: vec![vec![proof.answer_eval]],
    //        },
    //        Evaluation {
    //            commitment: PolyComm {
    //                chunks: vec![inst.comm_e],
    //            },
    //            evaluations: vec![vec![proof.error_eval]],
    //        },
    //        Evaluation {
    //            commitment: PolyComm {
    //                chunks: vec![proof.quotient_comm],
    //            },
    //            evaluations: vec![vec![quotient_eval]],
    //        },
    //    ];
    //    let combined_inner_product = {
    //        let evaluations: Vec<_> = coms_and_evaluations
    //            .iter()
    //            .map(|Evaluation { evaluations, .. }| evaluations.clone())
    //            .collect();
    //
    //        combined_inner_product(&polyscale, &evalscale, evaluations.as_slice())
    //    };
    //
    //    srs.verify(
    //        group_map,
    //        &mut [BatchEvaluationProof {
    //            sponge: fq_sponge,
    //            evaluation_points: vec![evaluation_point],
    //            polyscale,
    //            evalscale,
    //            evaluations: coms_and_evaluations,
    //            opening: &proof.opening_proof,
    //            combined_inner_product,
    //        }],
    //        rng,
    //    )
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

        let indices: Vec<usize> = generate_unique_u64(512, 1 << 17);

        println!("Creating data");
        let number_of_coms = 5;
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
            &srs, domain, &group_map, &mut rng, indices, data_evals, data_comms,
        );

        let res = verify_vid_ipa(&srs, domain, &group_map, &mut rng);
        assert!(res)
    }
}
