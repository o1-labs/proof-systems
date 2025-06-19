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
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefMutIterator, ParallelIterator,
};
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct VIDProof {
    pub quotient_comm: Vec<Curve>,

    pub quotient_evals: Vec<ScalarField>,

    pub combined_data_eval: ScalarField,

    pub opening_proof: OpeningProof<Curve>,
}

/// Divide `self` by the vanishing polynomial for the sub-domain, `X^{domain_size} - coeff`.
///
/// coeff_powers are w^i starting with i = 0
pub fn divide_by_sub_vanishing_poly(
    poly: &DensePolynomial<ScalarField>,
    domain_size: usize,
    coeff_powers: &[ScalarField],
) -> DensePolynomial<ScalarField> {
    if poly.coeffs.len() < domain_size {
        // If degree(poly) < len(Domain), then the quotient is zero, and the entire polynomial is the remainder
        DensePolynomial::<ScalarField>::zero()
    } else {
        // Compute the quotient
        //
        // If `poly.len() <= 2 * domain_size`
        //    then quotient is simply `poly.coeffs[domain_size..]`
        // Otherwise
        //    during the division by `x^domain_size - 1`, some of `poly.coeffs[domain_size..]` will be updated as well
        //    which can be computed using the following algorithm.
        //

        let quotient_vec = (0..(poly.len() / domain_size))
            .into_par_iter()
            .map(|i| poly.coeffs[domain_size * (i + 1)..].to_vec())
            .zip(coeff_powers)
            .map(|(poly, pow)| poly.into_iter().map(|v| v * pow).collect::<Vec<_>>())
            .reduce_with(|mut l, r| {
                for i in 0..std::cmp::min(l.len(), r.len()) {
                    l[i] += r[i]
                }
                l
            })
            .unwrap();

        //        // TODO parallelise
        //        let mut quotient_vec = poly.coeffs[domain_size..].to_vec();
        //
        //        //println!("poly.len(): {:?}", poly.len());
        //        //assert!(poly.len() / domain_size <= 2);
        //
        //        if poly.len() / domain_size > 1 {
        //            let mut addons: Vec<_> = (1..(poly.len() / domain_size))
        //                .into_par_iter()
        //                .map(|i| poly.coeffs[domain_size * (i + 1)..].to_vec())
        //                .zip(coeff_powers)
        //                .map(|(poly, pow)| poly.into_iter().map(|v| v * pow).collect::<Vec<_>>())
        //                .reduce_with(|mut l, r| {
        //                    for i in 0..std::cmp::min(l.len(), r.len()) {
        //                        l[i] += r[i]
        //                    }
        //                    l
        //                })
        //                .unwrap();
        //
        //            for i in 1..(poly.len() / domain_size) {
        //                quotient_vec
        //                    .iter_mut()
        //                    .zip(&poly.coeffs[domain_size * (i + 1)..])
        //                    .for_each(|(s, c)| *s += c * &(coeff_powers[i]));
        //            }
        //        }
        //            .reduce_with(|mut l, r| &l * &r)
        //            .unwrap()

        let quotient = DensePolynomial::from_coefficients_vec(quotient_vec);
        quotient
    }
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
    bases_d2: &[DensePolynomial<ScalarField>],
    group_map: &<Curve as CommitmentCurve>::Map,
    rng: &mut RNG,
    per_node_size: usize,
    data: &[Evaluations<ScalarField, R2D<ScalarField>>],
    data_comms: &[Curve],
) -> Vec<VIDProof>
where
    RNG: RngCore + CryptoRng,
{
    let mut fq_sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());

    fq_sponge.absorb_g(&data_comms);

    let recombination_point = fq_sponge.challenge();
    println!("Prover, recombination point: {:?}", recombination_point);

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
        Evaluations::from_vec_and_domain(combined_data.clone(), domain.d1).interpolate_by_ref();

    let combined_data_d2 = combined_data_poly.evaluate_over_domain_by_ref(domain.d2);

    let mut proofs: Vec<VIDProof> = vec![];
    let proofs_number = domain.d2.size() / per_node_size;

    println!("proofs_number: {:?}", proofs_number);
    println!("per_node_size: {:?}", per_node_size);

    let fq_sponge_common = fq_sponge.clone();

    println!("computing all divisors");
    //let all_divisors: Vec<DensePolynomial<ScalarField>> = (0..proofs_number)
    //    .map(|i| {
    //        let indices: Vec<usize> = (i * per_node_size..(i + 1) * per_node_size).collect();
    //        let omegas: Vec<ScalarField> = indices
    //            .iter()
    //            .map(|i| domain.d2.group_gen.pow([*i as u64]))
    //            .collect();

    //        println!("Divisor");
    //        omegas
    //            .into_par_iter()
    //            .map(|omega| DensePolynomial {
    //                coeffs: vec![-omega.clone(), ScalarField::one()],
    //            })
    //            .reduce_with(|mut l, r| &l * &r)
    //            .unwrap()
    //    })
    //    .collect();

    // do it faster
    let all_omegas: Vec<ScalarField> = (0..domain.d2.size())
        .into_par_iter()
        .map(|i| domain.d2.group_gen.pow([i as u64]))
        .collect();

    // divisors with cosets
    // div_i(X) = X^per_node_size - w^{i*per_node_size}
    // div_i(X) is supposed to be zero on all elements from coset i
    let all_divisors: Vec<DensePolynomial<ScalarField>> = (0..proofs_number)
        .into_par_iter()
        .map(|node_ix| {
            let mut res = DensePolynomial {
                coeffs: vec![ScalarField::zero(); per_node_size + 1],
            };
            res[0] = -all_omegas[node_ix * per_node_size];
            res[per_node_size] = ScalarField::one();
            res
        })
        .collect();

    for i in 0..3 {
        assert!(all_divisors[i].evaluate(&all_omegas[proofs_number + i]) == ScalarField::zero());
    }

    for node_ix in 0..proofs_number {
        let start = Instant::now();

        // TEMPORARILY skip most iterations
        if node_ix > 1 {
            continue;
        }

        println!("Creating proof number {:?}", node_ix);
        let indices: Vec<usize> = (0..per_node_size)
            .map(|j| j * proofs_number + node_ix)
            .collect();

        // c such that (X^N - c) = 0 for all elements in the current coset
        let coset_divisor_coeff = all_omegas[node_ix * per_node_size].clone();

        let coeff_powers: Vec<_> = (0..proofs_number)
            .map(|i| coset_divisor_coeff.pow([i as u64]))
            .collect();

        for j in indices.iter() {
            assert!(all_divisors[node_ix].evaluate(&all_omegas[*j]) == ScalarField::zero());
        }

        println!("Quotient");

        let quotient_poly: DensePolynomial<ScalarField> = {
            println!("Numerator eval");
            // p(X) - \prod L_i(X) e_i
            let numerator_eval: Evaluations<ScalarField, R2D<ScalarField>> = {
                let mut res = combined_data_d2.clone();
                for i in indices.iter() {
                    res.evals[*i] = ScalarField::zero();
                }
                res
            };

            println!("Numerator eval interpolate");
            let numerator_eval_interpolated = numerator_eval.interpolate();

            println!("Division");
            // We compute the polynomial t(X) by dividing the constraints polynomial
            // by the vanishing polynomial, i.e. Z_H(X).
            let quotient = divide_by_sub_vanishing_poly(
                &numerator_eval_interpolated,
                per_node_size,
                &coeff_powers,
            );

            let divisor_poly = {
                let mut coeffs = vec![ScalarField::zero(); per_node_size + 1];
                coeffs[0] = -coset_divisor_coeff.clone();
                coeffs[per_node_size] = ScalarField::one();
                DensePolynomial { coeffs }
            };
            //            let (quotient, res) = DenseOrSparsePolynomial::divide_with_q_and_r(
            //                &From::from(numerator_eval_interpolated),
            //                &From::from(all_divisors[i].clone()),
            //            )
            //            .unwrap();

            //            // As the constraints must be verified on H, the rest of the division
            //            // must be equal to 0 as the constraints polynomial and Z_H(X) are both
            //            // equal on H.
            //            if !res.is_zero() {
            //                println!("res degree: {:?}", res.degree());
            //                let fail_final_q_division = || panic!("Division by poly must not fail");
            //                fail_final_q_division();
            //            }

            assert!(&quotient * &divisor_poly == numerator_eval_interpolated);

            quotient
        };

        println!("Quotient poly split");

        let (quotient_poly_1, quotient_poly_2) = {
            let mut quotient_poly_1 = quotient_poly.clone();
            let quotient_poly_2 = DensePolynomial {
                coeffs: quotient_poly_1.coeffs()[srs.size()..].to_vec(),
            };
            quotient_poly_1.coeffs.truncate(srs.size());
            (quotient_poly_1, quotient_poly_2)
        };

        println!("Quotient comm");
        // commit to the quotient polynomial $t$.
        // num_chunks = 1 because our constraint is degree 2, which makes the quotient polynomial of degree d1
        let quotient_comm: Vec<Curve> = srs.commit_non_hiding(&quotient_poly, 2).chunks;

        let mut fq_sponge = fq_sponge_common.clone(); // reset the sponge
        println!("Prover, Quotient comm: {:?}", quotient_comm);
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

        println!("evals");

        let combined_data_eval = combined_data_poly.evaluate(&evaluation_point);
        let quotient_eval = quotient_poly.evaluate(&evaluation_point);
        let quotient_eval_1 = quotient_poly_1.evaluate(&evaluation_point);
        let quotient_eval_2 = quotient_poly_2.evaluate(&evaluation_point);
        println!("Prover, quotient eval: {:?}", quotient_eval);
        println!("Prover, quotient eval 1: {:?}", quotient_eval_1);
        println!("Prover, quotient eval 2: {:?}", quotient_eval_2);

        assert!(
            quotient_eval
                == quotient_eval_1 + evaluation_point.pow([srs.size() as u64]) * quotient_eval_2
        );

        //// Sanity check for verification
        //if node_ix == 1 {
        //    let combined_data_at_ixs: Vec<ScalarField> = indices
        //        .iter()
        //        .map(|&i| combined_data_d2[i].clone())
        //        .collect();

        //    let quotient_eval_alt = {
        //        let divisor_poly_at_zeta: ScalarField =
        //            evaluation_point.pow([per_node_size as u64]) - coset_divisor_coeff;

        //        let mut eval = -combined_data_eval;
        //        for (lagrange, data_eval) in bases_d2.iter().zip(combined_data_at_ixs.iter()) {
        //            eval += lagrange.evaluate(&evaluation_point) * data_eval;
        //        }
        //        eval = ScalarField::zero() - eval;
        //        eval = eval * divisor_poly_at_zeta.inverse().unwrap();
        //        eval
        //    };
        //    assert!(quotient_eval_alt == quotient_eval);
        //}

        for eval in [combined_data_eval, quotient_eval_1, quotient_eval_2].into_iter() {
            fr_sponge.absorb(&eval);
        }

        let (_, endo_r) = Curve::endos();
        // Generate scalars used as combiners for sub-statements within our IPA opening proof.
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

        println!("Creating opening proof");

        let opening_proof = srs.open(
            group_map,
            opening_proof_inputs.as_slice(),
            &[evaluation_point],
            polyscale,
            evalscale,
            fq_sponge.clone(),
            rng,
        );
        println!("Opening proof created");

        proofs.push(VIDProof {
            quotient_comm,
            quotient_evals: vec![quotient_eval_1, quotient_eval_2],
            combined_data_eval,
            opening_proof,
        });

        let duration = start.elapsed();

        let millis = duration.as_millis();
        println!("Prover time elapsed: {} ms", millis);
    }

    proofs
}

pub fn verify_vid_ipa<RNG>(
    srs: &SRS<Curve>,
    domain: EvaluationDomains<ScalarField>,
    bases_d2: &[DensePolynomial<ScalarField>],
    group_map: &<Curve as CommitmentCurve>::Map,
    rng: &mut RNG,
    per_node_size: usize,
    node_ix: &usize,
    verifier_indices: &[usize],
    proof: &VIDProof,
    data_comms: &[Curve],
    data: &[Vec<ScalarField>],
) -> bool
where
    RNG: RngCore + CryptoRng,
{
    let start = Instant::now();

    let mut fq_sponge = CurveFqSponge::new(Curve::other_curve_sponge_params());
    fq_sponge.absorb_g(&data_comms);

    let recombination_point = fq_sponge.challenge();
    println!("Verifier, recombination point: {:?}", recombination_point);

    println!("combining data commitments");
    let combined_data_commitment =
        crate::utils::aggregate_commitments(recombination_point, data_comms);

    println!("Verifier, Quotient comm: {:?}", proof.quotient_comm);
    fq_sponge.absorb_g(&proof.quotient_comm);

    let evaluation_point = fq_sponge.challenge();
    println!("Verifier, evaluation point: {:?}", evaluation_point);

    let mut fr_sponge = CurveFrSponge::new(Curve::sponge_params());
    fr_sponge.absorb(&fq_sponge.clone().digest());

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

    println!("Computing alt lagrange");
    //let all_omegas: Vec<ScalarField> = (0..domain.d2.size())
    //    .into_par_iter()
    //    .map(|i| domain.d2.group_gen.pow([i as u64]))
    //    .collect();
    //let denominators: Vec<ScalarField> = {
    //    let mut res: Vec<_> = verifier_indices
    //        .iter()
    //        .map(|i| {
    //            let mut acc = ScalarField::zero();
    //            for j in 0..domain.d2.size() {
    //                if j != *i {
    //                    acc *= all_omegas[*i] - all_omegas[j]
    //                }
    //            }
    //            acc
    //        })
    //        .collect();
    //    ark_ff::batch_inversion(&mut res);
    //    res
    //};
    //let nominator_total: ScalarField = all_omegas
    //    .clone()
    //    .into_par_iter()
    //    .map(|omega_i| evaluation_point - omega_i)
    //    .reduce_with(|mut l, r| {
    //        l *= r;
    //        l
    //    })
    //    .unwrap();

    //let nominator_diffs: Vec<ScalarField> = {
    //    let mut res: Vec<_> = verifier_indices
    //        .iter()
    //        .map(|i| evaluation_point - all_omegas[*i])
    //        .collect();
    //    ark_ff::batch_inversion(&mut res);
    //    res
    //};

    //for (i, lagrange) in bases_d2.iter().enumerate() {
    //    assert!(
    //        lagrange.evaluate(&evaluation_point)
    //            == nominator_total * nominator_diffs[i] * denominators[i]
    //    );
    //}

    let coset_divisor_coeff = domain.d2.group_gen.pow([(node_ix * per_node_size) as u64]);

    println!("quotient eval");
    let quotient_eval = {
        let divisor_poly_at_zeta: ScalarField =
            evaluation_point.pow([per_node_size as u64]) - coset_divisor_coeff;

        let mut eval = -proof.combined_data_eval;
        for (i, (lagrange, data_eval)) in bases_d2.iter().zip(combined_data.iter()).enumerate() {
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

    println!("verifying IPA");
    let res = srs.verify(
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
    );

    let duration = start.elapsed();

    let millis = duration.as_millis();
    println!("Verifier time elapsed: {} ms", millis);

    res
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

        let number_of_coms = 8;
        let per_node_size = 1024;
        let proofs_number = domain.d2.size() / per_node_size;

        //let verifier_indices: Vec<usize> = generate_unique_u64(512, 1 << 17);
        //let verifier_indices: Vec<usize> = (0..(domain.d2.size() / per_node_size)).collect();
        //let verifier_indices: Vec<usize> = (0..per_node_size).map(|j| j * (i + 1)).collect();
        let verifier_ix = 1; // we're testing verifier 0
        let verifier_indices: Vec<usize> = (0..per_node_size)
            .map(|j| j * proofs_number + verifier_ix)
            .collect();

        println!("Generating bases");
        let bases_d2: Vec<DensePolynomial<ScalarField>> =
            srs.lagrange_basis_raw(domain.d2, &verifier_indices);
        println!("Generating bases DONE");

        println!("Creating data");

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

        let proofs = prove_vid_ipa(
            &srs,
            domain,
            &bases_d2,
            &group_map,
            &mut rng,
            per_node_size,
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

        for i in 0..4 {
            let res = verify_vid_ipa(
                &srs,
                domain,
                &bases_d2,
                &group_map,
                &mut rng,
                per_node_size,
                &verifier_ix,
                &verifier_indices,
                &proofs[verifier_ix],
                &data_comms,
                &expanded_data_at_ixs,
            );
            assert!(res, "proof must verify")
        }
    }

    #[test]
    fn test_vid_poly_div() {
        let mut rng = OsRng;
        let srs = poly_commitment::precomputed_srs::get_srs_test::<Vesta>();
        let domain: EvaluationDomains<ScalarField> =
            EvaluationDomains::<ScalarField>::create(srs.size()).unwrap();

        let data: Vec<ScalarField> = (0..domain.d2.size)
            .map(|_| ScalarField::rand(&mut rng))
            .collect();

        let data_eval: Evaluations<ScalarField, R2D<ScalarField>> =
            Evaluations::from_vec_and_domain(data, domain.d2);

        let verifier_ix = 1;
        //let per_node_size = domain.d1.size();
        //let per_node_size = domain.d1.size() / 2;
        let per_node_size = 1024;
        let proofs_number = domain.d2.size() / per_node_size;

        let indices: Vec<usize> = (0..per_node_size)
            .map(|j| j * proofs_number + verifier_ix)
            .collect();

        let numerator_eval: Evaluations<ScalarField, R2D<ScalarField>> = {
            let mut res = data_eval.clone();
            for i in indices {
                res.evals[i] = ScalarField::zero();
            }
            res
        };

        let coset_omega = domain
            .d2
            .group_gen
            .pow([(verifier_ix * per_node_size) as u64]);

        // X^per_node_size - w^verifier_ix
        let divisor = {
            let mut res = DensePolynomial {
                coeffs: vec![ScalarField::zero(); per_node_size + 1],
            };
            res[0] = -coset_omega;
            //res[0] = -ScalarField::one();
            res[per_node_size] = ScalarField::one();
            res
        };

        println!("Numerator eval interpolate");
        let numerator_eval_interpolated = numerator_eval.interpolate();

        // sanity checking numerator_eval
        if numerator_eval_interpolated.len() >= 2 * per_node_size
            && numerator_eval_interpolated.len() < 3 * per_node_size
        {
            let numerator_1 = DensePolynomial {
                coeffs: numerator_eval_interpolated[..per_node_size].to_vec(),
            };
            let numerator_2 = DensePolynomial {
                coeffs: numerator_eval_interpolated[per_node_size..2 * per_node_size].to_vec(),
            };
            let numerator_3 = DensePolynomial {
                coeffs: numerator_eval_interpolated[2 * per_node_size..].to_vec(),
            };

            for zero_point in (0..per_node_size)
                .map(|i| domain.d2.group_gen.pow([i as u64]) * coset_omega)
                .take(15)
            {
                assert!(
                    numerator_1.evaluate(&zero_point)
                        + coset_omega * numerator_2.evaluate(&zero_point)
                        + coset_omega * coset_omega * numerator_3.evaluate(&zero_point)
                        == ScalarField::zero()
                );
            }
        }

        let coeff_powers: Vec<_> = (0..proofs_number)
            .map(|i| coset_omega.pow([i as u64]))
            .collect();

        println!("Division");
        let quot = divide_by_sub_vanishing_poly(
            &numerator_eval_interpolated,
            per_node_size,
            &coeff_powers,
        );

        println!(
            "Degree of numerator_eval_interpolated: {:?}",
            numerator_eval_interpolated.degree()
        );
        println!("Degree of divisor: {:?}", divisor.degree());
        println!("Degree of quot: {:?}", quot.degree());

        let error = &(&quot * &divisor) - &numerator_eval_interpolated;

        println!("error degree: {:?}", error.degree());

        assert!(&quot * &divisor == numerator_eval_interpolated);
    }
}
