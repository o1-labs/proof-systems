use std::{array, collections::BTreeMap};

use ark_ff::{One, PrimeField, Zero};
use ark_poly::{univariate::DensePolynomial, Evaluations, Polynomial, Radix2EvaluationDomain as D};
use kimchi::{
    circuits::{
        berkeley_columns::BerkeleyChallenges,
        domains::EvaluationDomains,
        expr::{l0_1, Constants},
    },
    curve::KimchiCurve,
    groupmap::GroupMap,
    plonk_sponge::FrSponge,
    proof::PointEvaluations,
};
use kimchi_msm::{
    logup::{prover::Env, LookupProof},
    LookupTableID,
};
use log::debug;
use mina_poseidon::{sponge::ScalarChallenge, FqSponge};
use o1_utils::ExtendedDensePolynomial;
use poly_commitment::{
    commitment::{absorb_commitment, PolyComm},
    ipa::{DensePolynomialOrEvaluations, OpeningProof, SRS},
    OpenProof as _, SRS as _,
};
use rand::{CryptoRng, RngCore};
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};

use super::{
    column_env::ColumnEnvironment,
    proof::{Lookup, Proof, ProofInputs, WitnessColumns},
    DEGREE_QUOTIENT_POLYNOMIAL,
};
use crate::{interpreters::mips::column::N_MIPS_SEL_COLS, E};
use thiserror::Error;

/// Errors that can arise when creating a proof
#[derive(Error, Debug, Clone)]
pub enum ProverError {
    #[error("the provided constraint has degree {0} > allowed {1}; expr: {2}")]
    ConstraintDegreeTooHigh(u64, u64, String),
}

/// Make a PlonKish proof for the given circuit. As inputs, we get the execution
/// trace consisting of evaluations of polynomials over a certain domain
/// `domain`.
///
/// The proof is made of the following steps:
/// 1. For each column, we create a commitment and absorb it in the sponge.
/// 2. We compute the quotient polynomial.
/// 3. We evaluate each polynomial (columns + quotient) to two challenges ζ and ζω.
/// 4. We make a batch opening proof using the IPA PCS.
///
/// The final proof consists of the opening proof, the commitments and the
/// evaluations at ζ and ζω.
pub fn prove<
    G: KimchiCurve,
    EFqSponge: FqSponge<G::BaseField, G, G::ScalarField> + Clone,
    EFrSponge: FrSponge<G::ScalarField>,
    RNG,
    ID: LookupTableID,
>(
    domain: EvaluationDomains<G::ScalarField>,
    srs: &SRS<G>,
    inputs: ProofInputs<G, ID>,
    constraints: &[E<G::ScalarField>],
    rng: &mut RNG,
) -> Result<Proof<G, ID>, ProverError>
where
    G::BaseField: PrimeField,
    RNG: RngCore + CryptoRng,
{
    let num_chunks = 1;
    let omega = domain.d1.group_gen;

    let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());

    ////////////////////////////////////////////////////////////////////////////
    // Round 1: Creating and absorbing column commitments
    ////////////////////////////////////////////////////////////////////////////

    debug!("Prover: interpolating all columns, including the selectors");
    let ProofInputs {
        evaluations,
        lookups,
    } = inputs;
    let polys: WitnessColumns<
        DensePolynomial<G::ScalarField>,
        [DensePolynomial<G::ScalarField>; N_MIPS_SEL_COLS],
        ID,
    > = {
        let WitnessColumns {
            scratch,
            scratch_inverse,
            instruction_counter,
            error,
            selector,
            lookup,
            lookup_agg,
        } = evaluations;

        let domain_size = domain.d1.size as usize;

        // Build the selectors
        let selector: [Vec<G::ScalarField>; N_MIPS_SEL_COLS] = array::from_fn(|i| {
            let mut s_i = Vec::with_capacity(domain_size);
            for s in &selector {
                s_i.push(if G::ScalarField::from(i as u64) == *s {
                    G::ScalarField::one()
                } else {
                    G::ScalarField::zero()
                })
            }
            s_i
        });

        let eval_col = |evals: Vec<G::ScalarField>| {
            Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(evals, domain.d1)
                .interpolate()
        };

        let eval_lookup = |lookup: Lookup<Vec<G::ScalarField>>| Lookup {
            f: lookup
                .f
                .into_par_iter()
                .map(eval_col)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            m: lookup
                .m
                .into_par_iter()
                .map(eval_col)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            t: eval_col(lookup.t),
        };

        // Doing in parallel
        let scratch = scratch.into_par_iter().map(eval_col).collect::<Vec<_>>();
        let scratch_inverse = scratch_inverse
            .into_par_iter()
            .map(|mut evals| {
                ark_ff::batch_inversion(&mut evals);
                eval_col(evals)
            })
            .collect::<Vec<_>>();
        let selector = selector.into_par_iter().map(eval_col).collect::<Vec<_>>();
        let lookup = lookup
            .clone()
            .into_par_iter()
            .map(|(id, l)| (id, eval_lookup(l)))
            .collect::<BTreeMap<ID, _>>();
        WitnessColumns {
            scratch: scratch.try_into().unwrap(),
            scratch_inverse: scratch_inverse.try_into().unwrap(),
            instruction_counter: eval_col(instruction_counter),
            error: eval_col(error.clone()),
            selector: selector.try_into().unwrap(),
            lookup,
            lookup_agg: eval_col(lookup_agg.clone()),
        }
    };

    debug!("Prover: committing to all columns, including the selectors");
    let commitments: WitnessColumns<PolyComm<G>, [PolyComm<G>; N_MIPS_SEL_COLS], ID> = {
        let WitnessColumns {
            scratch,
            scratch_inverse,
            instruction_counter,
            error,
            selector,
            lookup,
            lookup_agg,
        } = &polys;

        let comm = |poly: &DensePolynomial<G::ScalarField>| {
            srs.commit_custom(
                poly,
                num_chunks,
                &PolyComm::new(vec![G::ScalarField::one()]),
            )
            .unwrap()
            .commitment
        };
        let comm_lookup = |lookup: Lookup<DensePolynomial<G::ScalarField>>| Lookup {
            f: lookup
                .f
                .par_iter()
                .map(comm)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            m: lookup
                .m
                .par_iter()
                .map(comm)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            t: comm(&lookup.t),
        };

        // Doing in parallel
        let scratch = scratch.par_iter().map(comm).collect::<Vec<_>>();
        let scratch_inverse = scratch_inverse.par_iter().map(comm).collect::<Vec<_>>();
        let selector = selector.par_iter().map(comm).collect::<Vec<_>>();
        let lookup = lookup
            .clone()
            .into_par_iter()
            .map(|(id, l)| (id, comm_lookup(l)))
            .collect::<BTreeMap<_, _>>();
        WitnessColumns {
            scratch: scratch.try_into().unwrap(),
            scratch_inverse: scratch_inverse.try_into().unwrap(),
            instruction_counter: comm(instruction_counter),
            error: comm(error),
            selector: selector.try_into().unwrap(),
            lookup,
            lookup_agg: comm(&lookup_agg),
        }
    };

    debug!("Prover: evaluating all columns, including the selectors, on d8");
    // We evaluate on a domain higher than d1 for the quotient polynomial.
    // Based on the regression test
    // `test_regression_constraints_with_selectors`, the highest degree is 6.
    // Therefore, we do evaluate on d8.
    let evaluations_d8 = {
        let WitnessColumns {
            scratch,
            scratch_inverse,
            instruction_counter,
            error,
            selector,
            lookup,
            lookup_agg,
        } = &polys;

        let eval_d8 =
            |poly: &DensePolynomial<G::ScalarField>| poly.evaluate_over_domain_by_ref(domain.d8);

        let eval_d8_lookup = |lookup: Lookup<DensePolynomial<G::ScalarField>>| Lookup {
            f: lookup
                .f
                .par_iter()
                .map(eval_d8)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            m: lookup
                .m
                .par_iter()
                .map(eval_d8)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            t: eval_d8(&lookup.t),
        };

        // Doing in parallel
        let scratch = scratch.into_par_iter().map(eval_d8).collect::<Vec<_>>();
        let scratch_inverse = scratch_inverse
            .into_par_iter()
            .map(eval_d8)
            .collect::<Vec<_>>();
        let selector = selector.into_par_iter().map(eval_d8).collect::<Vec<_>>();
        let lookup = lookup
            .into_par_iter()
            .map(|(&id, l)| (id, eval_d8_lookup(l.clone())))
            .collect::<BTreeMap<_, _>>();
        WitnessColumns {
            scratch: scratch.try_into().unwrap(),
            scratch_inverse: scratch_inverse.try_into().unwrap(),
            instruction_counter: eval_d8(instruction_counter),
            error: eval_d8(error),
            selector: selector.try_into().unwrap(),
            lookup,
            lookup_agg: eval_d8(lookup_agg),
        }
    };

    // Absorbing the commitments - Fiat Shamir
    // We do not parallelize as we need something deterministic.
    for comm in commitments.scratch.iter() {
        absorb_commitment(&mut fq_sponge, comm)
    }
    for comm in commitments.scratch_inverse.iter() {
        absorb_commitment(&mut fq_sponge, comm)
    }
    absorb_commitment(&mut fq_sponge, &commitments.instruction_counter);
    absorb_commitment(&mut fq_sponge, &commitments.error);
    for comm in commitments.selector.iter() {
        absorb_commitment(&mut fq_sponge, comm)
    }

    let lookup_env = if !lookups.is_empty() {
        Some(Env::create::<OpeningProof<G>, EFqSponge>(
            lookups,
            domain,
            &mut fq_sponge,
            srs,
        ))
    } else {
        None
    };

    // Don't need to be absorbed. Already absorbed in logup::prover::Env::create
    // FIXME: remove clone
    let lookup_commitments = Option::map(lookup_env.as_ref(), |lookup_env| LookupProof {
        m: lookup_env.lookup_counters_comm_d1.clone(),
        h: lookup_env.lookup_terms_comms_d1.clone(),
        sum: lookup_env.lookup_aggregation_comm_d1.clone(),
        fixed_tables: lookup_env.fixed_lookup_tables_comms_d1.clone(),
    });

    ////////////////////////////////////////////////////////////////////////////
    // Round 2: Creating and committing to the quotient polynomial
    ////////////////////////////////////////////////////////////////////////////

    let (_, endo_r) = G::endos();

    // Constraints combiner
    let alpha: G::ScalarField = fq_sponge.challenge();

    let zk_rows = 0;
    let column_env: ColumnEnvironment<'_, G::ScalarField, ID> = {
        // FIXME: use a proper Challenge structure
        let challenges = BerkeleyChallenges {
            alpha,
            // TODO: No permutation argument for the moment
            beta: G::ScalarField::zero(),
            gamma: G::ScalarField::zero(),
            // TODO: No lookup for the moment
            joint_combiner: lookup_env
                .map(|le| le.joint_combiner)
                .unwrap_or(G::ScalarField::zero()),
        };
        ColumnEnvironment {
            constants: Constants {
                endo_coefficient: *endo_r,
                mds: &G::sponge_params().mds,
                zk_rows,
            },
            challenges,
            witness: &evaluations_d8,
            l0_1: l0_1(domain.d1),
            lookup: Option::map(lookup_env.as_ref(), |lookup_env| {
                kimchi_msm::logup::prover::QuotientPolynomialEnvironment {
                    lookup_terms_evals_d8: &lookup_env.lookup_terms_evals_d8,
                    lookup_aggregation_evals_d8: &lookup_env.lookup_aggregation_evals_d8,
                    lookup_counters_evals_d8: &lookup_env.lookup_counters_evals_d8,
                    fixed_tables_evals_d8: &lookup_env.fixed_lookup_tables_evals_d8,
                }
            }),
            domain,
        }
    };

    debug!("Prover: computing the quotient polynomial");
    // Hint:
    // To debug individual constraint, you can revert the following commits that implement the
    // check for individual constraints.
    // ```
    // git revert 8e87244a98d55b90d175ad389611a3c98bd16b34
    // git revert 96d42c127ef025869c91e5fed680e0e383108706
    // ```
    let quotient_poly: DensePolynomial<G::ScalarField> = {
        // Compute ∑ α^i constraint_i as an expression
        let combined_expr =
            E::combine_constraints(0..(constraints.len() as u32), (constraints).to_vec());

        // We want to compute the quotient polynomial, i.e.
        // t(X) = (∑ α^i constraint_i(X)) / Z_H(X).
        // The sum of the expressions is called the "constraint polynomial".
        // We will use the evaluations points of the individual witness
        // columns.
        // Note that as the constraints might be of higher degree than N, the
        // size of the set H we want the constraints to be verified on, we must
        // have more than N evaluations points for each columns. This is handled
        // in the ColumnEnvironment structure.
        // Reminder: to compute P(X) = P_{1}(X) * P_{2}(X), from the evaluations
        // of P_{1} and P_{2}, with deg(P_{1}) = deg(P_{2}(X)) = N, we must have
        // 2N evaluation points to compute P as deg(P(X)) <= 2N.
        let expr_evaluation: Evaluations<G::ScalarField, D<G::ScalarField>> =
            combined_expr.evaluations(&column_env);

        // And we interpolate using the evaluations
        let expr_evaluation_interpolated = expr_evaluation.interpolate();

        let fail_final_q_division = || panic!("Fail division by vanishing poly");
        let fail_remainder_not_zero =
            || panic!("The constraints are not satisifed since the remainder is not zero");
        // We compute the polynomial t(X) by dividing the constraints polynomial
        // by the vanishing polynomial, i.e. Z_H(X).
        let (quotient, rem) = expr_evaluation_interpolated
            .divide_by_vanishing_poly(domain.d1)
            .unwrap_or_else(fail_final_q_division);
        // As the constraints must be verified on H, the rest of the division
        // must be equal to 0 as the constraints polynomial and Z_H(X) are both
        // equal on H.
        if !rem.is_zero() {
            fail_remainder_not_zero();
        }

        quotient
    };

    let quotient_commitment = srs
        .commit_custom(
            &quotient_poly,
            DEGREE_QUOTIENT_POLYNOMIAL as usize,
            &PolyComm::new(vec![
                G::ScalarField::one();
                DEGREE_QUOTIENT_POLYNOMIAL as usize
            ]),
        )
        .unwrap();
    absorb_commitment(&mut fq_sponge, &quotient_commitment.commitment);

    ////////////////////////////////////////////////////////////////////////////
    // Round 3: Evaluations at ζ and ζω
    ////////////////////////////////////////////////////////////////////////////

    debug!("Prover: evaluating all columns, including the selectors, at ζ and ζω");
    let zeta_chal = ScalarChallenge(fq_sponge.challenge());

    let zeta = zeta_chal.to_field(endo_r);
    let zeta_omega = zeta * omega;

    let evals = |point| {
        let WitnessColumns {
            scratch,
            scratch_inverse,
            instruction_counter,
            error,
            selector,
            lookup,
            lookup_agg,
        } = &polys;

        let eval = |poly: &DensePolynomial<G::ScalarField>| poly.evaluate(point);

        let eval_lookup = |lookup: Lookup<DensePolynomial<G::ScalarField>>| Lookup {
            f: lookup
                .f
                .par_iter()
                .map(eval)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            m: lookup
                .m
                .par_iter()
                .map(eval)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            t: eval(&lookup.t),
        };

        let scratch = scratch.par_iter().map(eval).collect::<Vec<_>>();
        let scratch_inverse = scratch_inverse.par_iter().map(eval).collect::<Vec<_>>();
        let selector = selector.par_iter().map(eval).collect::<Vec<_>>();
        let lookup = lookup
            .clone()
            .into_par_iter()
            .map(|(id, l)| (id, eval_lookup(l)))
            .collect::<BTreeMap<_, _>>();
        WitnessColumns {
            scratch: scratch.try_into().unwrap(),
            scratch_inverse: scratch_inverse.try_into().unwrap(),
            instruction_counter: eval(instruction_counter),
            error: eval(error),
            selector: selector.try_into().unwrap(),
            lookup,
            lookup_agg: eval(&lookup_agg),
        }
    };
    // All evaluations at ζ
    let zeta_evaluations: WitnessColumns<G::ScalarField, [G::ScalarField; N_MIPS_SEL_COLS], ID> =
        evals(&zeta);

    // All evaluations at ζω
    let zeta_omega_evaluations: WitnessColumns<
        G::ScalarField,
        [G::ScalarField; N_MIPS_SEL_COLS],
        ID,
    > = evals(&zeta_omega);

    let chunked_quotient = quotient_poly
        .to_chunked_polynomial(DEGREE_QUOTIENT_POLYNOMIAL as usize, domain.d1.size as usize);
    let quotient_evaluations = PointEvaluations {
        zeta: chunked_quotient
            .polys
            .iter()
            .map(|p| p.evaluate(&zeta))
            .collect::<Vec<_>>(),
        zeta_omega: chunked_quotient
            .polys
            .iter()
            .map(|p| p.evaluate(&zeta_omega))
            .collect(),
    };

    let lookup_evaluations = lookup_env.as_ref().map(|lookup_env| LookupProof {
        m: lookup_env
            .lookup_counters_poly_d1
            .iter()
            .map(|(id, polys)| {
                (
                    *id,
                    polys
                        .iter()
                        .map(|poly| {
                            let zeta = poly.evaluate(&zeta);
                            let zeta_omega = poly.evaluate(&zeta_omega);
                            PointEvaluations { zeta, zeta_omega }
                        })
                        .collect(),
                )
            })
            .collect(),
        h: lookup_env
            .lookup_terms_poly_d1
            .iter()
            .map(|(id, polys)| {
                let polys_evals: Vec<_> = polys
                    .iter()
                    .map(|poly| PointEvaluations {
                        zeta: poly.evaluate(&zeta),
                        zeta_omega: poly.evaluate(&zeta_omega),
                    })
                    .collect();
                (*id, polys_evals)
            })
            .collect(),
        sum: PointEvaluations {
            zeta: lookup_env.lookup_aggregation_poly_d1.evaluate(&zeta),
            zeta_omega: lookup_env.lookup_aggregation_poly_d1.evaluate(&zeta_omega),
        },
        fixed_tables: {
            lookup_env
                .fixed_lookup_tables_poly_d1
                .iter()
                .map(|(id, poly)| {
                    let zeta = poly.evaluate(&zeta);
                    let zeta_omega = poly.evaluate(&zeta_omega);
                    (*id, PointEvaluations { zeta, zeta_omega })
                })
                .collect()
        },
    });

    // Absorbing evaluations with a sponge for the other field
    // We initialize the state with the previous state of the fq_sponge
    let fq_sponge_before_evaluations = fq_sponge.clone();
    let mut fr_sponge = EFrSponge::new(G::sponge_params());
    fr_sponge.absorb(&fq_sponge.digest());

    for (zeta_eval, zeta_omega_eval) in zeta_evaluations
        .scratch
        .iter()
        .zip(zeta_omega_evaluations.scratch.iter())
    {
        fr_sponge.absorb(zeta_eval);
        fr_sponge.absorb(zeta_omega_eval);
    }
    for (zeta_eval, zeta_omega_eval) in zeta_evaluations
        .scratch_inverse
        .iter()
        .zip(zeta_omega_evaluations.scratch_inverse.iter())
    {
        fr_sponge.absorb(zeta_eval);
        fr_sponge.absorb(zeta_omega_eval);
    }
    fr_sponge.absorb(&zeta_evaluations.instruction_counter);
    fr_sponge.absorb(&zeta_omega_evaluations.instruction_counter);
    fr_sponge.absorb(&zeta_evaluations.error);
    fr_sponge.absorb(&zeta_omega_evaluations.error);
    for (zeta_eval, zeta_omega_eval) in zeta_evaluations
        .selector
        .iter()
        .zip(zeta_omega_evaluations.selector.iter())
    {
        fr_sponge.absorb(zeta_eval);
        fr_sponge.absorb(zeta_omega_eval);
    }
    for (quotient_zeta_eval, quotient_zeta_omega_eval) in quotient_evaluations
        .zeta
        .iter()
        .zip(quotient_evaluations.zeta_omega.iter())
    {
        fr_sponge.absorb(quotient_zeta_eval);
        fr_sponge.absorb(quotient_zeta_omega_eval);
    }

    if lookup_env.is_some() {
        for PointEvaluations { zeta, zeta_omega } in
            lookup_evaluations.as_ref().unwrap().into_iter()
        {
            fr_sponge.absorb(zeta);
            fr_sponge.absorb(zeta_omega);
        }
    }
    ////////////////////////////////////////////////////////////////////////////
    // Round 4: Opening proof w/o linearization polynomial
    ////////////////////////////////////////////////////////////////////////////

    let mut polynomials: Vec<_> = polys.scratch.into_iter().collect();
    polynomials.extend(polys.scratch_inverse);
    polynomials.push(polys.instruction_counter);
    polynomials.push(polys.error);
    polynomials.extend(polys.selector);

    // Preparing the polynomials for the opening proof
    let mut polynomials: Vec<_> = polynomials
        .iter()
        .map(|poly| {
            (
                DensePolynomialOrEvaluations::DensePolynomial(poly),
                // We do not have any blinder, therefore we set to 1.
                PolyComm::new(vec![G::ScalarField::one()]),
            )
        })
        .collect();
    // we handle the quotient separately because the number of blinders =
    // number of chunks, which is different for just the quotient polynomial.
    polynomials.push((
        DensePolynomialOrEvaluations::DensePolynomial(&quotient_poly),
        quotient_commitment.blinders,
    ));

    if let Some(ref lookup_env) = lookup_env {
        // -- first m(X)
        polynomials.extend(
            lookup_env
                .lookup_counters_poly_d1
                .values()
                .flat_map(|polys| {
                    polys
                        .iter()
                        .map(|poly| {
                            (
                                DensePolynomialOrEvaluations::DensePolynomial(poly),
                                PolyComm::new(vec![G::ScalarField::one()]),
                            )
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>(),
        );
        // -- after that the partial sums
        polynomials.extend({
            let polys = lookup_env.lookup_terms_poly_d1.values().map(|polys| {
                polys
                    .iter()
                    .map(|poly| {
                        (
                            DensePolynomialOrEvaluations::DensePolynomial(poly),
                            PolyComm::new(vec![G::ScalarField::one()]),
                        )
                    })
                    .collect::<Vec<_>>()
            });
            let polys: Vec<_> = polys.flatten().collect();
            polys
        });
        // -- after that the running sum
        polynomials.push((
            DensePolynomialOrEvaluations::DensePolynomial(&lookup_env.lookup_aggregation_poly_d1),
            PolyComm::new(vec![G::ScalarField::one()]),
        ));
        // -- Adding fixed lookup tables
        polynomials.extend(
            lookup_env
                .fixed_lookup_tables_poly_d1
                .values()
                .map(|poly| {
                    (
                        DensePolynomialOrEvaluations::DensePolynomial(poly),
                        PolyComm::new(vec![G::ScalarField::one()]),
                    )
                })
                .collect::<Vec<_>>(),
        );
    }

    // poly scale
    let v_chal = fr_sponge.challenge();
    let v = v_chal.to_field(endo_r);
    // eval scale
    let u_chal = fr_sponge.challenge();
    let u = u_chal.to_field(endo_r);

    let group_map = G::Map::setup();

    debug!("Prover: computing the (batched) opening proof using the IPA PCS");
    // Computing the opening proof for the IPA PCS
    let opening_proof = OpeningProof::open::<_, _, D<G::ScalarField>>(
        srs,
        &group_map,
        polynomials.as_slice(),
        &[zeta, zeta_omega],
        v,
        u,
        fq_sponge_before_evaluations,
        rng,
    );

    Ok(Proof {
        commitments,
        zeta_evaluations,
        zeta_omega_evaluations,
        quotient_commitment: quotient_commitment.commitment,
        quotient_evaluations,
        lookup_commitments,
        lookup_evaluations,
        opening_proof,
    })
}
