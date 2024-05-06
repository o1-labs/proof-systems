use crate::{
    column_env::ColumnEnvironment,
    expr::E,
    logup,
    logup::{prover::Env, LookupProof, LookupTableID},
    proof::{Proof, ProofCommitments, ProofEvaluations, ProofInputs},
    witness::Witness,
    MAX_SUPPORTED_DEGREE,
};
use ark_ff::{Field, One, Zero};
use ark_poly::{
    univariate::DensePolynomial, Evaluations, Polynomial, Radix2EvaluationDomain as R2D,
};
use kimchi::{
    circuits::{
        domains::EvaluationDomains,
        expr::{l0_1, Challenges, Constants, Expr},
    },
    curve::KimchiCurve,
    groupmap::GroupMap,
    plonk_sponge::FrSponge,
    proof::PointEvaluations,
};
use mina_poseidon::{sponge::ScalarChallenge, FqSponge};
use o1_utils::ExtendedDensePolynomial;
use poly_commitment::{
    commitment::{absorb_commitment, PolyComm},
    evaluation_proof::DensePolynomialOrEvaluations,
    OpenProof, SRS,
};
use rand::{CryptoRng, RngCore};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use thiserror::Error;

/// Errors that can arise when creating a proof
#[derive(Error, Debug, Clone)]
pub enum ProverError {
    #[error("the proof could not be constructed: {0}")]
    Generic(&'static str),

    #[error("the provided (witness) constraints was not satisfied: {0}")]
    ConstraintNotSatisfied(String),

    #[error("the provided (witness) constraint has degree {0} > allowed {1}; expr: {2}")]
    ConstraintDegreeTooHigh(u64, u64, String),
}

#[allow(unreachable_code)]
pub fn prove<
    G: KimchiCurve,
    OpeningProof: OpenProof<G>,
    EFqSponge: Clone + FqSponge<G::BaseField, G, G::ScalarField>,
    EFrSponge: FrSponge<G::ScalarField>,
    RNG,
    const N: usize,
    const N_REL: usize,
    const N_SEL: usize,
    ID: LookupTableID,
>(
    domain: EvaluationDomains<G::ScalarField>,
    srs: &OpeningProof::SRS,
    constraints: &Vec<E<G::ScalarField>>,
    inputs: ProofInputs<N, G::ScalarField, ID>,
    rng: &mut RNG,
) -> Result<Proof<N, N_REL, N_SEL, G, OpeningProof, ID>, ProverError>
where
    OpeningProof::SRS: Sync,
    RNG: RngCore + CryptoRng,
{
    ////////////////////////////////////////////////////////////////////////////
    // Setting up the protocol
    ////////////////////////////////////////////////////////////////////////////

    let group_map = G::Map::setup();

    ////////////////////////////////////////////////////////////////////////////
    // Round 1: Creating and absorbing column commitments
    ////////////////////////////////////////////////////////////////////////////

    let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());

    // Interpolate all columns on d1, using trait Into.
    let witness_evals: Witness<N, Evaluations<G::ScalarField, R2D<G::ScalarField>>> = inputs
        .evaluations
        .into_par_iter()
        .map(|evals| {
            Evaluations::<G::ScalarField, R2D<G::ScalarField>>::from_vec_and_domain(
                evals, domain.d1,
            )
        })
        .collect::<Witness<N, Evaluations<G::ScalarField, R2D<G::ScalarField>>>>();

    let witness_polys: Witness<N, DensePolynomial<G::ScalarField>> = {
        let interpolate =
            |evals: Evaluations<G::ScalarField, R2D<G::ScalarField>>| evals.interpolate();
        witness_evals
            .into_par_iter()
            .map(interpolate)
            .collect::<Witness<N, DensePolynomial<G::ScalarField>>>()
    };

    let witness_comms: Witness<N, PolyComm<G>> = {
        let comm = {
            |poly: &DensePolynomial<G::ScalarField>| {
                let mut comm = srs.commit_non_hiding(poly, 1);
                // In case the column polynomial is all zeroes, we want to mask the commitment
                comm = srs
                    .mask_custom(comm.clone(), &comm.map(|_| G::ScalarField::one()))
                    .unwrap()
                    .commitment;
                comm
            }
        };
        (&witness_polys)
            .into_par_iter()
            .map(comm)
            .collect::<Witness<N, PolyComm<G>>>()
    };

    // Do not use parallelism
    (&witness_comms)
        .into_iter()
        .for_each(|comm| absorb_commitment(&mut fq_sponge, comm));

    // -- Start Logup
    let lookup_env = if !inputs.logups.is_empty() {
        Some(Env::create::<OpeningProof, EFqSponge>(
            inputs.logups,
            domain,
            &mut fq_sponge,
            srs,
        ))
    } else {
        None
    };

    let max_degree = {
        if lookup_env.is_none() {
            constraints
                .iter()
                .map(|expr| expr.degree(1, 0))
                .max()
                .unwrap_or(0)
        } else {
            8
        }
    };

    // Don't need to be absorbed. Already absorbed in logup::prover::Env::create
    // FIXME: remove clone
    let logup_comms = Option::map(lookup_env.as_ref(), |lookup_env| LookupProof {
        m: lookup_env.lookup_counters_comm_d1.clone(),
        h: lookup_env.lookup_terms_comms_d1.clone(),
        sum: lookup_env.lookup_aggregation_comm_d1.clone(),
        fixed_tables: lookup_env.fixed_lookup_tables_comms_d1.clone(),
    });

    // -- end computing the running sum in lookup_aggregation
    // -- End of Logup

    let witness_evals: Witness<N, Evaluations<G::ScalarField, R2D<G::ScalarField>>> = {
        let domain_eval = if max_degree <= 4 {
            domain.d4
        } else if max_degree as usize <= MAX_SUPPORTED_DEGREE {
            domain.d8
        } else {
            panic!("We do support constraints up to {:?}", MAX_SUPPORTED_DEGREE)
        };
        (&witness_polys)
            .into_par_iter()
            .map(|evals| evals.evaluate_over_domain_by_ref(domain_eval))
            .collect::<Witness<N, Evaluations<G::ScalarField, R2D<G::ScalarField>>>>()
    };

    ////////////////////////////////////////////////////////////////////////////
    // Round 2: Creating and committing to the quotient polynomial
    ////////////////////////////////////////////////////////////////////////////

    let (_, endo_r) = G::endos();

    // Sample α with the Fq-Sponge.
    let alpha: G::ScalarField = fq_sponge.challenge();

    let zk_rows = 0;
    let column_env: ColumnEnvironment<'_, N, N_REL, N_SEL, _, _> = {
        let challenges = Challenges {
            alpha,
            // NB: as there is on permutation argument, we do use the beta
            // field instead of a new one for the evaluation point.
            beta: Option::map(lookup_env.as_ref(), |x| x.beta).unwrap_or(G::ScalarField::zero()),
            gamma: G::ScalarField::zero(),
            joint_combiner: Option::map(lookup_env.as_ref(), |x| x.joint_combiner),
        };
        ColumnEnvironment {
            constants: Constants {
                endo_coefficient: *endo_r,
                mds: &G::sponge_params().mds,
                zk_rows,
            },
            challenges,
            witness: &witness_evals,
            l0_1: l0_1(domain.d1),
            lookup: Option::map(lookup_env.as_ref(), |lookup_env| {
                logup::prover::QuotientPolynomialEnvironment {
                    lookup_terms_evals_d8: &lookup_env.lookup_terms_evals_d8,
                    lookup_aggregation_evals_d8: &lookup_env.lookup_aggregation_evals_d8,
                    lookup_counters_evals_d8: &lookup_env.lookup_counters_evals_d8,
                    fixed_tables_evals_d8: &lookup_env.fixed_lookup_tables_evals_d8,
                }
            }),
            domain,
        }
    };

    let quotient_poly: DensePolynomial<G::ScalarField> = {
        // Only for debugging purposes
        for expr in constraints.iter() {
            let fail_q_division =
                ProverError::ConstraintNotSatisfied(format!("Unsatisfied expression: {:}", expr));
            // Check this expression are witness satisfied
            let (_, res) = expr
                .evaluations(&column_env)
                .interpolate_by_ref()
                .divide_by_vanishing_poly(domain.d1)
                .ok_or(fail_q_division.clone())?;
            if !res.is_zero() {
                return Err(fail_q_division);
            }
        }

        // Compute ∑ α^i constraint_i as an expression
        let combined_expr =
            Expr::combine_constraints(0..(constraints.len() as u32), constraints.clone());

        // We want to compute the quotient polynomial, i.e.
        // t(X) = (∑ α^i constraint_i(X)) / Z_H(X).
        // The sum of the expressions is called the "constraint polynomial".
        // We will use the evaluations points of the individual witness and
        // lookup columns.
        // Note that as the constraints might be of higher degree than N, the
        // size of the set H we want the constraints to be verified on, we must
        // have more than N evaluations points for each columns. This is handled
        // in the ColumnEnvironment structure.
        // Reminder: to compute P(X) = P_{1}(X) * P_{2}(X), from the evaluations
        // of P_{1} and P_{2}, with deg(P_{1}) = deg(P_{2}(X)) = N, we must have
        // 2N evaluation points to compute P as deg(P(X)) <= 2N.
        let expr_evaluation: Evaluations<G::ScalarField, R2D<G::ScalarField>> =
            combined_expr.evaluations(&column_env);

        // And we interpolate using the evaluations
        let expr_evaluation_interpolated = expr_evaluation.interpolate();

        let fail_final_q_division = || {
            panic!("Division by vanishing poly must not fail at this point, we checked it before")
        };
        // We compute the polynomial t(X) by dividing the constraints polynomial
        // by the vanishing polynomial, i.e. Z_H(X).
        let (quotient, res) = expr_evaluation_interpolated
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

    let num_chunks: usize = if max_degree == 1 {
        1
    } else {
        (max_degree - 1) as usize
    };

    //~ 1. commit to the quotient polynomial $t$.
    let t_comm = srs.commit_non_hiding(&quotient_poly, num_chunks);

    ////////////////////////////////////////////////////////////////////////////
    // Round 3: Evaluations at zeta and zeta_omega
    ////////////////////////////////////////////////////////////////////////////

    //~ 1. Absorb the commitment of the quotient polynomial with the Fq-Sponge.
    absorb_commitment(&mut fq_sponge, &t_comm);

    //~ 1. Sample $\zeta'$ with the Fq-Sponge.
    let zeta_chal = ScalarChallenge(fq_sponge.challenge());

    //~ 1. Derive $\zeta$ from $\zeta'$ using the endomorphism (TODO: specify)
    let zeta = zeta_chal.to_field(endo_r);

    let omega = domain.d1.group_gen;
    // We will also evaluate at ζω as lookups do require to go to the next row.
    let zeta_omega = zeta * omega;

    // Evaluate the polynomials at ζ and ζω -- Columns
    let witness_evals: Witness<N, PointEvaluations<_>> = {
        let eval = |p: &DensePolynomial<_>| PointEvaluations {
            zeta: p.evaluate(&zeta),
            zeta_omega: p.evaluate(&zeta_omega),
        };
        (&witness_polys)
            .into_par_iter()
            .map(eval)
            .collect::<Witness<N, PointEvaluations<_>>>()
    };

    // IMPROVEME: move this into the logup module
    let logup_evals = lookup_env.as_ref().map(|lookup_env| LookupProof {
        m: lookup_env
            .lookup_counters_poly_d1
            .iter()
            .map(|(id, poly)| {
                let zeta = poly.evaluate(&zeta);
                let zeta_omega = poly.evaluate(&zeta_omega);
                (*id, PointEvaluations { zeta, zeta_omega })
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

    ////////////////////////////////////////////////////////////////////////////
    // Round 4: Opening proof w/o linearization polynomial
    ////////////////////////////////////////////////////////////////////////////

    // Fiat Shamir - absorbing evaluations
    let fq_sponge_before_evaluations = fq_sponge.clone();
    let mut fr_sponge = EFrSponge::new(G::sponge_params());
    fr_sponge.absorb(&fq_sponge.digest());

    for PointEvaluations { zeta, zeta_omega } in (&witness_evals).into_iter() {
        fr_sponge.absorb(zeta);
        fr_sponge.absorb(zeta_omega);
    }

    if lookup_env.is_some() {
        for PointEvaluations { zeta, zeta_omega } in logup_evals.as_ref().unwrap().into_iter() {
            fr_sponge.absorb(zeta);
            fr_sponge.absorb(zeta_omega);
        }
    }

    // Compute ft(X) = \
    //   (1 - ζ^n) \
    //    (t_0(X) + ζ^n t_1(X) + ... + ζ^{kn} t_{k}(X))
    // where \sum_i t_i(X) X^{i n} = t(X), and t(X) is the quotient polynomial.
    // At the end, we get the (partial) evaluation of the constraint polynomial
    // in ζ.
    let ft: DensePolynomial<G::ScalarField> = {
        let evaluation_point_to_domain_size = zeta.pow([domain.d1.size]);
        // Compute \sum_i t_i(X) ζ^{i n}
        // First we split t in t_i, and we reduce to degree (n - 1) after using `linearize`
        let t_chunked: DensePolynomial<G::ScalarField> = quotient_poly
            .to_chunked_polynomial(num_chunks, domain.d1.size as usize)
            .linearize(evaluation_point_to_domain_size);
        // Multiply the polynomial \sum_i t_i(X) ζ^{i n} by Z_H(ζ)
        // (the evaluation in ζ of the vanishing polynomial)
        t_chunked.scale(G::ScalarField::one() - evaluation_point_to_domain_size)
    };

    // We only evaluate at ζω as the verifier can compute the
    // evaluation at ζ from the independent evaluations at ζ of the
    // witness columns because ft(X) is the constraint polynomial, built from
    // the public constraints.
    // We evaluate at ζω because the lookup argument requires to compute
    // \phi(Xω) - \phi(X).
    let ft_eval1 = ft.evaluate(&zeta_omega);

    // Absorb ft(ζω)
    fr_sponge.absorb(&ft_eval1);

    let v_chal = fr_sponge.challenge();
    let v = v_chal.to_field(endo_r);
    let u_chal = fr_sponge.challenge();
    let u = u_chal.to_field(endo_r);

    let coefficients_form = DensePolynomialOrEvaluations::DensePolynomial;
    let non_hiding = |d1_size| PolyComm {
        elems: vec![G::ScalarField::zero(); d1_size],
    };
    let hiding = |d1_size| PolyComm {
        elems: vec![G::ScalarField::one(); d1_size],
    };

    // Gathering all polynomials to use in the opening proof
    let mut polynomials: Vec<_> = (&witness_polys)
        .into_par_iter()
        .map(|poly| (coefficients_form(poly), hiding(1)))
        .collect();

    // Adding Logup
    if let Some(ref lookup_env) = lookup_env {
        // -- first m(X)
        polynomials.extend(
            lookup_env
                .lookup_counters_poly_d1
                .values()
                .map(|poly| (coefficients_form(poly), non_hiding(1)))
                .collect::<Vec<_>>(),
        );
        // -- after that the partial sums
        polynomials.extend({
            let polys = lookup_env.lookup_terms_poly_d1.values().map(|polys| {
                polys
                    .iter()
                    .map(|poly| (coefficients_form(poly), non_hiding(1)))
                    .collect::<Vec<_>>()
            });
            let polys: Vec<_> = polys.flatten().collect();
            polys
        });
        // -- after that the running sum
        polynomials.push((
            coefficients_form(&lookup_env.lookup_aggregation_poly_d1),
            non_hiding(1),
        ));
        // -- Adding fixed lookup tables
        polynomials.extend(
            lookup_env
                .fixed_lookup_tables_poly_d1
                .values()
                .map(|poly| (coefficients_form(poly), non_hiding(1)))
                .collect::<Vec<_>>(),
        );
    }
    polynomials.push((coefficients_form(&ft), non_hiding(1)));

    let opening_proof = OpenProof::open::<_, _, R2D<G::ScalarField>>(
        srs,
        &group_map,
        polynomials.as_slice(),
        &[zeta, zeta_omega],
        v,
        u,
        fq_sponge_before_evaluations,
        rng,
    );

    let proof_evals: ProofEvaluations<N, N_REL, N_SEL, G::ScalarField, ID> = {
        ProofEvaluations {
            witness_evals,
            logup_evals,
            ft_eval1,
        }
    };

    Ok(Proof {
        proof_comms: ProofCommitments {
            witness_comms,
            logup_comms,
            t_comm,
        },
        proof_evals,
        opening_proof,
    })
}
