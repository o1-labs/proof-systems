use crate::{
    column_env::MSMColumnEnvironment,
    expr::MSMExpr,
    mvlookup::{prover::Env, LookupProof, LookupTableID},
    proof::{Proof, ProofCommitments, ProofEvaluations, ProofInputs},
    witness::Witness,
};
use ark_ff::{Field, One, Zero};
use ark_poly::Evaluations;
use ark_poly::{univariate::DensePolynomial, Polynomial, Radix2EvaluationDomain as R2D};
use kimchi::circuits::domains::EvaluationDomains;
use kimchi::circuits::expr::{l0_1, Challenges, Constants, Expr};
use kimchi::plonk_sponge::FrSponge;
use kimchi::proof::PointEvaluations;
use kimchi::{curve::KimchiCurve, groupmap::GroupMap};
use mina_poseidon::sponge::ScalarChallenge;
use mina_poseidon::FqSponge;
use o1_utils::ExtendedDensePolynomial;
use poly_commitment::{
    commitment::{absorb_commitment, PolyComm},
    evaluation_proof::DensePolynomialOrEvaluations,
    OpenProof, SRS,
};
use rand::{CryptoRng, RngCore};
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;
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
    Column,
    RNG,
    const N: usize,
    ID: LookupTableID + Send + Sync + Copy,
>(
    domain: EvaluationDomains<G::ScalarField>,
    srs: &OpeningProof::SRS,
    constraints: &[MSMExpr<G::ScalarField>],
    inputs: ProofInputs<N, G, ID>,
    rng: &mut RNG,
) -> Result<Proof<N, G, OpeningProof>, ProverError>
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
        let comm = |poly: &DensePolynomial<G::ScalarField>| srs.commit_non_hiding(poly, 1);
        (&witness_polys)
            .into_par_iter()
            .map(comm)
            .collect::<Witness<N, PolyComm<G>>>()
    };

    let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());

    // Do not use parallelism
    (&witness_comms)
        .into_iter()
        .for_each(|comm| absorb_commitment(&mut fq_sponge, comm));

    // -- Start MVLookup
    let lookup_env = if !inputs.mvlookups.is_empty() {
        Some(Env::create::<OpeningProof, EFqSponge, ID>(
            inputs.mvlookups,
            domain,
            &mut fq_sponge,
            srs,
        ))
    } else {
        None
    };

    // Don't need to be absorbed. Already absorbed in mvlookup::prover::Env::create
    // FIXME: remove clone
    let mvlookup_comms = Option::map(lookup_env.as_ref(), |lookup_env| LookupProof {
        m: lookup_env.lookup_counters_comm_d1.clone(),
        h: lookup_env.lookup_terms_comms_d1.clone(),
        sum: lookup_env.lookup_aggregation_comm_d1.clone(),
    });

    // -- end computing the running sum in lookup_aggregation
    // -- End of MVLookup

    // TODO rename this
    // The evaluations should be at least the degree of our expressions. Higher?
    // Maybe we can only use d4, we don't have degree-7 gates anyway
    let witness_evals_env: Vec<Evaluations<G::ScalarField, R2D<G::ScalarField>>> = (&witness_polys)
        .into_par_iter()
        .map(|witness_poly| witness_poly.evaluate_over_domain_by_ref(domain.d4))
        .collect();

    ////////////////////////////////////////////////////////////////////////////
    // Round 2: Creating and committing to the quotient polynomial
    ////////////////////////////////////////////////////////////////////////////

    let (_, endo_r) = G::endos();

    //~ 1. Sample $\alpha'$ with the Fq-Sponge.
    let alpha_chal = ScalarChallenge(fq_sponge.challenge());

    //~ 1. Derive $\alpha$ from $\alpha'$ using the endomorphism (TODO: details)
    let alpha: G::ScalarField = alpha_chal.to_field(endo_r);

    // TODO These should be evaluations of fixed coefficient polys
    let coefficient_evals_env: Vec<Evaluations<G::ScalarField, R2D<G::ScalarField>>> = vec![];

    let zk_rows = 0;
    let column_env = {
        let challenges = Challenges {
            alpha,
            // NB: as there is on permutation argument, we do use the beta
            // field instead of a new one for the evaluation point.
            beta: Option::map(lookup_env.as_ref(), |x| x.beta).unwrap_or(G::ScalarField::zero()),
            gamma: G::ScalarField::zero(),
            joint_combiner: Option::map(lookup_env.as_ref(), |x| x.joint_combiner),
        };
        MSMColumnEnvironment {
            constants: Constants {
                endo_coefficient: *endo_r,
                mds: &G::sponge_params().mds,
                zk_rows,
            },
            challenges,
            witness: &witness_evals_env,
            coefficients: &coefficient_evals_env,
            l0_1: l0_1(domain.d1),
            lookup: None,
            domain,
        }
    };

    let quotient_poly: DensePolynomial<G::ScalarField> = {
        // TODO FIXME This is only sound if powers of alpha are not used to combine constraints internally!
        // And they are, so we need to take extra care.
        for expr in constraints.iter() {
            // otherwise we need different t_size
            let expr_degree = expr.degree(1, zk_rows);
            if expr_degree > 2 {
                return Err(ProverError::ConstraintDegreeTooHigh(
                    expr_degree,
                    2,
                    format!("{:?}", expr),
                ));
            }

            let fail_q_division =
                ProverError::ConstraintNotSatisfied(format!("Unsatisfied expression: {:?}", expr));
            // Check this expression are witness satisfied
            let (_, res) = expr
                .evaluations(&column_env)
                .interpolate_by_ref()
                .divide_by_vanishing_poly(domain.d1)
                .ok_or(fail_q_division.clone())?;
            if !res.is_zero() {
                return Err(fail_q_division);
            }
            // TODO assert none of expressions contain alpha
        }

        let combined_expr =
            Expr::combine_constraints(0..(constraints.len() as u32), constraints.to_owned());

        // An evaluation of our expression E(vec X) on witness columns
        // Every witness column w_i(X) is evaluated first at D1, so we get E(vec w_i(X)) = 0?
        // E(w(X)) = 0 but only over H, so it's 0 evaluated at every {w^i}_{i=1}^N
        let expr_evaluation: Evaluations<G::ScalarField, R2D<G::ScalarField>> =
            combined_expr.evaluations(&column_env);

        let expr_evaluation_interpolated = expr_evaluation.interpolate();

        // divide contributions with vanishing polynomial
        let fail_final_q_division = || {
            panic!("Division by vanishing poly must not fail at this point, we checked it before")
        };
        let (quotient, res) = expr_evaluation_interpolated
            .divide_by_vanishing_poly(domain.d1)
            .unwrap_or_else(fail_final_q_division);
        if !res.is_zero() {
            fail_final_q_division();
        }

        quotient
    };

    //~ 1. commit (hiding) to the quotient polynomial $t$.
    //
    // Our constraints are at most degree d2. When divided by
    // vanishing polynomial, we obtain t(X) of degree d1.
    let expected_t_size = 1;
    // Quotient commitment
    let t_comm = {
        let num_chunks = 1;
        let mut t_comm = srs.commit_non_hiding(&quotient_poly, num_chunks);
        let dummies_n = expected_t_size - t_comm.elems.len();
        for _ in 0..dummies_n {
            t_comm.elems.push(G::zero());
        }
        t_comm
    };

    ////////////////////////////////////////////////////////////////////////////
    // Round 3: Evaluations at zeta and zeta_omega
    ////////////////////////////////////////////////////////////////////////////

    //~ 1. Absorb the the commitment of the quotient polynomial with the Fq-Sponge.
    absorb_commitment(&mut fq_sponge, &t_comm);

    //~ 1. Sample $\zeta'$ with the Fq-Sponge.
    let zeta_chal = ScalarChallenge(fq_sponge.challenge());

    //~ 1. Derive $\zeta$ from $\zeta'$ using the endomorphism (TODO: specify)
    let zeta = zeta_chal.to_field(endo_r);

    let omega = domain.d1.group_gen; // index.cs.domain.d1.group_gen;
    let zeta_omega = zeta * omega;

    // Evaluate the polynomials at zeta and zeta * omega -- Columns
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

    let mvlookup_evals = {
        if let Some(ref lookup_env) = lookup_env {
            let evals = |point| {
                let eval = |poly: &DensePolynomial<G::ScalarField>| poly.evaluate(point);
                let m = (&lookup_env.lookup_counters_poly_d1)
                    .into_par_iter()
                    .map(eval)
                    .collect::<Vec<_>>();
                let h = (&lookup_env.lookup_terms_poly_d1)
                    .into_par_iter()
                    .map(eval)
                    .collect::<Vec<_>>();
                let sum = eval(&lookup_env.lookup_aggregation_poly_d1);
                (m, h, sum)
            };
            let (m_zeta, h_zeta, sum_zeta) = evals(&zeta);
            let (m_zeta_omega, h_zeta_omega, sum_zeta_omega) = evals(&zeta_omega);
            Some(LookupProof {
                m: m_zeta
                    .into_iter()
                    .zip(m_zeta_omega)
                    .map(|(zeta, zeta_omega)| PointEvaluations { zeta, zeta_omega })
                    .collect(),
                h: h_zeta
                    .into_iter()
                    .zip(h_zeta_omega)
                    .map(|(zeta, zeta_omega)| PointEvaluations { zeta, zeta_omega })
                    .collect(),
                sum: PointEvaluations {
                    zeta: sum_zeta,
                    zeta_omega: sum_zeta_omega,
                },
            })
        } else {
            None
        }
    };

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
        for PointEvaluations { zeta, zeta_omega } in mvlookup_evals.as_ref().unwrap().into_iter() {
            fr_sponge.absorb(zeta);
            fr_sponge.absorb(zeta_omega);
        }
    }

    // TODO @volhovm I'm suspecting that due to the fact we don't use linearisation polynomial, we
    // need to evaluate t directly.
    // ft = (1 - xi^n) (t_0(X) + \xi^n t_1(X))
    let ft: DensePolynomial<G::ScalarField> = {
        let evaluation_point_to_domain_size = zeta.pow([domain.d1.size]);
        // TODO FIXME a wild guess. The second parameter should be chunk size, so srs size = domain.
        // t_chunked is t_0(X) + \xi^n t_1(X)
        // that is of degree n, but recombined.
        let t_chunked = quotient_poly
            .to_chunked_polynomial(1, domain.d1.size as usize)
            .linearize(evaluation_point_to_domain_size);
        t_chunked.scale(G::ScalarField::one() - evaluation_point_to_domain_size)
    };

    // TODO Maybe we also need to evaluate on zeta? why only zeta omega?
    let ft_eval1 = ft.evaluate(&zeta_omega);

    // Absorb ft/t
    fr_sponge.absorb(&ft_eval1);

    let v_chal = fr_sponge.challenge();
    let v = v_chal.to_field(endo_r);
    let u_chal = fr_sponge.challenge();
    let u = u_chal.to_field(endo_r);

    let coefficients_form = DensePolynomialOrEvaluations::DensePolynomial;
    let _evaluation_form = |e| DensePolynomialOrEvaluations::Evaluations(e, domain.d1);
    let non_hiding = |d1_size| PolyComm {
        elems: vec![G::ScalarField::zero(); d1_size],
    };

    // Gathering all polynomials to use in the opening proof
    let mut polynomials: Vec<_> = (&witness_polys)
        .into_par_iter()
        .map(|poly| (coefficients_form(poly), non_hiding(1)))
        .collect();

    // Adding MVLookup
    if let Some(ref lookup_env) = lookup_env {
        // -- first m(X)
        polynomials.extend(
            (&lookup_env.lookup_counters_poly_d1)
                .into_par_iter()
                .map(|poly| (coefficients_form(poly), non_hiding(1)))
                .collect::<Vec<_>>(),
        );
        // -- after that f_i and t
        polynomials.extend(
            (&lookup_env.lookup_terms_poly_d1)
                .into_par_iter()
                .map(|poly| (coefficients_form(poly), non_hiding(1)))
                .collect::<Vec<_>>(),
        );
        // -- after that the running sum
        polynomials.push((
            coefficients_form(&lookup_env.lookup_aggregation_poly_d1),
            non_hiding(1),
        ));
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

    let proof_evals: ProofEvaluations<N, G::ScalarField> = {
        ProofEvaluations {
            _public_evals: None,
            witness_evals,
            mvlookup_evals,
            ft_eval1,
        }
    };

    Ok(Proof {
        proof_comms: ProofCommitments {
            witness_comms,
            mvlookup_comms,
            t_comm,
        },
        proof_evals,
        opening_proof,
    })
}
