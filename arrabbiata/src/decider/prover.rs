//! A prover for the folding/accumulation scheme.
//!
//! The prover extracts the final accumulated state from the witness environment
//! and packages it into a proof that can be verified by the decider.
//!
//! ## Proof Generation Flow
//!
//! 1. Run N iterations of the IVC (in main.rs or a custom driver)
//! 2. Call `prove(&env)` to extract the final accumulated state
//! 3. The proof contains commitments and challenges from both curves
//! 4. The verifier checks the relaxed relation on the accumulated instances
//!
//! ## Plonk Proving
//!
//! When `prove_with_opening` is called, the prover additionally:
//! 1. Derives an evaluation point via Fiat-Shamir
//! 2. Computes the quotient polynomial t(X) = (C(W,X) - u^d * E(X)) / Z_H(X)
//! 3. Evaluates all witness, error, and quotient polynomials at this point
//! 4. Creates IPA opening proofs for these evaluations

use ark_ec::CurveConfig;
use ark_ff::PrimeField;
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Polynomial, Radix2EvaluationDomain,
};
use groupmap::GroupMap;
use kimchi::curve::KimchiCurve;
use mina_poseidon::FqSponge;
use mvpoly::{monomials::Sparse, MVPoly};
use poly_commitment::{
    commitment::{CommitmentCurve, EndoCurve},
    ipa::SRS,
    utils::DensePolynomialOrEvaluations,
    PolyComm, SRS as SRSTrait,
};
use rand::rngs::OsRng;
use rayon::prelude::*;
use std::collections::HashMap;

use crate::{
    challenge::ChallengeTerm,
    column::Gadget,
    curve::ArrabbiataCurve,
    decider::proof::{
        CurveOpeningProof, PolynomialEvaluations, Proof, RelaxedInstance, POSEIDON_FULL_ROUNDS,
    },
    witness::Env,
    MAX_DEGREE, MV_POLYNOMIAL_ARITY, NUMBER_OF_COLUMNS,
};

/// Generate a proof from the accumulated state in the environment.
///
/// This extracts the final accumulated instances from both curves and
/// packages them into a proof structure.
///
/// # Arguments
///
/// * `env` - The witness environment after N folding iterations
///
/// # Returns
///
/// A proof containing the accumulated state, or an error if the environment
/// is not in a valid state for proof generation.
pub fn prove<
    Fp: PrimeField,
    Fq: PrimeField,
    E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
    E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
>(
    env: &Env<Fp, Fq, E1, E2>,
) -> Result<Proof<Fp, Fq, E1, E2>, ProverError>
where
    <<E1 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
    <<E2 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
{
    // Validate that we have at least one iteration
    if env.current_iteration == 0 {
        return Err(ProverError::NoIterations);
    }

    // Extract the accumulated instance from E1
    let instance_e1 = extract_instance_e1(env)?;

    // Extract the accumulated instance from E2
    let instance_e2 = extract_instance_e2(env)?;

    // Get the final challenges
    let r = &env.challenges[ChallengeTerm::RelationCombiner];
    let public_io_hash = Fp::from_le_bytes_mod_order(&r.to_bytes_le().1);

    // Build the proof (without opening proofs for basic verification)
    Ok(Proof {
        num_iterations: env.current_iteration,
        instance_e1,
        instance_e2,
        public_io_hash,
        output: vec![], // TODO: extract from environment when public I/O is implemented
        opening_e1: None,
        opening_e2: None,
    })
}

/// Generate a proof with IPA opening proofs for full Plonk verification.
///
/// This is the full prover that:
/// 1. Extracts accumulated instances
/// 2. Derives evaluation points via Fiat-Shamir
/// 3. Computes quotient polynomials
/// 4. Evaluates polynomials
/// 5. Creates IPA opening proofs
pub fn prove_with_opening<
    Fp: PrimeField,
    Fq: PrimeField,
    E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>
        + EndoCurve
        + KimchiCurve<POSEIDON_FULL_ROUNDS>,
    E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>
        + EndoCurve
        + KimchiCurve<POSEIDON_FULL_ROUNDS>,
    EFqSponge1: Clone + FqSponge<Fq, E1, Fp, POSEIDON_FULL_ROUNDS>,
    EFqSponge2: Clone + FqSponge<Fp, E2, Fq, POSEIDON_FULL_ROUNDS>,
>(
    env: &Env<Fp, Fq, E1, E2>,
) -> Result<Proof<Fp, Fq, E1, E2>, ProverError>
where
    <<E1 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
    <<E2 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
{
    // Start with the basic proof
    let mut proof = prove(env)?;

    let domain_size = env.indexed_relation.get_srs_size();
    let group_map_e1 = E1::Map::setup();
    let group_map_e2 = E2::Map::setup();
    let mut rng = OsRng;

    // Generate opening proof for E1
    let opening_e1 = generate_opening_proof::<Fp, E1, EFqSponge1>(
        &env.indexed_relation.srs_e1,
        domain_size,
        &proof.instance_e1,
        &env.program_e1.accumulated_program_state,
        &env.program_e1.error_term,
        &env.indexed_relation.constraints_fp,
        &env.indexed_relation.circuit_gates,
        &group_map_e1,
        &mut rng,
    )?;
    proof.opening_e1 = Some(opening_e1);

    // Generate opening proof for E2
    let opening_e2 = generate_opening_proof::<Fq, E2, EFqSponge2>(
        &env.indexed_relation.srs_e2,
        domain_size,
        &proof.instance_e2,
        &env.program_e2.accumulated_program_state,
        &env.program_e2.error_term,
        &env.indexed_relation.constraints_fq,
        &env.indexed_relation.circuit_gates,
        &group_map_e2,
        &mut rng,
    )?;
    proof.opening_e2 = Some(opening_e2);

    Ok(proof)
}

/// Generate IPA opening proof for a curve.
///
/// This is a generic function that works for both E1 and E2.
/// It computes the quotient polynomial and generates IPA opening proofs.
fn generate_opening_proof<
    F: PrimeField,
    E: CommitmentCurve<ScalarField = F> + EndoCurve + KimchiCurve<POSEIDON_FULL_ROUNDS>,
    EFqSponge: Clone + FqSponge<E::BaseField, E, F, POSEIDON_FULL_ROUNDS>,
>(
    srs: &SRS<E>,
    domain_size: usize,
    instance: &RelaxedInstance<E>,
    witness: &[Vec<F>],
    error_term: &[F],
    constraints: &HashMap<Gadget, Vec<Sparse<F, MV_POLYNOMIAL_ARITY, MAX_DEGREE>>>,
    circuit_gates: &[Gadget],
    group_map: &E::Map,
    rng: &mut OsRng,
) -> Result<CurveOpeningProof<E>, ProverError>
where
    <<E as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
    E::BaseField: PrimeField,
{
    let domain = Radix2EvaluationDomain::<F>::new(domain_size)
        .ok_or_else(|| ProverError::InvalidState("Invalid domain size".to_string()))?;

    // Create a sponge for Fiat-Shamir using kimchi's sponge params
    let mut sponge =
        EFqSponge::new(<E as KimchiCurve<POSEIDON_FULL_ROUNDS>>::other_curve_sponge_params());

    // Absorb all witness commitments
    for comm in &instance.witness_commitments {
        for chunk in &comm.chunks {
            sponge.absorb_g(&[*chunk]);
        }
    }

    // Absorb error commitment
    for chunk in &instance.error_commitment.chunks {
        sponge.absorb_g(&[*chunk]);
    }

    // Absorb instance scalars
    sponge.absorb_fr(&[instance.u]);
    sponge.absorb_fr(&[instance.alpha]);

    // Squeeze evaluation point
    let eval_point = sponge.challenge();

    // Parallel interpolation of witness polynomials using rayon
    let witness_polys: Vec<DensePolynomial<F>> = witness
        .par_iter()
        .map(|evals: &Vec<F>| {
            let evaluations = ark_poly::Evaluations::from_vec_and_domain(evals.clone(), domain);
            evaluations.interpolate()
        })
        .collect();

    // Get error polynomial
    let error_poly = {
        let evaluations =
            ark_poly::Evaluations::from_vec_and_domain(error_term.to_vec(), domain);
        evaluations.interpolate()
    };

    // Compute quotient polynomial: t(X) = (C(W,X) - u^d * E(X)) / Z_H(X)
    let (quotient_poly, quotient_commitment) = compute_quotient_polynomial(
        srs,
        domain,
        &witness_polys,
        &error_poly,
        constraints,
        circuit_gates,
        instance.u,
        instance.alpha,
    )?;

    // Absorb quotient commitment
    for chunk in &quotient_commitment.chunks {
        sponge.absorb_g(&[*chunk]);
    }

    // Re-squeeze evaluation point after quotient (if needed for security)
    // For now we use the same point for simplicity

    // Parallel evaluation of all polynomials at the evaluation point
    let witness_evals: Vec<F> = witness_polys
        .par_iter()
        .map(|p| p.evaluate(&eval_point))
        .collect();

    let error_eval = error_poly.evaluate(&eval_point);
    let quotient_eval = quotient_poly.evaluate(&eval_point);

    // Absorb evaluations for next round of Fiat-Shamir
    let sponge_before_opening = sponge.clone();
    for eval in &witness_evals {
        sponge.absorb_fr(&[*eval]);
    }
    sponge.absorb_fr(&[error_eval]);
    sponge.absorb_fr(&[quotient_eval]);

    // Prepare polynomials for opening proof (references, no cloning)
    let mut polys_to_open: Vec<(
        DensePolynomialOrEvaluations<F, Radix2EvaluationDomain<F>>,
        PolyComm<F>,
    )> = witness_polys
        .iter()
        .map(|p| {
            (
                DensePolynomialOrEvaluations::DensePolynomial(p),
                PolyComm::new(vec![F::zero()]), // Blinder (non-hiding)
            )
        })
        .collect();

    polys_to_open.push((
        DensePolynomialOrEvaluations::DensePolynomial(&error_poly),
        PolyComm::new(vec![F::zero()]),
    ));

    polys_to_open.push((
        DensePolynomialOrEvaluations::DensePolynomial(&quotient_poly),
        PolyComm::new(vec![F::zero()]),
    ));

    // Generate the IPA opening proof
    let opening_proof = srs.open(
        group_map,
        polys_to_open.as_slice(),
        &[eval_point],
        F::one(), // polyscale
        F::one(), // evalscale
        sponge_before_opening,
        rng,
    );

    Ok(CurveOpeningProof {
        eval_point,
        evaluations: PolynomialEvaluations {
            witness_evals,
            error_eval,
            quotient_eval,
        },
        quotient_commitment,
        opening_proof,
    })
}

/// Compute the quotient polynomial for the relaxed relation.
///
/// For each row, compute C(W, row) - u^d * E(row), then divide by Z_H(X).
/// If the instance satisfies the relaxed relation, this division is exact.
///
/// # Arguments
/// * `srs` - The SRS for commitments
/// * `domain` - The evaluation domain
/// * `witness_polys` - The witness polynomials (already interpolated)
/// * `error_poly` - The error polynomial
/// * `constraints` - Constraint polynomials indexed by gadget
/// * `circuit_gates` - The gadget selector for each row
/// * `u` - The homogenization variable
/// * `alpha` - The constraint combiner challenge
///
/// # Returns
/// The quotient polynomial and its commitment.
fn compute_quotient_polynomial<F: PrimeField, E: CommitmentCurve<ScalarField = F>>(
    srs: &SRS<E>,
    domain: Radix2EvaluationDomain<F>,
    witness_polys: &[DensePolynomial<F>],
    error_poly: &DensePolynomial<F>,
    constraints: &HashMap<Gadget, Vec<Sparse<F, MV_POLYNOMIAL_ARITY, MAX_DEGREE>>>,
    circuit_gates: &[Gadget],
    u: F,
    alpha: F,
) -> Result<(DensePolynomial<F>, PolyComm<E>), ProverError>
where
    <<E as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
{
    let domain_size = domain.size();

    // Compute u^MAX_DEGREE for the relaxed relation
    let mut u_pow_d = F::one();
    for _ in 0..MAX_DEGREE {
        u_pow_d *= u;
    }

    // Evaluate the combined constraint polynomial on the domain
    // For each row: C(W, row) = sum_j alpha^j * C_j(W[row], W[row+1])
    let constraint_evals: Vec<F> = (0..domain_size)
        .into_par_iter()
        .map(|row| {
            let next_row = (row + 1) % domain_size;
            let gadget = circuit_gates[row];

            // Skip NoOp - no constraints
            if gadget == Gadget::NoOp {
                return F::zero();
            }

            let gadget_constraints = match constraints.get(&gadget) {
                Some(c) => c,
                None => return F::zero(),
            };

            // Build evaluation array for this row
            // Layout: [col_0_curr, ..., col_14_curr, col_0_next, ..., col_14_next]
            let mut eval_point: [F; MV_POLYNOMIAL_ARITY] = [F::zero(); MV_POLYNOMIAL_ARITY];
            for col in 0..NUMBER_OF_COLUMNS {
                eval_point[col] = witness_polys[col].evaluate(&domain.element(row));
                eval_point[NUMBER_OF_COLUMNS + col] =
                    witness_polys[col].evaluate(&domain.element(next_row));
            }

            // Evaluate constraints and combine with alpha
            let mut combined = F::zero();
            let mut alpha_power = F::one();
            for constraint in gadget_constraints {
                // Homogenize the constraint evaluation
                let c_eval = constraint.homogeneous_eval(&eval_point, u);
                combined += alpha_power * c_eval;
                alpha_power *= alpha;
            }

            combined
        })
        .collect();

    // Get error evaluations on the domain
    let error_evals: Vec<F> = (0..domain_size)
        .into_par_iter()
        .map(|row| error_poly.evaluate(&domain.element(row)))
        .collect();

    // Compute numerator: C(W, X) - u^d * E(X)
    let numerator_evals: Vec<F> = constraint_evals
        .par_iter()
        .zip(error_evals.par_iter())
        .map(|(c_eval, e_eval)| *c_eval - u_pow_d * e_eval)
        .collect();

    // Interpolate numerator
    let numerator_poly = {
        let evaluations =
            ark_poly::Evaluations::from_vec_and_domain(numerator_evals, domain);
        evaluations.interpolate()
    };

    // Divide: t(X) = numerator(X) / Z_H(X)
    // This should be exact if the constraint is satisfied
    // divide_by_vanishing_poly returns (quotient, remainder)
    let (quotient_poly, remainder) = numerator_poly.divide_by_vanishing_poly(domain);

    // Check that the remainder is zero (constraint satisfaction)
    let remainder_is_zero = remainder.coeffs.iter().all(|c: &F| c.is_zero());
    if !remainder_is_zero {
        return Err(ProverError::InvalidState(
            "Constraint not satisfied: non-zero remainder in quotient computation".to_string(),
        ));
    }

    // Commit to the quotient polynomial (1 chunk for non-chunked commitment)
    let quotient_commitment = srs.commit_non_hiding(&quotient_poly, 1);

    Ok((quotient_poly, quotient_commitment))
}

/// Extract the accumulated instance for curve E1.
fn extract_instance_e1<
    Fp: PrimeField,
    Fq: PrimeField,
    E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
    E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
>(
    env: &Env<Fp, Fq, E1, E2>,
) -> Result<RelaxedInstance<E1>, ProverError>
where
    <<E1 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
    <<E2 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
{
    // Get accumulated commitments from the E1 program state
    let witness_commitments = env.program_e1.accumulated_committed_state.clone();

    // Validate we have the right number of commitments
    if witness_commitments.len() != NUMBER_OF_COLUMNS {
        return Err(ProverError::InvalidState(format!(
            "Expected {} witness commitments for E1, got {}",
            NUMBER_OF_COLUMNS,
            witness_commitments.len()
        )));
    }

    // Get the error commitment
    let error_commitment = env.program_e1.error_term_commitment.clone();

    // Get cross-term commitments in order (powers 1 to MAX_DEGREE - 1)
    // Cross-terms are for powers 1, 2, ..., MAX_DEGREE - 1
    let cross_term_commitments: Vec<_> = (1..MAX_DEGREE)
        .filter_map(|power| env.program_e1.cross_terms_commitments.get(&power).cloned())
        .collect();

    // Get the homogenizer
    let u = env.program_e1.homogenizer;

    // Get accumulated challenges
    let alpha = {
        let alpha_bigint =
            &env.program_e1.accumulated_challenges[ChallengeTerm::ConstraintCombiner];
        Fp::from_le_bytes_mod_order(&alpha_bigint.to_bytes_le().1)
    };

    let r = {
        let r_bigint = &env.program_e1.accumulated_challenges[ChallengeTerm::RelationCombiner];
        Fp::from_le_bytes_mod_order(&r_bigint.to_bytes_le().1)
    };

    Ok(RelaxedInstance {
        witness_commitments,
        error_commitment,
        cross_term_commitments,
        u,
        alpha,
        r,
    })
}

/// Extract the accumulated instance for curve E2.
fn extract_instance_e2<
    Fp: PrimeField,
    Fq: PrimeField,
    E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
    E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
>(
    env: &Env<Fp, Fq, E1, E2>,
) -> Result<RelaxedInstance<E2>, ProverError>
where
    <<E1 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
    <<E2 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
{
    // Get accumulated commitments from the E2 program state
    let witness_commitments = env.program_e2.accumulated_committed_state.clone();

    // Validate we have the right number of commitments
    if witness_commitments.len() != NUMBER_OF_COLUMNS {
        return Err(ProverError::InvalidState(format!(
            "Expected {} witness commitments for E2, got {}",
            NUMBER_OF_COLUMNS,
            witness_commitments.len()
        )));
    }

    // Get the error commitment
    let error_commitment = env.program_e2.error_term_commitment.clone();

    // Get cross-term commitments in order (powers 1 to MAX_DEGREE - 1)
    // Cross-terms are for powers 1, 2, ..., MAX_DEGREE - 1
    let cross_term_commitments: Vec<_> = (1..MAX_DEGREE)
        .filter_map(|power| env.program_e2.cross_terms_commitments.get(&power).cloned())
        .collect();

    // Get the homogenizer
    let u = env.program_e2.homogenizer;

    // Get accumulated challenges
    let alpha = {
        let alpha_bigint =
            &env.program_e2.accumulated_challenges[ChallengeTerm::ConstraintCombiner];
        Fq::from_le_bytes_mod_order(&alpha_bigint.to_bytes_le().1)
    };

    let r = {
        let r_bigint = &env.program_e2.accumulated_challenges[ChallengeTerm::RelationCombiner];
        Fq::from_le_bytes_mod_order(&r_bigint.to_bytes_le().1)
    };

    Ok(RelaxedInstance {
        witness_commitments,
        error_commitment,
        cross_term_commitments,
        u,
        alpha,
        r,
    })
}

/// Errors that can occur during proof generation.
#[derive(Debug, Clone)]
pub enum ProverError {
    /// No iterations have been performed
    NoIterations,
    /// The environment is in an invalid state
    InvalidState(String),
    /// Commitment error
    CommitmentError(String),
}

impl std::fmt::Display for ProverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProverError::NoIterations => write!(f, "No folding iterations have been performed"),
            ProverError::InvalidState(msg) => write!(f, "Invalid environment state: {}", msg),
            ProverError::CommitmentError(msg) => write!(f, "Commitment error: {}", msg),
        }
    }
}

impl std::error::Error for ProverError {}

#[cfg(test)]
mod tests {
    // Tests require a full environment setup which is done in integration tests
}
