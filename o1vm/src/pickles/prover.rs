use ark_ec::AffineRepr;
use ark_ff::{PrimeField, Zero};
use ark_poly::{univariate::DensePolynomial, Evaluations, Polynomial, Radix2EvaluationDomain as D};
use kimchi::{
    circuits::{
        domains::EvaluationDomains,
        expr::{l0_1, BerkeleyChallenges, Constants},
    },
    curve::KimchiCurve,
    groupmap::GroupMap,
    plonk_sponge::FrSponge,
};
use mina_poseidon::{sponge::ScalarChallenge, FqSponge};
use poly_commitment::{
    commitment::{absorb_commitment, PolyComm},
    ipa::{DensePolynomialOrEvaluations, OpeningProof, SRS},
    OpenProof as _, SRS as _,
};
use rand::{CryptoRng, RngCore};
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};

use super::{
    column_env::ColumnEnvironment,
    proof::{Proof, ProofInputs, WitnessColumns},
};
use crate::E;
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
/// 2. FIXME: we compute the quotient polynomial.
/// 3. We evaluate each polynomial (columns + quotient) to two challenges ζ and ζω.
/// 4. We make a batch opening proof using the IPA PCS.
///
/// The final proof consists of the opening proof, the commitments and the
/// evaluations at ζ and ζω.
// TODO: we might need blinders when the evaluation of columns are zeroes.
pub fn prove<
    G: KimchiCurve,
    EFqSponge: FqSponge<G::BaseField, G, G::ScalarField> + Clone,
    EFrSponge: FrSponge<G::ScalarField>,
    RNG,
>(
    domain: EvaluationDomains<G::ScalarField>,
    srs: &SRS<G>,
    inputs: ProofInputs<G>,
    constraints: &[E<G::ScalarField>],
    rng: &mut RNG,
) -> Result<Proof<G>, ProverError>
where
    <G as AffineRepr>::BaseField: PrimeField,
    RNG: RngCore + CryptoRng,
{
    let num_chunks = 1;
    let omega = domain.d1.group_gen;

    let mut fq_sponge = EFqSponge::new(G::other_curve_sponge_params());

    ////////////////////////////////////////////////////////////////////////////
    // Round 1: Creating and absorbing column commitments
    ////////////////////////////////////////////////////////////////////////////

    // FIXME: add selectors
    // FIXME: evaluate on a domain higher than d1 for the quotient polynomial.
    let ProofInputs { evaluations } = inputs;
    let polys = {
        let WitnessColumns {
            scratch,
            instruction_counter,
            error,
            // FIXME
            selector: _,
        } = evaluations;
        let eval_col = |evals: Vec<G::ScalarField>| {
            Evaluations::<G::ScalarField, D<G::ScalarField>>::from_vec_and_domain(evals, domain.d1)
                .interpolate()
        };
        // Doing in parallel
        let scratch = scratch.into_par_iter().map(eval_col).collect::<Vec<_>>();
        WitnessColumns {
            scratch: scratch.try_into().unwrap(),
            instruction_counter: eval_col(instruction_counter),
            error: eval_col(error.clone()),
            // FIXME
            selector: eval_col(error),
        }
    };
    let commitments = {
        let WitnessColumns {
            scratch,
            instruction_counter,
            error,
            // FIXME
            selector: _,
        } = &polys;
        // Note: we do not blind. We might want in the near future in case we
        // have a column with only zeroes.
        let comm = |poly: &DensePolynomial<G::ScalarField>| srs.commit_non_hiding(poly, num_chunks);
        // Doing in parallel
        let scratch = scratch.par_iter().map(comm).collect::<Vec<_>>();
        WitnessColumns {
            scratch: scratch.try_into().unwrap(),
            instruction_counter: comm(instruction_counter),
            error: comm(error),
            // FIXME
            selector: comm(error),
        }
    };

    // We evaluate on a domain higher than d1 for the quotient polynomial.
    // Based on the regression test
    // `test_regression_constraints_with_selectors`, the highest degree is 6.
    // Therefore, we do evaluate on d8.
    let evaluations_d8 = {
        let WitnessColumns {
            scratch,
            instruction_counter,
            error,
            // FIXME
            selector: _,
        } = &polys;
        let eval_d8 =
            |poly: &DensePolynomial<G::ScalarField>| poly.evaluate_over_domain_by_ref(domain.d8);
        // Doing in parallel
        let scratch = scratch.into_par_iter().map(eval_d8).collect::<Vec<_>>();
        WitnessColumns {
            scratch: scratch.try_into().unwrap(),
            instruction_counter: eval_d8(instruction_counter),
            error: eval_d8(error),
            // FIXME
            selector: eval_d8(error),
        }
    };

    // Absorbing the commitments - Fiat Shamir
    // We do not parallelize as we need something deterministic.
    for comm in commitments.scratch.iter() {
        absorb_commitment(&mut fq_sponge, comm)
    }
    absorb_commitment(&mut fq_sponge, &commitments.instruction_counter);
    absorb_commitment(&mut fq_sponge, &commitments.error);

    ////////////////////////////////////////////////////////////////////////////
    // Round 2: Creating and committing to the quotient polynomial
    ////////////////////////////////////////////////////////////////////////////

    let (_, endo_r) = G::endos();

    // Constraints combiner
    let alpha: G::ScalarField = fq_sponge.challenge();

    let zk_rows = 0;
    let column_env: ColumnEnvironment<'_, G::ScalarField> = {
        // FIXME: use a proper Challenge structure
        let challenges = BerkeleyChallenges {
            alpha,
            // No permutation argument for the moment
            beta: G::ScalarField::zero(),
            gamma: G::ScalarField::zero(),
            // No lookup for the moment
            joint_combiner: G::ScalarField::zero(),
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
            domain,
        }
    };

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

    let _t_comm = srs.commit_non_hiding(&quotient_poly, 7);

    ////////////////////////////////////////////////////////////////////////////
    // Round 3: Evaluations at ζ and ζω
    ////////////////////////////////////////////////////////////////////////////

    let zeta_chal = ScalarChallenge(fq_sponge.challenge());

    let zeta = zeta_chal.to_field(endo_r);
    let zeta_omega = zeta * omega;

    // FIXME: add selectors
    let evals = |point| {
        let WitnessColumns {
            scratch,
            instruction_counter,
            error,
            // FIXME
            selector: _,
        } = &polys;
        let eval = |poly: &DensePolynomial<G::ScalarField>| poly.evaluate(point);
        let scratch = scratch.par_iter().map(eval).collect::<Vec<_>>();
        WitnessColumns {
            scratch: scratch.try_into().unwrap(),
            instruction_counter: eval(instruction_counter),
            error: eval(error),
            // FIXME
            selector: eval(error),
        }
    };
    // All evaluations at ζ
    let zeta_evaluations = evals(&zeta);
    // All evaluations at ζω
    let zeta_omega_evaluations = evals(&zeta_omega);

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
    fr_sponge.absorb(&zeta_evaluations.instruction_counter);
    fr_sponge.absorb(&zeta_omega_evaluations.instruction_counter);
    fr_sponge.absorb(&zeta_evaluations.error);
    fr_sponge.absorb(&zeta_omega_evaluations.error);
    // FIXME: add selectors

    ////////////////////////////////////////////////////////////////////////////
    // Round 4: Opening proof w/o linearization polynomial
    ////////////////////////////////////////////////////////////////////////////

    // Preparing the polynomials for the opening proof
    let mut polynomials: Vec<_> = polys.scratch.into_iter().collect();
    polynomials.push(polys.instruction_counter);
    polynomials.push(polys.error);
    // FIXME: add selectors
    let polynomials: Vec<_> = polynomials
        .iter()
        .map(|poly| {
            (
                DensePolynomialOrEvaluations::DensePolynomial(poly),
                // We do not have any blinder, therefore we set to 0.
                PolyComm::new(vec![G::ScalarField::zero()]),
            )
        })
        .collect();

    // poly scale
    let v_chal = fr_sponge.challenge();
    let v = v_chal.to_field(endo_r);
    // eval scale
    let u_chal = fr_sponge.challenge();
    let u = u_chal.to_field(endo_r);

    let group_map = G::Map::setup();

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
        opening_proof,
    })
}
