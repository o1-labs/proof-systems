use crate::E;
use ark_ec::AffineRepr;
use ark_ff::{PrimeField, Zero};
use ark_poly::{univariate::DensePolynomial, Evaluations, Polynomial, Radix2EvaluationDomain as D};
use kimchi::{
    circuits::domains::EvaluationDomains, curve::KimchiCurve, groupmap::GroupMap,
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

use super::proof::{Proof, ProofInputs, WitnessColumns};

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
    _constraints: &[E<G::ScalarField>],
    rng: &mut RNG,
) -> Proof<G>
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
    let _evaluations_d8 = {
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

    // FIXME: add quotient polynomial

    ////////////////////////////////////////////////////////////////////////////
    // Round 3: Evaluations at ζ and ζω
    ////////////////////////////////////////////////////////////////////////////

    let zeta_chal = ScalarChallenge(fq_sponge.challenge());
    let (_, endo_r) = G::endos();

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
                PolyComm {
                    elems: vec![G::ScalarField::zero()],
                },
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

    Proof {
        commitments,
        zeta_evaluations,
        zeta_omega_evaluations,
        opening_proof,
    }
}
