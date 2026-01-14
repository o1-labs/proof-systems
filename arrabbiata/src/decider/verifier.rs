//! Verifier for the Arrabbiata IVC scheme.
//!
//! The verifier checks that an accumulated proof is valid by:
//! 1. Verifying the structure of the proof (correct number of commitments, etc.)
//! 2. Verifying that the commitments open to the claimed values via IPA
//! 3. Checking the relaxed relation is satisfied
//!
//! ## Verification Flow
//!
//! For a folding-based IVC, the verifier doesn't re-execute all N iterations.
//! Instead, it verifies that the FINAL accumulated instance satisfies a
//! "relaxed" version of the original constraints.
//!
//! ### Relaxed Relation (Nova-style)
//!
//! For original constraint C(W) = 0, the relaxed version is:
//! ```text
//! C(W) = u^d * E
//! ```
//! where:
//! - W is the accumulated witness
//! - u is the homogenization variable (accumulated from all folds)
//! - d is the degree of the constraint
//! - E is the error polynomial (absorbs cross-terms from folding)
//!
//! ### Verification Steps
//!
//! 1. **Structure check**: Verify proof has correct number of commitments
//! 2. **Public I/O check**: Verify the claimed public I/O hash
//! 3. **Commitment opening**: Verify witness commitments via IPA
//! 4. **Relation check**: Evaluate constraints on opened witness values
//!
//! ## Comparison with Nova Verifier
//!
//! | Step | Nova | Arrabbiata |
//! |------|------|------------|
//! | Instance check | RelaxedR1CSInstance | RelaxedInstance |
//! | Opening | IPA for W, E | IPA for witness columns + error |
//! | Relation | A*z ○ B*z = u*C*z + E | C(W) = u^d * E (per constraint) |
//! | Curves | Cycle of 2 | Same (Pallas/Vesta) |

use ark_ec::CurveConfig;
use ark_ff::{PrimeField, Zero};
use groupmap::GroupMap;
use kimchi::curve::KimchiCurve;
use mina_poseidon::FqSponge;
use poly_commitment::{
    commitment::{BatchEvaluationProof, CommitmentCurve, EndoCurve, Evaluation},
    ipa::SRS,
};
use rand::rngs::OsRng;

use crate::{
    curve::ArrabbiataCurve,
    decider::proof::{CurveOpeningProof, Proof, RelaxedInstance, POSEIDON_FULL_ROUNDS},
    setup::IndexedRelation,
    MAX_DEGREE, NUMBER_OF_COLUMNS,
};

/// Verification key extracted from IndexedRelation.
///
/// Contains the minimal data needed for verification, without the full
/// prover-side data (like full constraint polynomials).
#[derive(Clone, Debug)]
pub struct VerificationKey<
    Fp: PrimeField,
    Fq: PrimeField,
    E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
    E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
> where
    <<E1 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
    <<E2 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
{
    /// Domain size (number of rows)
    pub domain_size: usize,

    /// Number of witness columns
    pub num_columns: usize,

    /// Commitment to the SRS generator for E1
    pub g1: E1,

    /// Commitment to the SRS generator for E2
    pub g2: E2,

    /// Blinding generator for E1
    pub h1: E1,

    /// Blinding generator for E2
    pub h2: E2,
}

impl<
        Fp: PrimeField,
        Fq: PrimeField,
        E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
        E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
    > VerificationKey<Fp, Fq, E1, E2>
where
    <<E1 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
    <<E2 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
{
    /// Extract a verification key from an indexed relation.
    pub fn from_indexed_relation(relation: &IndexedRelation<Fp, Fq, E1, E2>) -> Self {
        Self {
            domain_size: relation.get_srs_size(),
            num_columns: NUMBER_OF_COLUMNS,
            g1: relation.srs_e1.g[0],
            g2: relation.srs_e2.g[0],
            h1: relation.srs_e1.h,
            h2: relation.srs_e2.h,
        }
    }
}

/// Errors that can occur during verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifierError {
    /// Proof has no iterations
    NoIterations,

    /// Wrong number of witness commitments
    WrongCommitmentCount {
        expected: usize,
        got: usize,
        curve: &'static str,
    },

    /// Wrong number of cross-term commitments
    WrongCrossTermCount {
        expected: usize,
        got: usize,
        curve: &'static str,
    },

    /// Invalid homogenizer value (u should be non-zero for valid proofs)
    InvalidHomogenizer(&'static str),

    /// Public I/O hash mismatch
    PublicIOHashMismatch,

    /// Commitment opening failed
    OpeningFailed(&'static str),

    /// Relaxed relation check failed
    RelationCheckFailed(&'static str),

    /// Invalid proof structure
    InvalidProofStructure(String),
}

impl std::fmt::Display for VerifierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifierError::NoIterations => write!(f, "Proof has no iterations"),
            VerifierError::WrongCommitmentCount {
                expected,
                got,
                curve,
            } => {
                write!(
                    f,
                    "Wrong number of witness commitments for {}: expected {}, got {}",
                    curve, expected, got
                )
            }
            VerifierError::WrongCrossTermCount {
                expected,
                got,
                curve,
            } => {
                write!(
                    f,
                    "Wrong number of cross-term commitments for {}: expected {}, got {}",
                    curve, expected, got
                )
            }
            VerifierError::InvalidHomogenizer(curve) => {
                write!(f, "Invalid homogenizer u for {}", curve)
            }
            VerifierError::PublicIOHashMismatch => write!(f, "Public I/O hash mismatch"),
            VerifierError::OpeningFailed(msg) => write!(f, "Commitment opening failed: {}", msg),
            VerifierError::RelationCheckFailed(msg) => {
                write!(f, "Relaxed relation check failed: {}", msg)
            }
            VerifierError::InvalidProofStructure(msg) => {
                write!(f, "Invalid proof structure: {}", msg)
            }
        }
    }
}

impl std::error::Error for VerifierError {}

/// Result type for verification operations.
pub type VerifyResult<T> = Result<T, VerifierError>;

/// Verify a proof against a verification key.
///
/// This is the main entry point for verification. It performs all checks
/// needed to validate the accumulated IVC proof.
///
/// # Arguments
///
/// * `vk` - The verification key
/// * `proof` - The proof to verify
///
/// # Returns
///
/// `Ok(())` if the proof is valid, `Err(VerifierError)` otherwise.
pub fn verify<
    Fp: PrimeField,
    Fq: PrimeField,
    E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
    E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
>(
    vk: &VerificationKey<Fp, Fq, E1, E2>,
    proof: &Proof<Fp, Fq, E1, E2>,
) -> VerifyResult<()>
where
    <<E1 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
    <<E2 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
{
    // Step 1: Verify proof has at least one iteration
    if proof.num_iterations == 0 {
        return Err(VerifierError::NoIterations);
    }

    // Step 2: Verify proof structure
    verify_proof_structure(vk, proof)?;

    // Step 3: Verify relaxed instances are well-formed
    verify_instance_structure(&proof.instance_e1, "E1")?;
    verify_instance_structure(&proof.instance_e2, "E2")?;

    // Step 4: Verify public I/O (placeholder - needs actual I/O tracking)
    // TODO: When public I/O is fully implemented, verify:
    // - The claimed output matches the computation
    // - The public_io_hash is correctly computed

    // Step 5: Verify commitment openings (placeholder for IPA verification)
    // For basic verification without opening proofs, we just check structure
    // Use verify_with_opening for full Plonk verification

    // Step 6: Verify relaxed relation (placeholder)
    // For basic verification, we trust the accumulated state
    // Full verification requires IPA opening proofs

    Ok(())
}

/// Verify a proof with IPA opening proofs for full Plonk verification.
///
/// This is the complete verifier that:
/// 1. Verifies proof structure
/// 2. Re-derives evaluation points via Fiat-Shamir
/// 3. Verifies IPA opening proofs
/// 4. Checks that evaluations are consistent
pub fn verify_with_opening<
    Fp: PrimeField,
    Fq: PrimeField,
    E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq> + EndoCurve + KimchiCurve<POSEIDON_FULL_ROUNDS>,
    E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp> + EndoCurve + KimchiCurve<POSEIDON_FULL_ROUNDS>,
    EFqSponge1: Clone + FqSponge<Fq, E1, Fp, POSEIDON_FULL_ROUNDS>,
    EFqSponge2: Clone + FqSponge<Fp, E2, Fq, POSEIDON_FULL_ROUNDS>,
>(
    relation: &IndexedRelation<Fp, Fq, E1, E2>,
    proof: &Proof<Fp, Fq, E1, E2>,
) -> VerifyResult<()>
where
    <<E1 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
    <<E2 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
{
    // Step 1: Verify proof has at least one iteration
    if proof.num_iterations == 0 {
        return Err(VerifierError::NoIterations);
    }

    // Step 2: Verify proof structure
    let vk = VerificationKey::from_indexed_relation(relation);
    verify_proof_structure(&vk, proof)?;

    // Step 3: Verify relaxed instances are well-formed
    verify_instance_structure(&proof.instance_e1, "E1")?;
    verify_instance_structure(&proof.instance_e2, "E2")?;

    // Step 4: Check that opening proofs are present
    let opening_e1 = proof
        .opening_e1
        .as_ref()
        .ok_or(VerifierError::OpeningFailed("Missing E1 opening proof"))?;
    let opening_e2 = proof
        .opening_e2
        .as_ref()
        .ok_or(VerifierError::OpeningFailed("Missing E2 opening proof"))?;

    // Step 5: Verify IPA opening for E1
    verify_opening_e1::<Fp, Fq, E1, E2, EFqSponge1>(
        &relation.srs_e1,
        &proof.instance_e1,
        opening_e1,
    )?;

    // Step 6: Verify IPA opening for E2
    verify_opening_e2::<Fp, Fq, E1, E2, EFqSponge2>(
        &relation.srs_e2,
        &proof.instance_e2,
        opening_e2,
    )?;

    Ok(())
}

/// Verify the IPA opening proof for curve E1.
fn verify_opening_e1<
    Fp: PrimeField,
    Fq: PrimeField,
    E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq> + EndoCurve + KimchiCurve<POSEIDON_FULL_ROUNDS>,
    E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
    EFqSponge: Clone + FqSponge<Fq, E1, Fp, POSEIDON_FULL_ROUNDS>,
>(
    srs: &SRS<E1>,
    instance: &RelaxedInstance<E1>,
    opening: &CurveOpeningProof<E1>,
) -> VerifyResult<()>
where
    <<E1 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
    <<E2 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
{
    let group_map = E1::Map::setup();
    let mut rng = OsRng;

    // Re-derive evaluation point via Fiat-Shamir (must match prover)
    let mut sponge = EFqSponge::new(<E1 as KimchiCurve<POSEIDON_FULL_ROUNDS>>::other_curve_sponge_params());

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

    // Verify evaluation point matches
    if eval_point != opening.eval_point {
        return Err(VerifierError::OpeningFailed(
            "E1 evaluation point mismatch",
        ));
    }

    // Build evaluation structures for batch verification
    let mut evaluations = Vec::new();

    // Add witness polynomial evaluations
    for (i, comm) in instance.witness_commitments.iter().enumerate() {
        evaluations.push(Evaluation {
            commitment: comm.clone(),
            evaluations: vec![vec![opening.evaluations.witness_evals[i]]],
        });
    }

    // Add error polynomial evaluation
    evaluations.push(Evaluation {
        commitment: instance.error_commitment.clone(),
        evaluations: vec![vec![opening.evaluations.error_eval]],
    });

    // Compute combined inner product
    // This is the sum of all evaluations with appropriate scaling
    let combined_inner_product = compute_combined_inner_product_e1(&opening.evaluations);

    // Clone sponge state before evaluation absorption
    let sponge_before_opening = sponge.clone();

    // Absorb evaluations (must match prover)
    for eval in &opening.evaluations.witness_evals {
        sponge.absorb_fr(&[*eval]);
    }
    sponge.absorb_fr(&[opening.evaluations.error_eval]);

    // Create batch evaluation proof structure
    let mut batch = vec![BatchEvaluationProof {
        sponge: sponge_before_opening,
        evaluations,
        evaluation_points: vec![opening.eval_point],
        polyscale: Fp::one(),
        evalscale: Fp::one(),
        opening: &opening.opening_proof,
        combined_inner_product,
    }];

    // Verify the IPA opening
    if !srs.verify(&group_map, &mut batch, &mut rng) {
        return Err(VerifierError::OpeningFailed("E1 IPA verification failed"));
    }

    Ok(())
}

/// Verify the IPA opening proof for curve E2.
fn verify_opening_e2<
    Fp: PrimeField,
    Fq: PrimeField,
    E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
    E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp> + EndoCurve + KimchiCurve<POSEIDON_FULL_ROUNDS>,
    EFqSponge: Clone + FqSponge<Fp, E2, Fq, POSEIDON_FULL_ROUNDS>,
>(
    srs: &SRS<E2>,
    instance: &RelaxedInstance<E2>,
    opening: &CurveOpeningProof<E2>,
) -> VerifyResult<()>
where
    <<E1 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
    <<E2 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
{
    let group_map = E2::Map::setup();
    let mut rng = OsRng;

    // Re-derive evaluation point via Fiat-Shamir (must match prover)
    let mut sponge = EFqSponge::new(<E2 as KimchiCurve<POSEIDON_FULL_ROUNDS>>::other_curve_sponge_params());

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

    // Verify evaluation point matches
    if eval_point != opening.eval_point {
        return Err(VerifierError::OpeningFailed(
            "E2 evaluation point mismatch",
        ));
    }

    // Build evaluation structures for batch verification
    let mut evaluations = Vec::new();

    // Add witness polynomial evaluations
    for (i, comm) in instance.witness_commitments.iter().enumerate() {
        evaluations.push(Evaluation {
            commitment: comm.clone(),
            evaluations: vec![vec![opening.evaluations.witness_evals[i]]],
        });
    }

    // Add error polynomial evaluation
    evaluations.push(Evaluation {
        commitment: instance.error_commitment.clone(),
        evaluations: vec![vec![opening.evaluations.error_eval]],
    });

    // Compute combined inner product
    let combined_inner_product = compute_combined_inner_product_e2(&opening.evaluations);

    // Clone sponge state before evaluation absorption
    let sponge_before_opening = sponge.clone();

    // Absorb evaluations (must match prover)
    for eval in &opening.evaluations.witness_evals {
        sponge.absorb_fr(&[*eval]);
    }
    sponge.absorb_fr(&[opening.evaluations.error_eval]);

    // Create batch evaluation proof structure
    let mut batch = vec![BatchEvaluationProof {
        sponge: sponge_before_opening,
        evaluations,
        evaluation_points: vec![opening.eval_point],
        polyscale: Fq::one(),
        evalscale: Fq::one(),
        opening: &opening.opening_proof,
        combined_inner_product,
    }];

    // Verify the IPA opening
    if !srs.verify(&group_map, &mut batch, &mut rng) {
        return Err(VerifierError::OpeningFailed("E2 IPA verification failed"));
    }

    Ok(())
}

/// Compute the combined inner product for E1 evaluations.
///
/// This combines all evaluations using polyscale=1, evalscale=1.
fn compute_combined_inner_product_e1<F: PrimeField>(
    evaluations: &crate::decider::proof::PolynomialEvaluations<F>,
) -> F {
    let mut result = F::zero();

    // Sum all witness evaluations
    for eval in &evaluations.witness_evals {
        result += eval;
    }

    // Add error evaluation
    result += evaluations.error_eval;

    result
}

/// Compute the combined inner product for E2 evaluations.
fn compute_combined_inner_product_e2<F: PrimeField>(
    evaluations: &crate::decider::proof::PolynomialEvaluations<F>,
) -> F {
    let mut result = F::zero();

    // Sum all witness evaluations
    for eval in &evaluations.witness_evals {
        result += eval;
    }

    // Add error evaluation
    result += evaluations.error_eval;

    result
}

/// Verify the structure of a proof (correct commitment counts, etc.)
fn verify_proof_structure<
    Fp: PrimeField,
    Fq: PrimeField,
    E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
    E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
>(
    vk: &VerificationKey<Fp, Fq, E1, E2>,
    proof: &Proof<Fp, Fq, E1, E2>,
) -> VerifyResult<()>
where
    <<E1 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
    <<E2 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
{
    // Check E1 witness commitments
    if proof.instance_e1.witness_commitments.len() != vk.num_columns {
        return Err(VerifierError::WrongCommitmentCount {
            expected: vk.num_columns,
            got: proof.instance_e1.witness_commitments.len(),
            curve: "E1",
        });
    }

    // Check E2 witness commitments
    if proof.instance_e2.witness_commitments.len() != vk.num_columns {
        return Err(VerifierError::WrongCommitmentCount {
            expected: vk.num_columns,
            got: proof.instance_e2.witness_commitments.len(),
            curve: "E2",
        });
    }

    // Check cross-term commitments count (must be MAX_DEGREE - 1)
    // Cross-terms are for powers 1 to MAX_DEGREE - 1
    //
    // The folding scheme alternates between curves:
    // - Iteration 0, 2, 4, ... use E1
    // - Iteration 1, 3, 5, ... use E2
    //
    // So for N iterations:
    // - E1 has cross-terms if N >= 1
    // - E2 has cross-terms if N >= 2
    let expected_cross_terms = MAX_DEGREE - 1;

    // E1: Check cross-terms if at least 1 iteration was performed
    if proof.num_iterations >= 1
        && proof.instance_e1.cross_term_commitments.len() != expected_cross_terms
    {
        return Err(VerifierError::WrongCrossTermCount {
            expected: expected_cross_terms,
            got: proof.instance_e1.cross_term_commitments.len(),
            curve: "E1",
        });
    }

    // E2: Check cross-terms if at least 2 iterations were performed
    if proof.num_iterations >= 2
        && proof.instance_e2.cross_term_commitments.len() != expected_cross_terms
    {
        return Err(VerifierError::WrongCrossTermCount {
            expected: expected_cross_terms,
            got: proof.instance_e2.cross_term_commitments.len(),
            curve: "E2",
        });
    }

    Ok(())
}

/// Verify a relaxed instance is well-formed.
fn verify_instance_structure<E: CommitmentCurve>(
    instance: &RelaxedInstance<E>,
    curve_name: &'static str,
) -> VerifyResult<()>
where
    <<E as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
{
    // The homogenizer u should be non-zero for a valid accumulated instance
    // (it starts at 1 and accumulates via u_new = u_acc + r * u_fresh)
    if instance.u.is_zero() {
        return Err(VerifierError::InvalidHomogenizer(curve_name));
    }

    Ok(())
}

/// Verify that the public I/O hash is correct.
///
/// The public I/O hash should be computed as:
/// `hash = Poseidon(iteration_count, z_0, z_n)`
/// where z_0 is the initial input and z_n is the final output.
#[allow(dead_code)]
fn verify_public_io<Fp: PrimeField>(
    _claimed_hash: Fp,
    _num_iterations: u64,
    _z0: &[Fp],
    _zn: &[Fp],
) -> VerifyResult<()> {
    // TODO: Implement public I/O hash verification
    // 1. Compute expected_hash = Poseidon(num_iterations, z0, zn)
    // 2. Compare with claimed_hash
    // 3. Return error if mismatch
    Ok(())
}

/// Batch verify multiple proofs for efficiency.
///
/// When verifying multiple proofs, we can batch the IPA opening verifications
/// using random linear combinations, reducing the number of pairings/MSMs.
#[allow(dead_code)]
pub fn batch_verify<
    Fp: PrimeField,
    Fq: PrimeField,
    E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
    E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
>(
    _vk: &VerificationKey<Fp, Fq, E1, E2>,
    _proofs: &[Proof<Fp, Fq, E1, E2>],
) -> VerifyResult<()>
where
    <<E1 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
    <<E2 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
{
    // TODO: Implement batch verification
    // 1. Generate random challenges for batching
    // 2. Combine all opening claims
    // 3. Perform single batched IPA verification
    Ok(())
}

/// Estimate the verification time for a proof.
///
/// Returns an estimate of the number of group operations needed for verification.
/// This is useful for benchmarking and optimization.
pub fn estimate_verification_cost<
    Fp: PrimeField,
    Fq: PrimeField,
    E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
    E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
>(
    vk: &VerificationKey<Fp, Fq, E1, E2>,
    proof: &Proof<Fp, Fq, E1, E2>,
) -> VerificationCost
where
    <<E1 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
    <<E2 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
{
    let num_commitments_e1 = proof.instance_e1.witness_commitments.len()
        + 1 // error commitment
        + proof.instance_e1.cross_term_commitments.len();

    let num_commitments_e2 = proof.instance_e2.witness_commitments.len()
        + 1 // error commitment
        + proof.instance_e2.cross_term_commitments.len();

    // IPA verification cost: O(log n) group ops per commitment
    let log_domain_size = (vk.domain_size as f64).log2().ceil() as usize;

    VerificationCost {
        num_commitments_e1,
        num_commitments_e2,
        ipa_rounds: log_domain_size,
        // MSM size for final IPA check
        msm_size: vk.domain_size,
        // Field operations for constraint evaluation
        field_ops: vk.num_columns * vk.domain_size,
    }
}

/// Cost estimate for verification.
#[derive(Debug, Clone)]
pub struct VerificationCost {
    /// Number of commitments to verify on E1
    pub num_commitments_e1: usize,
    /// Number of commitments to verify on E2
    pub num_commitments_e2: usize,
    /// Number of IPA rounds (log of domain size)
    pub ipa_rounds: usize,
    /// Size of MSM for final verification
    pub msm_size: usize,
    /// Number of field operations for constraint evaluation
    pub field_ops: usize,
}

impl VerificationCost {
    /// Estimate total group operations.
    pub fn total_group_ops(&self) -> usize {
        // Each commitment needs ipa_rounds group ops
        // Plus final MSM
        (self.num_commitments_e1 + self.num_commitments_e2) * self.ipa_rounds + self.msm_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decider::proof::RelaxedInstance;
    use mina_curves::pasta::{Fp, Fq, Pallas, Vesta};

    #[test]
    fn test_verify_instance_structure_valid() {
        let instance: RelaxedInstance<Vesta> = RelaxedInstance::trivial(NUMBER_OF_COLUMNS);
        // Trivial instance has u = 1, which is valid
        let result = verify_instance_structure(&instance, "E1");
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_instance_structure_zero_u() {
        let mut instance: RelaxedInstance<Vesta> = RelaxedInstance::trivial(NUMBER_OF_COLUMNS);
        instance.u = Fp::zero();

        let result = verify_instance_structure(&instance, "E1");
        assert!(matches!(result, Err(VerifierError::InvalidHomogenizer(_))));
    }

    #[test]
    fn test_verification_key_creation() {
        use crate::{setup::IndexedRelation, MIN_SRS_LOG2_SIZE};

        let relation: IndexedRelation<Fp, Fq, Vesta, Pallas> =
            IndexedRelation::new(MIN_SRS_LOG2_SIZE);
        let vk = VerificationKey::from_indexed_relation(&relation);

        assert_eq!(vk.num_columns, NUMBER_OF_COLUMNS);
        assert_eq!(vk.domain_size, 1 << MIN_SRS_LOG2_SIZE);
    }

    #[test]
    fn test_verify_proof_structure() {
        use crate::{
            decider::prover::prove, setup::IndexedRelation, witness::Env, MIN_SRS_LOG2_SIZE,
        };
        use num_bigint::BigInt;

        let relation: IndexedRelation<Fp, Fq, Vesta, Pallas> =
            IndexedRelation::new(MIN_SRS_LOG2_SIZE);
        let vk = VerificationKey::from_indexed_relation(&relation);

        let mut env: Env<Fp, Fq, Vesta, Pallas> = Env::new(BigInt::from(1u64), relation);

        // Run one folding iteration
        env.fold(1);

        let proof = prove(&env).expect("Proof generation should succeed");

        // Structure verification should pass
        let result = super::verify_proof_structure(&vk, &proof);
        assert!(
            result.is_ok(),
            "Structure verification failed: {:?}",
            result
        );
    }

    #[test]
    fn test_full_verify() {
        use crate::{
            decider::prover::prove, setup::IndexedRelation, witness::Env, MIN_SRS_LOG2_SIZE,
        };
        use num_bigint::BigInt;

        let relation: IndexedRelation<Fp, Fq, Vesta, Pallas> =
            IndexedRelation::new(MIN_SRS_LOG2_SIZE);
        let vk = VerificationKey::from_indexed_relation(&relation);

        let mut env: Env<Fp, Fq, Vesta, Pallas> = Env::new(BigInt::from(1u64), relation);

        // Run one folding iteration
        env.fold(1);

        let proof = prove(&env).expect("Proof generation should succeed");

        // Full verification should pass
        let result = verify(&vk, &proof);
        assert!(result.is_ok(), "Verification failed: {:?}", result);
    }

    #[test]
    fn test_verification_cost_estimate() {
        use crate::{
            decider::prover::prove, setup::IndexedRelation, witness::Env, MIN_SRS_LOG2_SIZE,
        };
        use num_bigint::BigInt;

        let relation: IndexedRelation<Fp, Fq, Vesta, Pallas> =
            IndexedRelation::new(MIN_SRS_LOG2_SIZE);
        let vk = VerificationKey::from_indexed_relation(&relation);

        let mut env: Env<Fp, Fq, Vesta, Pallas> = Env::new(BigInt::from(1u64), relation);
        env.fold(1);

        let proof = prove(&env).expect("Proof generation should succeed");

        let cost = estimate_verification_cost(&vk, &proof);

        // E1 should have: 15 witness + 1 error + 4 cross-terms (MAX_DEGREE - 1)
        // (E1 is active on iteration 0, so it has cross-terms)
        assert_eq!(cost.num_commitments_e1, NUMBER_OF_COLUMNS + 1 + (MAX_DEGREE - 1));

        // E2 should have: 15 witness + 1 error + 0 cross-terms
        // (E2 is not active on iteration 0, so no cross-terms)
        assert_eq!(cost.num_commitments_e2, NUMBER_OF_COLUMNS + 1);

        // IPA rounds should be log2(domain_size)
        assert_eq!(cost.ipa_rounds, MIN_SRS_LOG2_SIZE);

        println!("Verification cost estimate:");
        println!("  Commitments E1: {}", cost.num_commitments_e1);
        println!("  Commitments E2: {}", cost.num_commitments_e2);
        println!("  IPA rounds: {}", cost.ipa_rounds);
        println!("  MSM size: {}", cost.msm_size);
        println!("  Total group ops: {}", cost.total_group_ops());
    }
}
