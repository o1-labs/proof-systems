//! Proof structure for the Arrabbiata IVC scheme.
//!
//! The proof contains the final accumulated state after all folding iterations,
//! along with the data needed for the decider to verify the computation.
//!
//! ## Proof Structure
//!
//! After N iterations of folding, we have:
//! - Relaxed R1CS-like instances on both curves (E1 and E2)
//! - Accumulated witnesses, challenges, and error terms
//! - Commitments to all accumulated polynomials
//!
//! The decider verifies that:
//! 1. The accumulated instances satisfy the relaxed relation
//! 2. The commitments open to the claimed values via IPA
//! 3. The public I/O hash matches the claimed computation
//!
//! ## Plonk Verification
//!
//! The proof includes:
//! - Quotient polynomial commitment (t(X) = (C(W,X) - u^d * E(X)) / Z_H(X))
//! - IPA opening proofs for all polynomials at the evaluation point

use ark_ec::CurveConfig;
use ark_ff::{One, PrimeField, Zero};
use poly_commitment::{commitment::CommitmentCurve, ipa::OpeningProof, PolyComm};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::curve::ArrabbiataCurve;

// Note: Full serialization support requires additional trait bounds.
// For now, we provide estimated_size() for proof size analysis.
// TODO: Add full serde support with proper bounds

/// The number of Poseidon full rounds (same as kimchi - 55 rounds).
pub const POSEIDON_FULL_ROUNDS: usize = mina_poseidon::pasta::FULL_ROUNDS;

/// A relaxed instance for one curve in the IVC scheme.
///
/// This corresponds to a "relaxed R1CS instance" in Nova terminology,
/// adapted for our Plonkish constraint system.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    bound = "PolyComm<E>: Serialize + DeserializeOwned, E::ScalarField: Serialize + DeserializeOwned"
)]
pub struct RelaxedInstance<E: CommitmentCurve>
where
    <<E as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
{
    /// Commitments to the witness columns
    pub witness_commitments: Vec<PolyComm<E>>,

    /// Commitment to the error polynomial
    pub error_commitment: PolyComm<E>,

    /// Commitments to the cross-term polynomials (one per power 1..MAX_DEGREE)
    pub cross_term_commitments: Vec<PolyComm<E>>,

    /// The homogenization variable u
    /// For a fresh instance u=1, for accumulated instances u = u_acc + r * u_fresh
    pub u: E::ScalarField,

    /// The accumulated constraint combiner challenge (alpha)
    pub alpha: E::ScalarField,

    /// The accumulated relation combiner challenge (r)
    pub r: E::ScalarField,
}

impl<E: CommitmentCurve> RelaxedInstance<E>
where
    <<E as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
{
    /// Create a trivial relaxed instance (initial accumulator).
    pub fn trivial(num_columns: usize) -> Self {
        Self {
            witness_commitments: (0..num_columns).map(|_| PolyComm::new(vec![])).collect(),
            error_commitment: PolyComm::new(vec![]),
            cross_term_commitments: vec![],
            u: E::ScalarField::one(),
            alpha: E::ScalarField::one(),
            r: E::ScalarField::zero(),
        }
    }
}

/// A relaxed witness for one curve in the IVC scheme.
#[derive(Clone, Debug)]
pub struct RelaxedWitness<F: PrimeField> {
    /// The witness polynomials (one vector of evaluations per column)
    pub witness: Vec<Vec<F>>,

    /// The error polynomial evaluations
    pub error: Vec<F>,
}

impl<F: PrimeField> RelaxedWitness<F> {
    /// Create a trivial relaxed witness with zeros.
    pub fn trivial(num_columns: usize, domain_size: usize) -> Self {
        Self {
            witness: vec![vec![F::zero(); domain_size]; num_columns],
            error: vec![F::zero(); domain_size],
        }
    }
}

/// Evaluations of all polynomials at the challenge point.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolynomialEvaluations<F: PrimeField> {
    /// Witness polynomial evaluations at the challenge point
    pub witness_evals: Vec<F>,

    /// Error polynomial evaluation at the challenge point
    pub error_eval: F,

    /// Quotient polynomial evaluation at the challenge point
    pub quotient_eval: F,
}

/// Opening proof data for one curve.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    bound = "PolyComm<E>: Serialize + DeserializeOwned, OpeningProof<E, POSEIDON_FULL_ROUNDS>: Serialize + DeserializeOwned, E::ScalarField: Serialize + DeserializeOwned"
)]
pub struct CurveOpeningProof<E: CommitmentCurve>
where
    <<E as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
{
    /// The evaluation point (derived via Fiat-Shamir)
    pub eval_point: E::ScalarField,

    /// Polynomial evaluations at the evaluation point
    pub evaluations: PolynomialEvaluations<E::ScalarField>,

    /// Commitment to the quotient polynomial
    pub quotient_commitment: PolyComm<E>,

    /// The IPA opening proof
    pub opening_proof: OpeningProof<E, POSEIDON_FULL_ROUNDS>,
}

/// The complete IVC proof containing the final accumulated state.
///
/// This proof can be:
/// 1. Verified directly by checking the relaxed relation satisfiability
/// 2. Used with IPA opening proofs for succinct verification
#[derive(Clone, Debug)]
pub struct Proof<
    Fp: PrimeField,
    Fq: PrimeField,
    E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
    E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
> where
    <<E1 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
    <<E2 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
{
    /// The number of folding iterations
    pub num_iterations: u64,

    /// Final accumulated instance on curve E1
    pub instance_e1: RelaxedInstance<E1>,

    /// Final accumulated instance on curve E2
    pub instance_e2: RelaxedInstance<E2>,

    /// The final public I/O hash
    pub public_io_hash: Fp,

    /// The final output of the computation (z_n)
    pub output: Vec<Fp>,

    /// Opening proof for E1 (optional for basic verification, required for full Plonk)
    pub opening_e1: Option<CurveOpeningProof<E1>>,

    /// Opening proof for E2 (optional for basic verification, required for full Plonk)
    pub opening_e2: Option<CurveOpeningProof<E2>>,
}

impl<
        Fp: PrimeField,
        Fq: PrimeField,
        E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
        E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
    > Proof<Fp, Fq, E1, E2>
where
    <<E1 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
    <<E2 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
{
    /// Check if this proof includes Plonk opening proofs.
    pub fn has_opening_proofs(&self) -> bool {
        self.opening_e1.is_some() && self.opening_e2.is_some()
    }

    /// Estimate the size of this proof in bytes.
    ///
    /// This is useful for benchmarking and understanding proof overhead.
    pub fn estimated_size(&self) -> usize {
        use std::mem::size_of;

        let mut size = 0;

        // num_iterations
        size += size_of::<u64>();

        // instance_e1
        size += self.instance_e1.witness_commitments.len() * size_of::<E1>(); // Approximate
        size += size_of::<E1>(); // error_commitment
        size += self.instance_e1.cross_term_commitments.len() * size_of::<E1>();
        size += size_of::<Fp>() * 3; // u, alpha, r

        // instance_e2
        size += self.instance_e2.witness_commitments.len() * size_of::<E2>();
        size += size_of::<E2>();
        size += self.instance_e2.cross_term_commitments.len() * size_of::<E2>();
        size += size_of::<Fq>() * 3;

        // public_io_hash and output
        size += size_of::<Fp>();
        size += self.output.len() * size_of::<Fp>();

        // Opening proofs (if present)
        if let Some(ref opening) = self.opening_e1 {
            size += size_of::<Fp>(); // eval_point
            size += opening.evaluations.witness_evals.len() * size_of::<Fp>(); // witness_evals
            size += size_of::<Fp>(); // error_eval
            size += size_of::<Fp>(); // quotient_eval
            size += size_of::<E1>(); // quotient_commitment
                                     // IPA proof: lr pairs + delta + z1 + z2 + sg
            size += opening.opening_proof.lr.len() * 2 * size_of::<E1>();
            size += size_of::<E1>() * 2 + size_of::<Fp>() * 2;
        }

        if let Some(ref opening) = self.opening_e2 {
            size += size_of::<Fq>();
            size += opening.evaluations.witness_evals.len() * size_of::<Fq>();
            size += size_of::<Fq>();
            size += size_of::<Fq>(); // quotient_eval
            size += size_of::<E2>(); // quotient_commitment
            size += opening.opening_proof.lr.len() * 2 * size_of::<E2>();
            size += size_of::<E2>() * 2 + size_of::<Fq>() * 2;
        }

        size
    }

    /// Get a detailed size breakdown of the proof.
    pub fn size_breakdown(&self) -> ProofSizeBreakdown {
        use std::mem::size_of;

        let instance_e1_size = {
            let mut s = 0;
            s += self.instance_e1.witness_commitments.len() * size_of::<E1>();
            s += size_of::<E1>(); // error_commitment
            s += self.instance_e1.cross_term_commitments.len() * size_of::<E1>();
            s += size_of::<Fp>() * 3; // u, alpha, r
            s
        };

        let instance_e2_size = {
            let mut s = 0;
            s += self.instance_e2.witness_commitments.len() * size_of::<E2>();
            s += size_of::<E2>();
            s += self.instance_e2.cross_term_commitments.len() * size_of::<E2>();
            s += size_of::<Fq>() * 3;
            s
        };

        let opening_e1_size = self.opening_e1.as_ref().map(|opening| {
            let mut s = 0;
            s += size_of::<Fp>(); // eval_point
            s += opening.evaluations.witness_evals.len() * size_of::<Fp>();
            s += size_of::<Fp>() * 2; // error_eval, quotient_eval
            s += size_of::<E1>(); // quotient_commitment
            s += opening.opening_proof.lr.len() * 2 * size_of::<E1>();
            s += size_of::<E1>() * 2 + size_of::<Fp>() * 2;
            s
        });

        let opening_e2_size = self.opening_e2.as_ref().map(|opening| {
            let mut s = 0;
            s += size_of::<Fq>();
            s += opening.evaluations.witness_evals.len() * size_of::<Fq>();
            s += size_of::<Fq>() * 2;
            s += size_of::<E2>();
            s += opening.opening_proof.lr.len() * 2 * size_of::<E2>();
            s += size_of::<E2>() * 2 + size_of::<Fq>() * 2;
            s
        });

        ProofSizeBreakdown {
            num_iterations: size_of::<u64>(),
            instance_e1: instance_e1_size,
            instance_e2: instance_e2_size,
            public_io: size_of::<Fp>() + self.output.len() * size_of::<Fp>(),
            opening_e1: opening_e1_size.unwrap_or(0),
            opening_e2: opening_e2_size.unwrap_or(0),
        }
    }
}

/// Detailed breakdown of proof size by component.
#[derive(Debug, Clone)]
pub struct ProofSizeBreakdown {
    pub num_iterations: usize,
    pub instance_e1: usize,
    pub instance_e2: usize,
    pub public_io: usize,
    pub opening_e1: usize,
    pub opening_e2: usize,
}

impl ProofSizeBreakdown {
    /// Total estimated size in bytes.
    pub fn total(&self) -> usize {
        self.num_iterations
            + self.instance_e1
            + self.instance_e2
            + self.public_io
            + self.opening_e1
            + self.opening_e2
    }
}

impl std::fmt::Display for ProofSizeBreakdown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Proof Size Breakdown:")?;
        writeln!(f, "  num_iterations: {} bytes", self.num_iterations)?;
        writeln!(f, "  instance_e1: {} bytes", self.instance_e1)?;
        writeln!(f, "  instance_e2: {} bytes", self.instance_e2)?;
        writeln!(f, "  public_io: {} bytes", self.public_io)?;
        writeln!(f, "  opening_e1: {} bytes", self.opening_e1)?;
        writeln!(f, "  opening_e2: {} bytes", self.opening_e2)?;
        writeln!(f, "  TOTAL: {} bytes", self.total())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::AffineRepr;
    use mina_curves::pasta::{Pallas, Vesta};

    #[test]
    fn test_relaxed_instance_trivial() {
        let instance: RelaxedInstance<Vesta> = RelaxedInstance::trivial(15);
        assert_eq!(instance.witness_commitments.len(), 15);
        assert_eq!(instance.u, <Vesta as AffineRepr>::ScalarField::one());
    }

    #[test]
    fn test_relaxed_witness_trivial() {
        let witness: RelaxedWitness<<Vesta as AffineRepr>::ScalarField> =
            RelaxedWitness::trivial(15, 256);
        assert_eq!(witness.witness.len(), 15);
        assert_eq!(witness.witness[0].len(), 256);
        assert_eq!(witness.error.len(), 256);
    }

    #[test]
    fn test_proof_size_breakdown() {
        use crate::NUMBER_OF_COLUMNS;
        use mina_curves::pasta::{Fp, Fq};

        // Create trivial instances
        let instance_e1: RelaxedInstance<Vesta> = RelaxedInstance::trivial(NUMBER_OF_COLUMNS);
        let instance_e2: RelaxedInstance<Pallas> = RelaxedInstance::trivial(NUMBER_OF_COLUMNS);

        let proof: Proof<Fp, Fq, Vesta, Pallas> = Proof {
            num_iterations: 100,
            instance_e1,
            instance_e2,
            public_io_hash: Fp::zero(),
            output: vec![],
            opening_e1: None,
            opening_e2: None,
        };

        // Test size estimation and breakdown
        let size = proof.estimated_size();
        let breakdown = proof.size_breakdown();

        assert!(size > 0);
        assert_eq!(breakdown.total(), size);

        println!("Estimated proof size: {} bytes", size);
        println!("{}", breakdown);
    }

    #[test]
    fn test_proof_size_estimation() {
        use crate::NUMBER_OF_COLUMNS;
        use mina_curves::pasta::{Fp, Fq};

        // Create trivial instances to estimate proof size
        let instance_e1: RelaxedInstance<Vesta> = RelaxedInstance::trivial(NUMBER_OF_COLUMNS);
        let instance_e2: RelaxedInstance<Pallas> = RelaxedInstance::trivial(NUMBER_OF_COLUMNS);

        let proof: Proof<Fp, Fq, Vesta, Pallas> = Proof {
            num_iterations: 100,
            instance_e1,
            instance_e2,
            public_io_hash: Fp::zero(),
            output: vec![],
            opening_e1: None,
            opening_e2: None,
        };

        let size = proof.estimated_size();

        // The proof should be reasonably small (< 10KB for a basic proof without outputs)
        // With 15 columns and empty cross-terms, we expect roughly:
        // - 8 bytes for num_iterations
        // - 15 * sizeof(curve point) * 2 for witness commitments
        // - 2 * sizeof(curve point) for error commitments
        // - 6 * sizeof(field element) for u, alpha, r on both curves
        // - 1 * sizeof(Fp) for public_io_hash
        assert!(size > 0);
        assert!(
            size < 10_000,
            "Proof size {} should be under 10KB for basic proof",
            size
        );

        // Print the size for informational purposes during testing
        println!("Estimated proof size: {} bytes", size);
    }

    #[test]
    fn test_proof_size_scales_with_cross_terms() {
        use crate::{MAX_DEGREE, NUMBER_OF_COLUMNS};
        use mina_curves::pasta::{Fp, Fq};

        // Create instance with cross-term commitments
        let mut instance_e1: RelaxedInstance<Vesta> = RelaxedInstance::trivial(NUMBER_OF_COLUMNS);
        let mut instance_e2: RelaxedInstance<Pallas> = RelaxedInstance::trivial(NUMBER_OF_COLUMNS);

        // Add cross-term commitments (one per degree 2..MAX_DEGREE)
        for _ in 2..=MAX_DEGREE {
            instance_e1
                .cross_term_commitments
                .push(PolyComm::new(vec![]));
            instance_e2
                .cross_term_commitments
                .push(PolyComm::new(vec![]));
        }

        let proof_with_cross_terms: Proof<Fp, Fq, Vesta, Pallas> = Proof {
            num_iterations: 100,
            instance_e1,
            instance_e2,
            public_io_hash: Fp::zero(),
            output: vec![],
            opening_e1: None,
            opening_e2: None,
        };

        let proof_without: Proof<Fp, Fq, Vesta, Pallas> = Proof {
            num_iterations: 100,
            instance_e1: RelaxedInstance::trivial(NUMBER_OF_COLUMNS),
            instance_e2: RelaxedInstance::trivial(NUMBER_OF_COLUMNS),
            public_io_hash: Fp::zero(),
            output: vec![],
            opening_e1: None,
            opening_e2: None,
        };

        let size_with = proof_with_cross_terms.estimated_size();
        let size_without = proof_without.estimated_size();

        // Proof with cross-terms should be larger
        assert!(
            size_with > size_without,
            "Proof with cross-terms ({}) should be larger than without ({})",
            size_with,
            size_without
        );
    }
}
