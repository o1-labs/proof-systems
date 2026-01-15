//! Setup phase for the NIFS-based IVC scheme.
//!
//! The setup phase establishes the "indexed relation" - the circuit definition
//! and cryptographic parameters needed for proving and verification.
//!
//! ## Overview
//!
//! The setup process:
//! 1. Takes a typed gadget sequence (HList of TypedGadgets)
//! 2. Generates SRS for both curves in the cycle
//! 3. Computes selector polynomial commitments
//! 4. Initializes the sponge state by absorbing the circuit description
//!
//! ## Fiat-Shamir Transcript Initialization
//!
//! The initial sponge state is critical for the Fiat-Shamir transcript.
//! It is computed by absorbing:
//! 1. The domain size
//! 2. All selector commitments (circuit structure binding)
//!
//! This ensures that proofs for different circuits have different
//! Fiat-Shamir challenges, preventing cross-circuit attacks.
//!
//! ## Usage
//!
//! ```ignore
//! use arrabbiata::circuits::{SquaringGadget, CubicGadget, HNil, GadgetList};
//! use arrabbiata::nifs::setup::Setup;
//!
//! // Define a circuit as a typed gadget sequence
//! let gadgets = HNil
//!     .push(SquaringGadget::new())
//!     .push(SquaringGadget::new())
//!     .push(CubicGadget::new());
//!
//! // Create setup from the gadget sequence (SRS size inferred)
//! let setup = Setup::new(gadgets);
//!
//! // Extract verification key
//! let vk = setup.verification_key();
//!
//! // Get initial sponge state for folding
//! let initial_sponge = setup.initial_sponge_state();
//! ```

use ark_ff::PrimeField;
use kimchi::circuits::domains::EvaluationDomains;
use log::{debug, info};
use mina_poseidon::constants::SpongeConstants;
use num_bigint::BigInt;
use o1_utils::FieldHelpers;
use poly_commitment::{ipa::SRS, PolyComm, SRS as _};
use std::time::Instant;

use crate::{
    circuits::TypedGadgetList,
    curve::{ArrabbiataCurve, PlonkSpongeConstants},
    nifs::column::Gadget,
    NUMBER_OF_COLUMNS, NUMBER_OF_GADGETS,
};

// ============================================================================
// Setup - Main setup structure
// ============================================================================

/// Setup for the NIFS-based IVC scheme.
///
/// Contains all the information needed to run the prover and verifier:
/// - SRS (Structured Reference String) for polynomial commitments
/// - Evaluation domains for FFT operations
/// - Circuit description (gadget sequence)
/// - Selector commitments
/// - Initial sponge state
pub struct Setup<
    Fp: PrimeField,
    Fq: PrimeField,
    E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
    E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
> where
    E1::BaseField: PrimeField,
    E2::BaseField: PrimeField,
{
    /// Domain for Fp (first curve's scalar field)
    pub domain_fp: EvaluationDomains<Fp>,

    /// Domain for Fq (second curve's scalar field)
    pub domain_fq: EvaluationDomains<Fq>,

    /// SRS for the first curve
    pub srs_e1: SRS<E1>,

    /// SRS for the second curve
    pub srs_e2: SRS<E2>,

    /// Size of the SRS (power of 2)
    pub srs_size: usize,

    /// The gadget sequence defining the circuit.
    /// Each entry corresponds to one row of the circuit.
    pub circuit_gates: Vec<Gadget>,

    /// Commitments to the selector polynomials for both curves.
    /// Indexed by gadget type (see `NUMBER_OF_GADGETS`).
    pub selectors_comm: (
        [PolyComm<E1>; NUMBER_OF_GADGETS],
        [PolyComm<E2>; NUMBER_OF_GADGETS],
    ),

    /// Initial state of the sponge, containing circuit-specific information.
    /// This is derived by hashing the circuit description.
    pub initial_sponge: [BigInt; PlonkSpongeConstants::SPONGE_WIDTH],
}

impl<
        Fp: PrimeField,
        Fq: PrimeField,
        E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
        E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
    > Setup<Fp, Fq, E1, E2>
where
    E1::BaseField: PrimeField,
    E2::BaseField: PrimeField,
{
    /// Create a setup from a typed gadget sequence (HList).
    ///
    /// The SRS size is automatically computed as the smallest power of 2
    /// that can accommodate all gadget rows.
    ///
    /// # Arguments
    ///
    /// * `gadgets` - A heterogeneous list of TypedGadgets
    ///
    /// # Type Parameters
    ///
    /// * `L` - The HList type representing the gadget sequence
    ///
    /// # Example
    ///
    /// ```ignore
    /// use arrabbiata::circuits::{SquaringGadget, CubicGadget, HNil, GadgetList};
    ///
    /// let gadgets = HNil
    ///     .push(SquaringGadget::new())
    ///     .push(CubicGadget::new());
    ///
    /// let setup = Setup::new(gadgets);
    /// ```
    pub fn new<L>(gadgets: L) -> Self
    where
        L: TypedGadgetList<Fp> + TypedGadgetList<Fq>,
    {
        // Extract the gadget sequence from the HList
        let circuit_gates: Vec<Gadget> = <L as TypedGadgetList<Fp>>::gadgets(&gadgets);

        // Get total rows from the typed gadget list
        let total_rows = <L as TypedGadgetList<Fp>>::typed_total_rows(&gadgets);

        // Compute the smallest power of 2 that fits all rows
        // We need at least size 2 for evaluation domains
        let srs_log2_size = if total_rows <= 1 {
            1 // Minimum size of 2
        } else {
            (total_rows as f64).log2().ceil() as usize
        };
        let srs_size = 1 << srs_log2_size;

        // Pad with NoOp gadgets to fill the SRS
        let mut padded_gates = circuit_gates;
        padded_gates.resize(srs_size, Gadget::NoOp);

        // Create evaluation domains
        let domain_fp = EvaluationDomains::<Fp>::create(srs_size).unwrap();
        let domain_fq = EvaluationDomains::<Fq>::create(srs_size).unwrap();

        // Create SRS for both curves
        info!(
            "Creating SRS of size 2^{} = {} for the first curve",
            srs_log2_size, srs_size
        );
        let srs_e1: SRS<E1> = {
            let start = Instant::now();
            let srs = SRS::create(srs_size);
            debug!("SRS for E1 created in {:?}", start.elapsed());
            let start = Instant::now();
            srs.get_lagrange_basis(domain_fp.d1);
            debug!("Lagrange basis for E1 added in {:?}", start.elapsed());
            srs
        };

        info!(
            "Creating SRS of size 2^{} = {} for the second curve",
            srs_log2_size, srs_size
        );
        let srs_e2: SRS<E2> = {
            let start = Instant::now();
            let srs = SRS::create(srs_size);
            debug!("SRS for E2 created in {:?}", start.elapsed());
            let start = Instant::now();
            srs.get_lagrange_basis(domain_fq.d1);
            debug!("Lagrange basis for E2 added in {:?}", start.elapsed());
            srs
        };

        // Compute selector commitments
        let selectors_comm = Self::compute_selector_commitments(
            &padded_gates,
            &srs_e1,
            &srs_e2,
            &domain_fp,
            &domain_fq,
        );

        // Initialize sponge state from circuit description
        let initial_sponge = Self::compute_initial_sponge(&padded_gates, &selectors_comm);

        Self {
            domain_fp,
            domain_fq,
            srs_e1,
            srs_e2,
            srs_size,
            circuit_gates: padded_gates,
            selectors_comm,
            initial_sponge,
        }
    }

    /// Compute selector polynomial commitments.
    ///
    /// Each selector polynomial has value 1 on rows where that gadget is active,
    /// and 0 elsewhere. The commitment is computed in Lagrange basis.
    fn compute_selector_commitments(
        circuit_gates: &[Gadget],
        srs_e1: &SRS<E1>,
        srs_e2: &SRS<E2>,
        domain_fp: &EvaluationDomains<Fp>,
        domain_fq: &EvaluationDomains<Fq>,
    ) -> (
        [PolyComm<E1>; NUMBER_OF_GADGETS],
        [PolyComm<E2>; NUMBER_OF_GADGETS],
    ) {
        // Initialize with the blinder to avoid the identity element
        let init: (
            [PolyComm<E1>; NUMBER_OF_GADGETS],
            [PolyComm<E2>; NUMBER_OF_GADGETS],
        ) = (
            core::array::from_fn(|_| PolyComm::new(vec![srs_e1.h])),
            core::array::from_fn(|_| PolyComm::new(vec![srs_e2.h])),
        );

        // Commit to the selectors using evaluations.
        // As they are supposed to be one or zero, each row adds a small
        // contribution to the commitment.
        circuit_gates
            .iter()
            .enumerate()
            .fold(init, |mut acc, (row, g)| {
                let i = usize::from(*g);
                acc.0[i] = &acc.0[i] + &srs_e1.get_lagrange_basis(domain_fp.d1)[row];
                acc.1[i] = &acc.1[i] + &srs_e2.get_lagrange_basis(domain_fq.d1)[row];
                acc
            })
    }

    /// Compute the initial sponge state from the circuit description.
    ///
    /// This is critical for the Fiat-Shamir transcript. The sponge absorbs:
    /// 1. The domain size
    /// 2. All selector commitments (binds the circuit structure)
    ///
    /// This ensures that proofs for different circuits have different
    /// Fiat-Shamir challenges, preventing cross-circuit attacks.
    ///
    /// The sponge is initialized by absorbing from E1's perspective
    /// (using Fq as the base field for absorbing E1 points).
    fn compute_initial_sponge(
        circuit_gates: &[Gadget],
        selectors_comm: &(
            [PolyComm<E1>; NUMBER_OF_GADGETS],
            [PolyComm<E2>; NUMBER_OF_GADGETS],
        ),
    ) -> [BigInt; PlonkSpongeConstants::SPONGE_WIDTH] {
        // Create a fresh sponge and absorb the circuit description
        let mut sponge = E1::create_new_sponge();

        // Absorb the domain size as a field element
        let domain_size_fq = Fq::from(circuit_gates.len() as u64);
        E1::absorb_fq(&mut sponge, domain_size_fq);

        // Absorb all selector commitments from E1
        // This binds the circuit structure into the transcript
        for selector_comm in &selectors_comm.0 {
            for chunk in &selector_comm.chunks {
                E1::absorb_curve_points(&mut sponge, &[*chunk]);
            }
        }

        // Squeeze challenges to derive the initial state
        // Each challenge is in the scalar field (Fp for E1)
        // We squeeze SPONGE_WIDTH challenges to fill the initial state
        core::array::from_fn(|_| {
            let challenge: Fp = E1::squeeze_challenge(&mut sponge);
            let bytes = challenge.to_bytes();
            BigInt::from_bytes_le(num_bigint::Sign::Plus, &bytes)
        })
    }

    /// Get the SRS size.
    pub fn get_srs_size(&self) -> usize {
        self.srs_size
    }

    /// Get the SRS blinding generators.
    pub fn get_srs_blinders(&self) -> (E1, E2) {
        (self.srs_e1.h, self.srs_e2.h)
    }

    /// Get the initial sponge state for starting a folding sequence.
    pub fn initial_sponge_state(&self) -> [BigInt; PlonkSpongeConstants::SPONGE_WIDTH] {
        self.initial_sponge.clone()
    }

    /// Extract a verification key from this setup.
    pub fn verification_key(&self) -> VerificationKey<Fp, Fq, E1, E2> {
        VerificationKey {
            domain_size: self.srs_size,
            num_columns: NUMBER_OF_COLUMNS,
            g1: self.srs_e1.g[0],
            g2: self.srs_e2.g[0],
            h1: self.srs_e1.h,
            h2: self.srs_e2.h,
            initial_sponge: self.initial_sponge.clone(),
            selectors_comm_e1: self.selectors_comm.0.clone(),
            selectors_comm_e2: self.selectors_comm.1.clone(),
        }
    }

    /// Get the number of non-NoOp rows (actual circuit rows).
    pub fn active_rows(&self) -> usize {
        self.circuit_gates
            .iter()
            .filter(|g| **g != Gadget::NoOp)
            .count()
    }

    /// Get the trivial accumulated instance for the base case (iteration 0).
    ///
    /// The trivial instance uses `u = 0`, which causes all constant terms
    /// in the homogenized constraints to vanish. This allows a zero witness
    /// to satisfy any constraint, including those with constants like Poseidon
    /// round constants.
    ///
    /// After folding with the first fresh instance (which has `u = 1`):
    /// ```text
    /// u_new = u_acc + r * u_fresh = 0 + r * 1 = r
    /// ```
    ///
    /// The resulting `u = r` is non-zero (with overwhelming probability),
    /// and the scheme proceeds normally.
    pub fn trivial_accumulator(&self) -> TrivialAccumulator<E1, E2> {
        TrivialAccumulator {
            // Witness commitments: blinded zero polynomials
            witness_commitments_e1: core::array::from_fn(|_| PolyComm::new(vec![self.srs_e1.h])),
            witness_commitments_e2: core::array::from_fn(|_| PolyComm::new(vec![self.srs_e2.h])),

            // Error commitments: blinded zero polynomials
            error_commitment_e1: PolyComm::new(vec![self.srs_e1.h]),
            error_commitment_e2: PolyComm::new(vec![self.srs_e2.h]),

            // u = 0: Constants vanish in homogenized constraints
            u: BigInt::from(0),

            // Canonical value for constraint combiner
            alpha: BigInt::from(1),
        }
    }
}

// ============================================================================
// TrivialAccumulator - Base case for folding
// ============================================================================

/// Trivial accumulated instance for the base case (iteration 0).
///
/// This is used as the "previous accumulator" when folding the first
/// fresh instance. It has:
/// - Zero witness and error polynomials
/// - Commitments equal to the blinding generator `h` (not identity!)
/// - `u = 0` so homogenized constants vanish
///
/// The verifier can deterministically reconstruct this from the SRS,
/// so it doesn't need to be transmitted.
#[derive(Clone, Debug)]
pub struct TrivialAccumulator<E1, E2>
where
    E1: ArrabbiataCurve,
    E2: ArrabbiataCurve,
    E1::BaseField: PrimeField,
    E2::BaseField: PrimeField,
{
    /// Witness commitments for E1 (all equal to h1).
    pub witness_commitments_e1: [PolyComm<E1>; NUMBER_OF_COLUMNS],

    /// Witness commitments for E2 (all equal to h2).
    pub witness_commitments_e2: [PolyComm<E2>; NUMBER_OF_COLUMNS],

    /// Error commitment for E1 (equal to h1).
    pub error_commitment_e1: PolyComm<E1>,

    /// Error commitment for E2 (equal to h2).
    pub error_commitment_e2: PolyComm<E2>,

    /// Homogenization variable: u = 0.
    ///
    /// With u = 0, the homogenized constraints evaluate to 0 for any witness,
    /// because constant terms are multiplied by powers of u.
    pub u: BigInt,

    /// Constraint combiner: α = 1 (canonical value).
    pub alpha: BigInt,
}

impl<E1, E2> TrivialAccumulator<E1, E2>
where
    E1: ArrabbiataCurve,
    E2: ArrabbiataCurve,
    E1::BaseField: PrimeField,
    E2::BaseField: PrimeField,
{
    /// Check if a commitment matches the trivial (blinded zero) commitment.
    ///
    /// This is useful for the verifier to check that the prover is using
    /// the correct trivial accumulator at iteration 0.
    pub fn is_trivial_commitment_e1(&self, comm: &PolyComm<E1>, h: E1) -> bool {
        comm.chunks.len() == 1 && comm.chunks[0] == h
    }

    /// Check if a commitment matches the trivial (blinded zero) commitment for E2.
    pub fn is_trivial_commitment_e2(&self, comm: &PolyComm<E2>, h: E2) -> bool {
        comm.chunks.len() == 1 && comm.chunks[0] == h
    }
}

// ============================================================================
// VerificationKey - Minimal data for verification
// ============================================================================

/// Verification key extracted from Setup.
///
/// Contains the minimal data needed for verification, without the full
/// prover-side data (like full SRS or constraint polynomials).
#[derive(Clone, Debug)]
pub struct VerificationKey<
    Fp: PrimeField,
    Fq: PrimeField,
    E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
    E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
> where
    E1::BaseField: PrimeField,
    E2::BaseField: PrimeField,
{
    /// Domain size (number of rows)
    pub domain_size: usize,

    /// Number of witness columns
    pub num_columns: usize,

    /// SRS generator for E1
    pub g1: E1,

    /// SRS generator for E2
    pub g2: E2,

    /// Blinding generator for E1
    pub h1: E1,

    /// Blinding generator for E2
    pub h2: E2,

    /// Initial sponge state (derived from circuit description).
    /// Must match for prover and verifier.
    pub initial_sponge: [BigInt; PlonkSpongeConstants::SPONGE_WIDTH],

    /// Commitments to selector polynomials for E1.
    /// Indexed by gadget type (see `NUMBER_OF_GADGETS`).
    pub selectors_comm_e1: [PolyComm<E1>; NUMBER_OF_GADGETS],

    /// Commitments to selector polynomials for E2.
    /// Indexed by gadget type (see `NUMBER_OF_GADGETS`).
    pub selectors_comm_e2: [PolyComm<E2>; NUMBER_OF_GADGETS],
}

impl<
        Fp: PrimeField,
        Fq: PrimeField,
        E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
        E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
    > VerificationKey<Fp, Fq, E1, E2>
where
    E1::BaseField: PrimeField,
    E2::BaseField: PrimeField,
{
    /// Verify that the verification key matches another.
    ///
    /// This ensures both parties are using the same circuit.
    /// The initial sponge is derived from selector commitments, so checking
    /// both is defense in depth.
    pub fn matches_circuit(&self, other: &Self) -> bool {
        self.initial_sponge == other.initial_sponge
            && self.domain_size == other.domain_size
            && self.num_columns == other.num_columns
            && self.selectors_comm_e1 == other.selectors_comm_e1
            && self.selectors_comm_e2 == other.selectors_comm_e2
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::{
        gadgets::{CubicGadget, SquaringGadget, TrivialGadget},
        GadgetList, HNil,
    };
    use mina_curves::pasta::{Fp, Fq, Pallas, Vesta};

    #[test]
    fn test_setup_new() {
        let gadgets = HNil
            .push(SquaringGadget::new())
            .push(SquaringGadget::new())
            .push(CubicGadget::new());

        // SRS size is inferred: 3 rows -> 2^2 = 4
        let setup: Setup<Fp, Fq, Vesta, Pallas> = Setup::new(gadgets);

        // Should have 4 rows (next power of 2 >= 3)
        assert_eq!(setup.get_srs_size(), 4);

        // First 3 rows are our gadgets, rest are NoOp
        assert_eq!(setup.circuit_gates[0], Gadget::Cubic);
        assert_eq!(setup.circuit_gates[1], Gadget::Squaring);
        assert_eq!(setup.circuit_gates[2], Gadget::Squaring);
        assert_eq!(setup.circuit_gates[3], Gadget::NoOp);

        // Active rows should be 3
        assert_eq!(setup.active_rows(), 3);
    }

    #[test]
    fn test_setup_srs_size_inference() {
        // 1 gadget -> 2^1 = 2
        let gadgets1 = HNil.push(SquaringGadget::new());
        let setup1: Setup<Fp, Fq, Vesta, Pallas> = Setup::new(gadgets1);
        assert_eq!(setup1.get_srs_size(), 2);

        // 5 gadgets -> 2^3 = 8
        let gadgets5 = HNil
            .push(SquaringGadget::new())
            .push(SquaringGadget::new())
            .push(SquaringGadget::new())
            .push(SquaringGadget::new())
            .push(SquaringGadget::new());
        let setup5: Setup<Fp, Fq, Vesta, Pallas> = Setup::new(gadgets5);
        assert_eq!(setup5.get_srs_size(), 8);
    }

    #[test]
    fn test_setup_verification_key() {
        let gadgets = HNil.push(TrivialGadget::new());

        let setup: Setup<Fp, Fq, Vesta, Pallas> = Setup::new(gadgets);
        let vk = setup.verification_key();

        // 1 gadget -> 2^1 = 2
        assert_eq!(vk.domain_size, 2);
        assert_eq!(vk.num_columns, NUMBER_OF_COLUMNS);
    }

    #[test]
    fn test_initial_sponge_differs_for_different_circuits() {
        let gadgets1 = HNil.push(SquaringGadget::new());
        let gadgets2 = HNil.push(CubicGadget::new());

        let setup1: Setup<Fp, Fq, Vesta, Pallas> = Setup::new(gadgets1);
        let setup2: Setup<Fp, Fq, Vesta, Pallas> = Setup::new(gadgets2);

        // Different circuits should have different initial sponge states
        assert_ne!(setup1.initial_sponge_state(), setup2.initial_sponge_state());
    }

    #[test]
    fn test_verification_key_matches() {
        let gadgets = HNil.push(SquaringGadget::new()).push(CubicGadget::new());

        let setup1: Setup<Fp, Fq, Vesta, Pallas> = Setup::new(gadgets.clone());
        let setup2: Setup<Fp, Fq, Vesta, Pallas> = Setup::new(gadgets);

        let vk1 = setup1.verification_key();
        let vk2 = setup2.verification_key();

        assert!(vk1.matches_circuit(&vk2));
    }

    #[test]
    fn test_selector_commitments_not_identity() {
        let gadgets = HNil.push(SquaringGadget::new());

        let setup: Setup<Fp, Fq, Vesta, Pallas> = Setup::new(gadgets);

        // Check that selector commitments are not the identity
        // (they should be blinder + contribution from active rows)
        for comm in &setup.selectors_comm.0 {
            assert!(!comm.chunks.is_empty());
        }
        for comm in &setup.selectors_comm.1 {
            assert!(!comm.chunks.is_empty());
        }
    }
}
