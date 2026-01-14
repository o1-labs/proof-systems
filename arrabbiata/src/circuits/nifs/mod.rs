//! NIFS (Non-Interactive Folding Scheme) circuit gadgets.
//!
//! This module contains the verifier circuit for the folding-based IVC scheme.
//!
//! ## Overview
//!
//! The NIFS verifier circuit implements the verifier's computation:
//!
//! 1. **Hash commitments**: Absorb commitments into a Poseidon sponge to
//!    derive challenges using Fiat-Shamir.
//! 2. **Fold commitments**: (TODO) Use EC scalar multiplication and addition to
//!    combine accumulated commitments with fresh ones.
//!
//! ## Commitment Absorption
//!
//! The verifier absorbs all commitments from the prover:
//! - Witness column commitments (NUMBER_OF_COLUMNS × 2 field elements)
//! - Cross-term commitments (MAX_DEGREE × 2 field elements)
//! - Error term commitment (2 field elements)

// TODO: Restore when verifier.rs is reconstructed
// mod verifier;
// pub use verifier::{
//     initial_sponge_state, squeeze_challenge, VerifierCircuit, NUM_CROSS_TERM_COMMITMENTS,
//     NUM_WITNESS_COMMITMENTS, TOTAL_FRESH_COMMITMENTS,
// };
