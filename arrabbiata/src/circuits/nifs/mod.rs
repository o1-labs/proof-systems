//! NIFS (Non-Interactive Folding Scheme) circuit gadgets.
//!
//! This module contains the verifier circuit for the folding-based IVC scheme.
//!
//! ## Overview
//!
//! The NIFS verifier circuit implements the in-circuit verifier computation:
//!
//! 1. **Absorb commitments**: Hash commitments into a Poseidon sponge
//! 2. **Derive challenges**: Squeeze α, r, u via Fiat-Shamir
//! 3. **Verify accumulation**: Check scalar accumulation equations
//! 4. **Output digest**: Produce sponge state for next instance
//!
//! ## Two-Step Delay Pattern
//!
//! Due to the curve cycle (Pallas/Vesta), verification happens with a delay:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                        IVC Message Flow Diagram                              │
//! └─────────────────────────────────────────────────────────────────────────────┘
//!
//!   Instance n                    Instance n+1                  Instance n+2
//!   (Vesta/Fp)                    (Pallas/Fq)                   (Vesta/Fp)
//!   ──────────                    ───────────                   ──────────
//!        │                              │                             │
//!        │  Generates:                  │                             │
//!        │  - α, r, u (Fq elements)     │                             │
//!        │  - Commitments (Fq points)   │                             │
//!        │  - Digest o_(p,n)            │                             │
//!        │                              │                             │
//!        │────────────────────────────▶ │                             │
//!        │  Pass: commitments,          │                             │
//!        │        α, r, u, digest       │  Verifies FS:               │
//!        │                              │  - Re-derive α, r, u        │
//!        │                              │    from sponge over Fq      │
//!        │                              │  - Compare with claimed     │
//!        │                              │                             │
//!        │                              │  Cannot verify:             │
//!        │                              │  - u_acc = u_old + r·u      │
//!        │                              │    (that's Fp arithmetic!)  │
//!        │                              │                             │
//!        │                              │─────────────────────────────▶
//!        │                              │  Pass: accumulation data    │
//!        │                              │        for native verify    │
//!        │                              │                             │
//!        │                              │                             │  Verifies accumulation:
//!        │                              │                             │  - u_new = u_old + r·u
//!        │                              │                             │  - α_new = α_old + r·α
//!        │                              │                             │    (native Fp ops!)
//!        │                              │                             │
//!        ▼                              ▼                             ▼
//! ```
//!
//! ## Commitments Absorbed
//!
//! The verifier absorbs all commitments from the prover:
//! - Witness column commitments: `NUMBER_OF_COLUMNS` points (2 field elements each)
//! - Cross-term commitments: `MAX_DEGREE - 1` points
//! - Error term commitment: 1 point
//!
//! Total: `(NUMBER_OF_COLUMNS + MAX_DEGREE) × 2` field elements per instance.
//!
//! ## Challenges Derived
//!
//! After absorption, the sponge squeezes:
//! - `α`: Constraint combiner (combines all constraint polynomials)
//! - `r`: Folding challenge (random linear combination for folding)
//! - `u`: Homogenizer (tracks relaxation degree)
//!
//! ## Data Structures
//!
//! - [`PreviousInstanceData`]: Data from instance n-1 (opposite curve)
//! - [`TwoStepBackData`]: Data from instance n-2 (same curve, for native verification)
//! - [`AccumulatedState`]: Accumulated scalars and sponge state
//! - [`VerifierCircuit`]: Main verifier circuit structure

pub mod verifier;

pub use verifier::{
    AccumulatedState, PreviousInstanceData, TwoStepBackData, VerifierCircuit,
    ELEMENTS_TO_ABSORB_PER_INSTANCE, NUM_CHALLENGES_PER_INSTANCE, NUM_CROSS_TERM_COMMITMENTS,
    NUM_WITNESS_COMMITMENTS, SCALAR_MUL_BITS, TOTAL_FRESH_COMMITMENTS, VERIFIER_ARITY,
};
