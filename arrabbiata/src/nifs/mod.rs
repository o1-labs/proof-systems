//! Non-Interactive Folding Scheme (NIFS) module.
//!
//! This module implements the core folding/accumulation logic for the Arrabbiata
//! IVC scheme, following the Nova folding approach adapted for Plonkish constraints.
//!
//! ## Overview
//!
//! The folding scheme allows combining two relaxed instances into a single
//! accumulated instance without the need for expensive pairing operations.
//! This is the key building block for Incrementally Verifiable Computation (IVC).
//!
//! The implementation relies on a representation of the circuit as a 2D array
//! of "data points" the interpreter can use. An interpreter defines what a "position"
//! is in the circuit and allows performing operations using these positions.
//! Some positions are public inputs (fixed at setup time), while others are private.
//!
//! ## Modules
//!
//! - [`folding`] - Core folding operations including cross-terms computation,
//!   witness folding, and error term accumulation.
//! - [`witness`] - Witness environment and program state management.
//! - [`column`] - Column definitions and gadgets for the circuit.
//! - [`challenge`] - Challenge terms for the Fiat-Shamir heuristic.
//! - [`logup`] - LogUp lookup argument support.
//! - [`poseidon_3_60_0_5_5_fp`] / [`poseidon_3_60_0_5_5_fq`] - Poseidon parameters.
//!
//! ## Nova-style Folding
//!
//! For a constraint polynomial P of degree D, when we fold two instances with
//! a random challenge r, the cross-terms are the coefficients of r^1, r^2, ..., r^{D-1}
//! in the expansion of P(acc + r * fresh).
//!
//! The relaxed relation is:
//! ```text
//! C(W, X) = u^d * E(X)
//! ```
//! where:
//! - C(W, X) is the combined constraint polynomial evaluated at witness W
//! - u is the homogenization variable
//! - d is the maximum constraint degree (MAX_DEGREE)
//! - E(X) is the error polynomial
//!
//! For a fresh instance, u = 1 and E(X) = 0, so C(W, X) = 0 (satisfied).
//! After folding, u and E evolve to capture the accumulated "slack".
//!
//! ## Gadgets Implemented
//!
//! The interpreter implements gadgets for the IVC verifier circuit. For details
//! on the full verifier flow, see [`crate::interpreter`].
//!
//! ### Elliptic Curve Addition
//!
//! The IVC augmented circuit requires elliptic curve operations, specifically
//! additions and scalar multiplications. We use affine coordinates for efficiency.
//!
//! For two different points P1 = (X1, Y1) and P2 = (X2, Y2), P3 = P1 + P2 is computed as:
//!
//! ```text
//! λ = (Y1 - Y2) / (X1 - X2)
//! X3 = λ² - X1 - X2
//! Y3 = λ (X1 - X3) - Y1
//! ```
//!
//! These are degree-2 constraints:
//! - Constraint 1: λ (X1 - X2) - Y1 + Y2 = 0
//! - Constraint 2: X3 + X1 + X2 - λ² = 0
//! - Constraint 3: Y3 - λ (X1 - X3) + Y1 = 0
//!
//! For point doubling (same point), λ = (3X1² + a) / (2Y1).
//!
//! #### Gadget Layout (EC Addition)
//!
//! ```text
//! | C1 | C2 | C3 | C4 | C5 | C6 | C7 | C8 |
//! | x1 | y1 | x2 | y2 | b0 | λ  | x3 | y3 |
//! ```
//!
//! where b0 = 1 if points are the same (doubling), 0 otherwise.
//!
//! ### Hash - Poseidon
//!
//! Hashing is crucial for the IVC scheme. We use Poseidon with:
//! - State width: 3 (PlonkSpongeConstants::SPONGE_WIDTH)
//! - Full rounds: 60 (suitable for ~256-bit field security)
//! - S-box: x^5
//!
//! With [NUMBER_OF_COLUMNS](crate::NUMBER_OF_COLUMNS) columns and constraints up to
//! [MAX_DEGREE](crate::MAX_DEGREE), we can compute 5 full rounds per row using the
//! "next row" (evaluation at ζω).
//!
//! #### Gadget Layout (Poseidon, 5 rounds)
//!
//! ```text
//! | C1 | C2 | C3 | C4 | C5 | C6 | C7 | C8 | C9 | C10 | C11 | C12 | C13 | C14 | C15 |
//! | x  | y  | z  | a1 | a2 | a3 | b1 | b2 | b3 | c1  | c2  | c3  | d1  | d2  | d3  |
//! | o1 | o2 | o3 |
//! ```
//!
//! where:
//! - (x, y, z) is the input state
//! - (o1, o2, o3) is the output after 5 rounds
//! - Intermediate values are after each round application
//!
//! Round constants are public inputs. Elements to absorb are added to the initial
//! state before the permutation.
//!
//! ### Elliptic Curve Scalar Multiplication
//!
//! Scalar multiplication uses the double-and-add algorithm with the "next row"
//! for accumulators. Each row processes one bit of the scalar.
//!
//! #### Gadget Layout (EC Scaling, one bit)
//!
//! ```text
//! | C1   |   C2   |    C3    |    C4    |  C5  |  C6 |     C7     |     C8     | C9 | C10 |
//! | o_x  |  o_y   | tmp_x    | tmp_y    | r_i  |  λ  | sum_x      | sum_y      | λ' | bit |
//! | o'_x |  o'_y  | tmp'_x   | tmp'_y   | r'   |
//! ```
//!
//! where:
//! - (o_x, o_y): result accumulator
//! - (tmp_x, tmp_y): doubled point for double-and-add
//! - r_i: remaining scalar, r' = r >> 1
//! - bit: current bit (r_i & 1)
//! - λ, λ': slopes for addition and doubling
//!
//! ## Constraint Combination
//!
//! The prover combines constraints using a challenge α (generated via Fiat-Shamir
//! in the verifier circuit). Challenges are accumulated using the folding random coin.
//!
//! This requires folding of degree 5+1 constraints (α is a variable). See
//! [HackMD document](https://hackmd.io/@dannywillems/Syo5MBq90) for details.
//!
//! ## Permutation Argument
//!
//! Communication between rows uses a generalized PlonK permutation argument.
//! Permutations are built using `save` and `load` methods with row indices.
//!
//! The polynomials are:
//! ```text
//! f'(X) = f(X) + β X + γ
//! g'(X) = g(X) + β σ(X) + γ
//! ```
//!
//! An accumulator is built after coining challenges β and γ (absorbed after
//! column commitments). The verifier circuit checks correct challenge computation.
//!
//! ## Fiat-Shamir Challenges
//!
//! Verifier challenges are simulated by passing "messages" as public inputs to
//! subsequent instances. At step i+1, challenges from step i are verified by
//! the in-circuit verifier and checked against received public inputs.
//!
//! ## Homogenization and Folding
//!
//! Constraints are homogenized for folding by adding variable "U":
//! - Each monomial of degree d is homogenized to degree d' = MAX_DEGREE
//! - Cross-terms and error terms are computed after witness building
//!
//! The [mvpoly] crate provides `compute_cross_terms` for this.
//!
//! ## Message Passing
//!
//! Messages (commitments, challenges) are passed between steps and curves.
//! The sponge state is forked at different steps for consistency.
//!
//! Key variables per instance n:
//! - w_(p, n): witness
//! - W_(p, n): aggregated witness
//! - C_(p, n): commitment to witness
//! - acc_(p, n): accumulated commitments
//! - α, β, γ, r, u: various challenges
//! - t_(p, n, i): cross-term evaluations
//! - Ct_(p, n, i): cross-term commitments
//! - o_(p, n): final sponge digest
//!
//! The verifier circuit responsibilities include:
//! - Verifying Fiat-Shamir challenges from previous instance
//! - Aggregating witness columns
//! - Aggregating error terms with cross-terms

pub mod challenge;
pub mod column;
pub mod folding;
pub mod logup;
pub mod poseidon_3_60_0_5_5_fp;
pub mod poseidon_3_60_0_5_5_fq;
pub mod setup;
pub mod witness;

// Re-export commonly used items
pub use challenge::{ChallengeTerm, Challenges};
pub use column::{Column, Gadget};
pub use folding::{
    compute_all_cross_terms, compute_cross_terms_for_row, fold_challenge, fold_error_terms,
    fold_homogenizer, fold_witnesses, CrossTerms,
};
pub use setup::{Setup, TrivialAccumulator, VerificationKey};
pub use witness::{Env, Program};
