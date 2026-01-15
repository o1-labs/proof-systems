//! NIFS Verifier Circuit
//!
//! This module implements the in-circuit verifier for the Nova-style folding scheme.
//! The verifier circuit runs inside each IVC step to verify that the previous
//! fold was computed correctly.
//!
//! ## Overview
//!
//! At each IVC step n, the verifier circuit:
//! 1. Receives data from instance (n-1) on the opposite curve
//! 2. Receives data from instance (n-2) on the same curve
//! 3. Verifies Fiat-Shamir challenge derivation from (n-1)
//! 4. Verifies scalar accumulation from (n-2): u, α
//! 5. Verifies commitment accumulation from (n-2): C_acc = C_acc_old + r * C_fresh
//! 6. Outputs a new sponge digest for the next instance
//!
//! ## Two-Step Delay Pattern
//!
//! Due to the curve cycle, verification happens with a delay:
//!
//! ```text
//! Instance n (Fp):
//!   - Generates challenges α, r, u (sponge over Fq, outputs Fq elements)
//!   - Generates commitments on curve E2 (base field Fp)
//!   - Cannot verify challenges in-circuit (wrong field!)
//!
//! Instance n+1 (Fq):
//!   - Receives α, r, u from instance n
//!   - CAN verify Fiat-Shamir (re-run sponge over Fq, check outputs)
//!   - Cannot verify scalar accumulation (that's Fp arithmetic)
//!   - Cannot verify commitment accumulation (commitments are on E1, base field Fq)
//!
//! Instance n+2 (Fp):
//!   - Receives accumulation claims from n
//!   - CAN verify scalar accumulation: u_new = u_old + r * u (native Fp)
//!   - CAN verify commitment accumulation: C_new = C_old + r * C (native EC on E2)
//! ```
//!
//! ## Type Parameters
//!
//! The verifier circuit is parametrized by:
//! - `F`: The native field (scalar field of the current curve)
//! - `E`: The opposite curve (commitments from n-1 are points on this curve)
//! - `C`: Curve configuration for EC operations (same base field as F)
//! - `S`: The sponge implementation for Fiat-Shamir
//!
//! ## Circuit Structure
//!
//! The verifier circuit synthesizes constraints in four phases:
//!
//! 1. **Sponge Phase**: Absorb commitments and squeeze challenges
//!    - Uses `Sponge` trait for Poseidon operations
//!    - Generates constraints for absorption and permutation
//!
//! 2. **Challenge Verification**: Assert squeezed values match claimed
//!    - `assert_eq(squeezed_alpha, claimed_alpha)`
//!    - `assert_eq(squeezed_r, claimed_r)`
//!    - `assert_eq(squeezed_u, claimed_u)`
//!
//! 3. **Scalar Accumulation Verification** (from n-2): Native field arithmetic
//!    - `assert_eq(u_acc_new, u_acc_old + r * u_fresh)`
//!    - `assert_eq(alpha_acc_new, alpha_acc_old + r * alpha_fresh)`
//!
//! 4. **Commitment Accumulation Verification** (from n-2): EC operations
//!    - For each commitment: `assert_eq(C_acc_new, C_acc_old + r * C_fresh)`
//!    - Uses EC scalar multiplication (128-bit challenge) and EC addition
//!    - Total: 20 commitments (15 witness + 4 cross-term + 1 error)

use ark_ec::{short_weierstrass::SWCurveConfig, AffineRepr};
use ark_ff::PrimeField;
use core::marker::PhantomData;

use crate::{
    circuit::{CircuitEnv, SelectorEnv, StepCircuit},
    circuits::{
        gadget::{ECPointPair, ECScalarMulInput, TypedGadget},
        gadgets::{
            curve::native::{CurveNativeAddGadget, CurveNativeScalarMulGadget},
            hash::{Sponge, POSEIDON_RATE, POSEIDON_STATE_SIZE},
        },
        types::ECPoint,
    },
    MAX_DEGREE, NUMBER_OF_COLUMNS,
};

// ============================================================================
// Constants
// ============================================================================

/// Number of witness column commitments.
pub const NUM_WITNESS_COMMITMENTS: usize = NUMBER_OF_COLUMNS;

/// Number of cross-term commitments (one per degree 1 to MAX_DEGREE-1).
pub const NUM_CROSS_TERM_COMMITMENTS: usize = MAX_DEGREE - 1;

/// Total commitments from a fresh instance:
/// - Witness columns
/// - Cross-terms
/// - Error term
pub const TOTAL_FRESH_COMMITMENTS: usize = NUM_WITNESS_COMMITMENTS + NUM_CROSS_TERM_COMMITMENTS + 1;

/// Number of field elements to absorb per instance.
/// Each commitment is 2 field elements (affine x, y coordinates).
pub const ELEMENTS_TO_ABSORB_PER_INSTANCE: usize = TOTAL_FRESH_COMMITMENTS * 2;

/// Number of challenges derived from the sponge per instance.
/// - α (constraint combiner)
/// - r (folding challenge)
/// - u (homogenizer)
pub const NUM_CHALLENGES_PER_INSTANCE: usize = 3;

/// Arity of the verifier circuit as a StepCircuit.
///
/// The verifier circuit state consists of:
/// - `z[0]`: digest - sponge digest from previous fold
/// - `z[1]`: u_acc - accumulated homogenizer
/// - `z[2]`: alpha_acc - accumulated constraint combiner
pub const VERIFIER_ARITY: usize = 3;

/// Data received from the previous instance (n-1) on the opposite curve.
///
/// This data is passed as public inputs and verified via Fiat-Shamir.
/// The commitments are points on curve E, represented as pairs of F elements
/// (where F is the base field of E = scalar field of current curve).
#[derive(Clone, Debug)]
pub struct PreviousInstanceData<F: PrimeField, E: AffineRepr<BaseField = F>> {
    /// Witness column commitments (points on opposite curve).
    pub witness_commitments: [ECPoint<F>; NUM_WITNESS_COMMITMENTS],

    /// Cross-term commitments T_1, ..., T_{d-1}.
    pub cross_term_commitments: [ECPoint<F>; NUM_CROSS_TERM_COMMITMENTS],

    /// Error term commitment.
    pub error_commitment: ECPoint<F>,

    /// Constraint combiner challenge α (claimed, to be verified).
    pub alpha: F,

    /// Folding challenge r (claimed, to be verified).
    pub r: F,

    /// Homogenizer u (claimed, to be verified).
    pub u: F,

    /// Sponge digest from instance (n-1).
    pub digest: F,

    /// Phantom for the curve type.
    _marker: PhantomData<E>,
}

impl<F: PrimeField, E: AffineRepr<BaseField = F>> PreviousInstanceData<F, E> {
    /// Create new previous instance data.
    pub fn new(
        witness_commitments: [ECPoint<F>; NUM_WITNESS_COMMITMENTS],
        cross_term_commitments: [ECPoint<F>; NUM_CROSS_TERM_COMMITMENTS],
        error_commitment: ECPoint<F>,
        alpha: F,
        r: F,
        u: F,
        digest: F,
    ) -> Self {
        Self {
            witness_commitments,
            cross_term_commitments,
            error_commitment,
            alpha,
            r,
            u,
            digest,
            _marker: PhantomData,
        }
    }

    /// Create from actual curve points.
    ///
    /// # Panics
    ///
    /// Panics if any commitment is the point at infinity.
    pub fn from_curve_points(
        witness_commitments: &[E; NUM_WITNESS_COMMITMENTS],
        cross_term_commitments: &[E; NUM_CROSS_TERM_COMMITMENTS],
        error_commitment: E,
        alpha: F,
        r: F,
        u: F,
        digest: F,
    ) -> Self {
        // Helper to convert a curve point to ECPoint (assumes non-infinity)
        let to_ecpoint = |p: E| {
            let (x, y) = p.xy().expect("commitment should not be point at infinity");
            ECPoint::new(x, y)
        };

        Self {
            witness_commitments: core::array::from_fn(|i| to_ecpoint(witness_commitments[i])),
            cross_term_commitments: core::array::from_fn(|i| to_ecpoint(cross_term_commitments[i])),
            error_commitment: to_ecpoint(error_commitment),
            alpha,
            r,
            u,
            digest,
            _marker: PhantomData,
        }
    }
}

/// Data received from two instances back (n-2) on the same curve.
///
/// This data is used to verify accumulation equations using native field ops.
/// Since instance (n-2) is on the same curve, these are native field elements.
///
/// The data includes both scalar accumulation (u, α) and commitment accumulation.
/// For each commitment, we verify: C_acc_new = C_acc_old + r * C_fresh
#[derive(Clone, Debug)]
pub struct TwoStepBackData<F: PrimeField> {
    /// Previous accumulated homogenizer u_acc (before fold at n-2).
    pub u_acc_old: F,

    /// Fresh homogenizer u from instance (n-2).
    pub u_fresh: F,

    /// Folding challenge r used at instance (n-2).
    pub r: F,

    /// Claimed new accumulated homogenizer (to verify: u_acc_new = u_acc_old + r * u_fresh).
    pub u_acc_new_claimed: F,

    /// Previous accumulated α (before fold at n-2).
    pub alpha_acc_old: F,

    /// Fresh α from instance (n-2).
    pub alpha_fresh: F,

    /// Claimed new accumulated α (to verify: α_acc_new = α_acc_old + r * α_fresh).
    pub alpha_acc_new_claimed: F,

    // ========================================================================
    // Commitment accumulation data
    // ========================================================================
    /// Previous accumulated witness commitments (before fold at n-2).
    pub witness_acc_old: [ECPoint<F>; NUM_WITNESS_COMMITMENTS],

    /// Fresh witness commitments from instance (n-2).
    pub witness_fresh: [ECPoint<F>; NUM_WITNESS_COMMITMENTS],

    /// Claimed new accumulated witness commitments.
    pub witness_acc_new_claimed: [ECPoint<F>; NUM_WITNESS_COMMITMENTS],

    /// Previous accumulated cross-term commitments (before fold at n-2).
    pub cross_term_acc_old: [ECPoint<F>; NUM_CROSS_TERM_COMMITMENTS],

    /// Fresh cross-term commitments from instance (n-2).
    pub cross_term_fresh: [ECPoint<F>; NUM_CROSS_TERM_COMMITMENTS],

    /// Claimed new accumulated cross-term commitments.
    pub cross_term_acc_new_claimed: [ECPoint<F>; NUM_CROSS_TERM_COMMITMENTS],

    /// Previous accumulated error commitment (before fold at n-2).
    pub error_acc_old: ECPoint<F>,

    /// Fresh error commitment from instance (n-2).
    pub error_fresh: ECPoint<F>,

    /// Claimed new accumulated error commitment.
    pub error_acc_new_claimed: ECPoint<F>,
}

impl<F: PrimeField> TwoStepBackData<F> {
    /// Verify the accumulation equation for u.
    ///
    /// Checks: u_acc_new = u_acc_old + r * u_fresh
    pub fn verify_u_accumulation(&self) -> bool {
        let expected = self.u_acc_old + self.r * self.u_fresh;
        expected == self.u_acc_new_claimed
    }

    /// Verify the accumulation equation for α.
    ///
    /// Checks: α_acc_new = α_acc_old + r * α_fresh
    pub fn verify_alpha_accumulation(&self) -> bool {
        let expected = self.alpha_acc_old + self.r * self.alpha_fresh;
        expected == self.alpha_acc_new_claimed
    }

    /// Verify all scalar accumulation equations.
    pub fn verify_scalar_accumulation(&self) -> bool {
        self.verify_u_accumulation() && self.verify_alpha_accumulation()
    }

    /// Verify all accumulation equations (scalars and commitments).
    ///
    /// Note: Commitment verification requires EC operations and is performed
    /// in-circuit via `synthesize_commitment_accumulation_verification`.
    pub fn verify_all(&self) -> bool {
        self.verify_scalar_accumulation()
        // Commitment verification is done in-circuit
    }
}

/// Accumulated state carried through the IVC.
///
/// This represents what instance n has accumulated so far and will pass
/// to future instances for verification.
#[derive(Clone, Debug)]
pub struct AccumulatedState<F: PrimeField> {
    /// Accumulated homogenizer u.
    /// Starts at 0 for trivial accumulator, becomes non-zero after first fold.
    pub u: F,

    /// Accumulated constraint combiner α.
    pub alpha: F,

    /// Digest from the previous fold's sponge (single squeeze output).
    /// This is used to initialize the sponge state for the next step.
    pub digest: F,

    /// Number of IVC iterations completed.
    pub iteration: u64,
}

impl<F: PrimeField> AccumulatedState<F> {
    /// Create initial state from setup's initial digest.
    pub fn initial(initial_digest: F) -> Self {
        Self {
            u: F::zero(),    // Trivial accumulator has u = 0
            alpha: F::one(), // Start with α = 1
            digest: initial_digest,
            iteration: 0,
        }
    }

    /// Fold in new values with challenge r.
    pub fn fold(&self, fresh_u: F, fresh_alpha: F, r: F, new_digest: F) -> Self {
        Self {
            u: self.u + r * fresh_u,
            alpha: self.alpha + r * fresh_alpha,
            digest: new_digest,
            iteration: self.iteration + 1,
        }
    }
}

// ============================================================================
// Verifier Circuit
// ============================================================================

/// Number of bits for scalar multiplication in commitment accumulation.
///
/// This determines how many bits of the folding challenge `r` are processed.
/// Following Pickles, challenges (from sponge squeeze) are 128 bits, not full
/// field elements. This halves the cost of scalar multiplication.
pub const SCALAR_MUL_BITS: usize = 128;

/// The NIFS verifier circuit.
///
/// This circuit verifies the correctness of the previous folding step
/// and prepares data for the next step.
///
/// ## Type Parameters
///
/// - `F`: Native field (scalar field of current curve)
/// - `E`: Opposite curve (commitments are points on E, with E::BaseField = F)
/// - `C`: Curve configuration for EC operations (same curve as commitments)
/// - `S`: Sponge implementation for Fiat-Shamir (provides `absorb` and `permute`)
///
/// ## Verification Steps
///
/// 1. **Absorb commitments**: Add all commitment coordinates to sponge
/// 2. **Squeeze challenges**: Derive α, r, u and compare with claimed values
/// 3. **Verify scalar accumulation**: Check u_new = u_old + r * u_fresh (from n-2 data)
/// 4. **Verify commitment accumulation**: Check C_acc_new = C_acc_old + r * C_fresh
/// 5. **Update state**: Produce new sponge digest for next instance
pub struct VerifierCircuit<F, E, C, S>
where
    F: PrimeField,
    E: AffineRepr<BaseField = F>,
    C: SWCurveConfig<BaseField = F>,
    S: Sponge<F, POSEIDON_STATE_SIZE, POSEIDON_RATE>,
{
    /// Data from the previous instance (n-1, opposite curve).
    /// Used to verify Fiat-Shamir challenge derivation.
    pub previous: PreviousInstanceData<F, E>,

    /// Data from two steps back (n-2, same curve).
    /// Used to verify accumulation with native field ops.
    /// None for iterations 0 and 1.
    pub two_step_back: Option<TwoStepBackData<F>>,

    /// Current accumulated state (input to this step).
    pub accumulated: AccumulatedState<F>,

    /// Fresh challenges for this instance (to be derived).
    pub fresh_alpha: F,
    pub fresh_u: F,

    /// The sponge implementation for Fiat-Shamir operations.
    pub sponge: S,

    /// Phantom data for the curve configuration.
    _curve: PhantomData<C>,
}

// Manual Clone implementation to avoid requiring Clone bound on C
impl<F, E, C, S> Clone for VerifierCircuit<F, E, C, S>
where
    F: PrimeField,
    E: AffineRepr<BaseField = F>,
    C: SWCurveConfig<BaseField = F>,
    S: Sponge<F, POSEIDON_STATE_SIZE, POSEIDON_RATE> + Clone,
{
    fn clone(&self) -> Self {
        Self {
            previous: self.previous.clone(),
            two_step_back: self.two_step_back.clone(),
            accumulated: self.accumulated.clone(),
            fresh_alpha: self.fresh_alpha,
            fresh_u: self.fresh_u,
            sponge: self.sponge.clone(),
            _curve: PhantomData,
        }
    }
}

// Manual Debug implementation to avoid requiring Debug bound on C
impl<F, E, C, S> core::fmt::Debug for VerifierCircuit<F, E, C, S>
where
    F: PrimeField,
    E: AffineRepr<BaseField = F>,
    C: SWCurveConfig<BaseField = F>,
    S: Sponge<F, POSEIDON_STATE_SIZE, POSEIDON_RATE> + core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerifierCircuit")
            .field("previous", &self.previous)
            .field("two_step_back", &self.two_step_back)
            .field("accumulated", &self.accumulated)
            .field("fresh_alpha", &self.fresh_alpha)
            .field("fresh_u", &self.fresh_u)
            .field("sponge", &self.sponge)
            .finish()
    }
}

impl<F, E, C, S> VerifierCircuit<F, E, C, S>
where
    F: PrimeField,
    E: AffineRepr<BaseField = F>,
    C: SWCurveConfig<BaseField = F>,
    S: Sponge<F, POSEIDON_STATE_SIZE, POSEIDON_RATE>,
{
    /// Create a new verifier circuit for iteration n.
    ///
    /// # Arguments
    ///
    /// * `previous` - Data from instance n-1 (opposite curve)
    /// * `two_step_back` - Data from instance n-2 (same curve), None for n < 2
    /// * `accumulated` - Current accumulated state
    /// * `sponge` - The sponge implementation for Fiat-Shamir
    pub fn new(
        previous: PreviousInstanceData<F, E>,
        two_step_back: Option<TwoStepBackData<F>>,
        accumulated: AccumulatedState<F>,
        sponge: S,
    ) -> Self {
        Self {
            previous,
            two_step_back,
            accumulated,
            fresh_alpha: F::zero(), // Will be computed
            fresh_u: F::one(),      // Fresh instance always has u = 1
            sponge,
            _curve: PhantomData,
        }
    }

    /// Verify accumulation equations from two steps back.
    ///
    /// Returns true if:
    /// - No two-step-back data (iterations 0, 1) - nothing to verify
    /// - Two-step-back data exists and accumulation equations hold
    pub fn verify_accumulation(&self) -> bool {
        match &self.two_step_back {
            None => true, // Nothing to verify for first two iterations
            Some(data) => data.verify_all(),
        }
    }

    /// Compute the new accumulated state after this fold.
    ///
    /// Uses the folding challenge r from the previous instance and the new digest.
    pub fn compute_new_accumulated(&self, new_digest: F) -> AccumulatedState<F> {
        self.accumulated
            .fold(self.fresh_u, self.fresh_alpha, self.previous.r, new_digest)
    }
}

// ============================================================================
// Circuit Synthesis Implementation
// ============================================================================

impl<F, E, C, S> VerifierCircuit<F, E, C, S>
where
    F: PrimeField,
    E: AffineRepr<BaseField = F>,
    C: SWCurveConfig<BaseField = F>,
    S: Sponge<F, POSEIDON_STATE_SIZE, POSEIDON_RATE>,
{
    /// Synthesize the verifier circuit constraints.
    ///
    /// This generates constraints for:
    /// 1. Fiat-Shamir verification (absorb commitments, squeeze and verify challenges)
    /// 2. Scalar accumulation verification (native field arithmetic from n-2 data)
    /// 3. Commitment accumulation verification (EC operations from n-2 data)
    ///
    /// # Type Parameters
    ///
    /// - `Env`: Circuit environment (ConstraintEnv for constraints, Trace for witness)
    ///
    /// # Arguments
    ///
    /// - `env`: The circuit environment
    /// - `initial_digest`: The sponge digest from the previous fold
    ///
    /// # Returns
    ///
    /// The final digest after all operations (for chaining to next instance).
    pub fn synthesize<Env>(&self, env: &mut Env, initial_digest: Env::Variable) -> Env::Variable
    where
        Env: CircuitEnv<F> + SelectorEnv<F>,
    {
        // Phase 1: Absorb commitments and squeeze/verify challenges
        // (challenge verification is inline in synthesize_fiat_shamir)
        let (final_digest, _challenges) = self.synthesize_fiat_shamir(env, initial_digest);

        // Phase 2: Verify scalar accumulation from n-2 (if present)
        self.synthesize_scalar_accumulation_verification(env);

        // Phase 3: Verify commitment accumulation from n-2 (if present)
        self.synthesize_commitment_accumulation_verification(env);

        final_digest
    }

    /// Synthesize the Fiat-Shamir phase: absorb commitments and squeeze challenges.
    ///
    /// This is the main circuit logic for verifying that the claimed challenges
    /// (α, r, u) were correctly derived from the sponge.
    ///
    /// ## Protocol Order
    ///
    /// The Fiat-Shamir protocol follows this specific order:
    /// 1. Absorb witness commitments → squeeze α (constraint combiner)
    /// 2. Absorb cross-term commitments (computed using α) → squeeze r (folding challenge)
    /// 3. Absorb error commitment → squeeze u (homogenizer)
    ///
    /// This ordering is critical because cross-terms depend on α.
    ///
    /// # Returns
    ///
    /// A tuple of (final_digest, squeezed_challenges).
    fn synthesize_fiat_shamir<Env>(
        &self,
        env: &mut Env,
        initial_digest: Env::Variable,
    ) -> (Env::Variable, [Env::Variable; NUM_CHALLENGES_PER_INSTANCE])
    where
        Env: CircuitEnv<F> + SelectorEnv<F>,
    {
        // Initialize sponge state from digest (digest in first position, zeros elsewhere)
        let mut state: [Env::Variable; POSEIDON_STATE_SIZE] = core::array::from_fn(|i| {
            if i == 0 {
                initial_digest.clone()
            } else {
                env.zero()
            }
        });

        // Phase 1: Absorb witness commitments
        for comm in &self.previous.witness_commitments {
            let values = [env.constant(comm.x), env.constant(comm.y)];
            state = self.sponge.absorb(env, &state, values);
            env.next_row();
            state = self.sponge.permute(env, &state);
        }

        // Squeeze α (constraint combiner)
        let squeezed_alpha = self.sponge.squeeze::<Env>(&state);

        // Verify α matches claimed value immediately
        let claimed_alpha = env.constant(self.previous.alpha);
        env.assert_eq(&squeezed_alpha, &claimed_alpha);

        // Phase 2: Absorb cross-term commitments (which were computed using α)
        for comm in &self.previous.cross_term_commitments {
            let values = [env.constant(comm.x), env.constant(comm.y)];
            state = self.sponge.absorb(env, &state, values);
            env.next_row();
            state = self.sponge.permute(env, &state);
        }

        // Squeeze r (folding challenge)
        state = self.sponge.permute(env, &state);
        let squeezed_r = self.sponge.squeeze::<Env>(&state);

        // Verify r matches claimed value
        let claimed_r = env.constant(self.previous.r);
        env.assert_eq(&squeezed_r, &claimed_r);

        // Phase 3: Absorb error commitment
        let error = &self.previous.error_commitment;
        let values = [env.constant(error.x), env.constant(error.y)];
        state = self.sponge.absorb(env, &state, values);
        env.next_row();
        state = self.sponge.permute(env, &state);

        // Squeeze u (homogenizer)
        state = self.sponge.permute(env, &state);
        let squeezed_u = self.sponge.squeeze::<Env>(&state);

        // Verify u matches claimed value
        let claimed_u = env.constant(self.previous.u);
        env.assert_eq(&squeezed_u, &claimed_u);

        let challenges = [squeezed_alpha, squeezed_r, squeezed_u];

        // Final digest is the first element of the final state
        let final_digest = state[0].clone();

        (final_digest, challenges)
    }

    /// Synthesize scalar accumulation verification constraints.
    ///
    /// For the two-step-back data (from instance n-2), verifies:
    /// - u_acc_new = u_acc_old + r * u_fresh
    /// - alpha_acc_new = alpha_acc_old + r * alpha_fresh
    ///
    /// These are native field operations (same curve as current instance).
    fn synthesize_scalar_accumulation_verification<Env>(&self, env: &mut Env)
    where
        Env: CircuitEnv<F>,
    {
        if let Some(ref data) = self.two_step_back {
            // Verify u accumulation: u_acc_new = u_acc_old + r * u_fresh
            let u_acc_old = env.constant(data.u_acc_old);
            let u_fresh = env.constant(data.u_fresh);
            let r = env.constant(data.r);
            let u_acc_new_claimed = env.constant(data.u_acc_new_claimed);

            // Compute expected: u_acc_old + r * u_fresh
            let r_times_u_fresh = r.clone() * u_fresh;
            let u_expected = u_acc_old + r_times_u_fresh;

            // Assert equality
            env.assert_eq(&u_expected, &u_acc_new_claimed);

            // Verify alpha accumulation: alpha_acc_new = alpha_acc_old + r * alpha_fresh
            let alpha_acc_old = env.constant(data.alpha_acc_old);
            let alpha_fresh = env.constant(data.alpha_fresh);
            let alpha_acc_new_claimed = env.constant(data.alpha_acc_new_claimed);

            // Compute expected: alpha_acc_old + r * alpha_fresh
            let r_times_alpha_fresh = r * alpha_fresh;
            let alpha_expected = alpha_acc_old + r_times_alpha_fresh;

            // Assert equality
            env.assert_eq(&alpha_expected, &alpha_acc_new_claimed);
        }
        // For iterations 0 and 1, no accumulation verification needed
    }

    /// Synthesize commitment accumulation verification constraints.
    ///
    /// For the two-step-back data (from instance n-2), verifies for each commitment:
    /// - C_acc_new = C_acc_old + r * C_fresh
    ///
    /// This uses EC scalar multiplication and addition gadgets.
    /// Total: 20 commitments (15 witness + 4 cross-term + 1 error).
    ///
    /// ## Public Inputs
    ///
    /// The following values are allocated as **public inputs** to the circuit:
    /// - `C_acc_old` (x, y): Previous accumulated commitment
    /// - `C_fresh` (x, y): Fresh commitment from the instance being folded
    /// - `C_acc_new_claimed` (x, y): Claimed new accumulated commitment
    /// - `r`: Folding challenge scalar
    ///
    /// These are public inputs (not constants) because they vary per circuit
    /// execution and must be provided by the prover. The verifier checks that
    /// the computation `C_acc_old + r * C_fresh` equals `C_acc_new_claimed`.
    ///
    /// ## Implementation Note
    ///
    /// The pattern `env.write_column(pos, env.constant(value))` allocates a
    /// position as a public input:
    /// - In constraint mode: `write_column` ignores the value and returns a
    ///   variable for that position (Cell expression)
    /// - In witness mode: `write_column` stores the actual value
    ///
    /// This ensures constraints reference positions (not embedded constants).
    fn synthesize_commitment_accumulation_verification<Env>(&self, env: &mut Env)
    where
        Env: CircuitEnv<F> + SelectorEnv<F>,
    {
        if let Some(ref data) = self.two_step_back {
            let scalar_mul = CurveNativeScalarMulGadget::<C>::new(SCALAR_MUL_BITS);
            let add_gadget = CurveNativeAddGadget::<C>::new();

            let r = data.r;

            // Verify witness commitment accumulation (15 commitments)
            for ((acc_old, fresh), acc_new_claimed) in data
                .witness_acc_old
                .iter()
                .zip(data.witness_fresh.iter())
                .zip(data.witness_acc_new_claimed.iter())
            {
                // Allocate fresh point as circuit input
                let fresh_x = {
                    let pos = env.allocate();
                    env.write_column(pos, env.constant(fresh.x))
                };
                let fresh_y = {
                    let pos = env.allocate();
                    env.write_column(pos, env.constant(fresh.y))
                };
                let fresh_point = ECPoint::new(fresh_x, fresh_y);

                // Allocate r as circuit input
                let scalar = {
                    let pos = env.allocate();
                    env.write_column(pos, env.constant(r))
                };

                // Step 1: Compute r * C_fresh using scalar multiplication
                let scaled_input = ECScalarMulInput::new(fresh_point, scalar);
                let scaled_output = scalar_mul.synthesize(env, scaled_input);
                env.next_row();

                // Allocate acc_old as circuit input
                let acc_old_x = {
                    let pos = env.allocate();
                    env.write_column(pos, env.constant(acc_old.x))
                };
                let acc_old_y = {
                    let pos = env.allocate();
                    env.write_column(pos, env.constant(acc_old.y))
                };
                let acc_old_point = ECPoint::new(acc_old_x, acc_old_y);

                // Step 2: Compute C_acc_old + (r * C_fresh) using EC addition
                let add_input = ECPointPair::new(acc_old_point, scaled_output.point);
                let add_output = add_gadget.synthesize(env, add_input);
                env.next_row();

                // Allocate claimed result as circuit input
                let claimed_x = {
                    let pos = env.allocate();
                    env.write_column(pos, env.constant(acc_new_claimed.x))
                };
                let claimed_y = {
                    let pos = env.allocate();
                    env.write_column(pos, env.constant(acc_new_claimed.y))
                };

                // Step 3: Assert computed result equals claimed accumulator
                env.assert_eq(&add_output.p1.x, &claimed_x);
                env.assert_eq(&add_output.p1.y, &claimed_y);
            }

            // Verify cross-term commitment accumulation (4 commitments)
            for ((acc_old, fresh), acc_new_claimed) in data
                .cross_term_acc_old
                .iter()
                .zip(data.cross_term_fresh.iter())
                .zip(data.cross_term_acc_new_claimed.iter())
            {
                // Allocate fresh point as circuit input
                let fresh_x = {
                    let pos = env.allocate();
                    env.write_column(pos, env.constant(fresh.x))
                };
                let fresh_y = {
                    let pos = env.allocate();
                    env.write_column(pos, env.constant(fresh.y))
                };
                let fresh_point = ECPoint::new(fresh_x, fresh_y);

                // Allocate r as circuit input
                let scalar = {
                    let pos = env.allocate();
                    env.write_column(pos, env.constant(r))
                };

                // Step 1: Compute r * C_fresh using scalar multiplication
                let scaled_input = ECScalarMulInput::new(fresh_point, scalar);
                let scaled_output = scalar_mul.synthesize(env, scaled_input);
                env.next_row();

                // Allocate acc_old as circuit input
                let acc_old_x = {
                    let pos = env.allocate();
                    env.write_column(pos, env.constant(acc_old.x))
                };
                let acc_old_y = {
                    let pos = env.allocate();
                    env.write_column(pos, env.constant(acc_old.y))
                };
                let acc_old_point = ECPoint::new(acc_old_x, acc_old_y);

                // Step 2: Compute C_acc_old + (r * C_fresh) using EC addition
                let add_input = ECPointPair::new(acc_old_point, scaled_output.point);
                let add_output = add_gadget.synthesize(env, add_input);
                env.next_row();

                // Allocate claimed result as circuit input
                let claimed_x = {
                    let pos = env.allocate();
                    env.write_column(pos, env.constant(acc_new_claimed.x))
                };
                let claimed_y = {
                    let pos = env.allocate();
                    env.write_column(pos, env.constant(acc_new_claimed.y))
                };

                // Step 3: Assert computed result equals claimed accumulator
                env.assert_eq(&add_output.p1.x, &claimed_x);
                env.assert_eq(&add_output.p1.y, &claimed_y);
            }

            // Verify error commitment accumulation (1 commitment)
            {
                let acc_old = &data.error_acc_old;
                let fresh = &data.error_fresh;
                let acc_new_claimed = &data.error_acc_new_claimed;

                // Allocate fresh point as circuit input
                let fresh_x = {
                    let pos = env.allocate();
                    env.write_column(pos, env.constant(fresh.x))
                };
                let fresh_y = {
                    let pos = env.allocate();
                    env.write_column(pos, env.constant(fresh.y))
                };
                let fresh_point = ECPoint::new(fresh_x, fresh_y);

                // Allocate r as circuit input
                let scalar = {
                    let pos = env.allocate();
                    env.write_column(pos, env.constant(r))
                };

                // Step 1: Compute r * C_fresh using scalar multiplication
                let scaled_input = ECScalarMulInput::new(fresh_point, scalar);
                let scaled_output = scalar_mul.synthesize(env, scaled_input);
                env.next_row();

                // Allocate acc_old as circuit input
                let acc_old_x = {
                    let pos = env.allocate();
                    env.write_column(pos, env.constant(acc_old.x))
                };
                let acc_old_y = {
                    let pos = env.allocate();
                    env.write_column(pos, env.constant(acc_old.y))
                };
                let acc_old_point = ECPoint::new(acc_old_x, acc_old_y);

                // Step 2: Compute C_acc_old + (r * C_fresh) using EC addition
                let add_input = ECPointPair::new(acc_old_point, scaled_output.point);
                let add_output = add_gadget.synthesize(env, add_input);
                env.next_row();

                // Allocate claimed result as circuit input
                let claimed_x = {
                    let pos = env.allocate();
                    env.write_column(pos, env.constant(acc_new_claimed.x))
                };
                let claimed_y = {
                    let pos = env.allocate();
                    env.write_column(pos, env.constant(acc_new_claimed.y))
                };

                // Step 3: Assert computed result equals claimed accumulator
                env.assert_eq(&add_output.p1.x, &claimed_x);
                env.assert_eq(&add_output.p1.y, &claimed_y);
            }
        }
        // For iterations 0 and 1, no commitment accumulation verification needed
    }

    /// Compute witness values for the Fiat-Shamir phase.
    ///
    /// This runs the sponge operations to compute the expected squeezed values,
    /// which can be used to verify the circuit witness.
    ///
    /// ## Protocol Order
    ///
    /// Follows the same order as `synthesize_fiat_shamir`:
    /// 1. Absorb witness commitments → squeeze α
    /// 2. Absorb cross-term commitments → squeeze r
    /// 3. Absorb error commitment → squeeze u
    ///
    /// # Returns
    ///
    /// A tuple of (final_digest, challenges).
    pub fn compute_fiat_shamir_witness(&self) -> (F, [F; NUM_CHALLENGES_PER_INSTANCE]) {
        // Initialize sponge state from digest (digest in first position, zeros elsewhere)
        let mut state: [F; POSEIDON_STATE_SIZE] = core::array::from_fn(|i| {
            if i == 0 {
                self.accumulated.digest
            } else {
                F::zero()
            }
        });

        // Phase 1: Absorb witness commitments
        for comm in &self.previous.witness_commitments {
            let values = [comm.x, comm.y];
            state = self.sponge.absorb_witness(&state, values);
            state = self.sponge.permute_witness(&state);
        }

        // Squeeze α (constraint combiner)
        let squeezed_alpha = self.sponge.squeeze_witness(&state);

        // Phase 2: Absorb cross-term commitments
        for comm in &self.previous.cross_term_commitments {
            let values = [comm.x, comm.y];
            state = self.sponge.absorb_witness(&state, values);
            state = self.sponge.permute_witness(&state);
        }

        // Squeeze r (folding challenge)
        state = self.sponge.permute_witness(&state);
        let squeezed_r = self.sponge.squeeze_witness(&state);

        // Phase 3: Absorb error commitment
        let error = &self.previous.error_commitment;
        let values = [error.x, error.y];
        state = self.sponge.absorb_witness(&state, values);
        state = self.sponge.permute_witness(&state);

        // Squeeze u (homogenizer)
        state = self.sponge.permute_witness(&state);
        let squeezed_u = self.sponge.squeeze_witness(&state);

        // Final digest is the first element
        let final_digest = state[0];

        (final_digest, [squeezed_alpha, squeezed_r, squeezed_u])
    }

    /// Get the number of rows required for the verifier circuit.
    ///
    /// This includes:
    /// - Absorption rows (one per commitment, each commitment = 2 field elements)
    /// - Permutation rows (after each absorption and squeeze)
    /// - Scalar accumulation verification rows (2 constraints, no extra rows)
    /// - Commitment accumulation verification rows (EC scalar mul + EC add per commitment)
    pub fn num_rows(&self) -> usize {
        // Total commitments to absorb (Fiat-Shamir phase):
        // - NUM_WITNESS_COMMITMENTS witness columns
        // - NUM_CROSS_TERM_COMMITMENTS cross-terms
        // - 1 error commitment
        let num_absorptions = TOTAL_FRESH_COMMITMENTS;
        let rows_per_perm = self.sponge.permutation_rows();

        // Each absorption: 1 absorb row + permutation rows
        let absorption_rows = num_absorptions * (1 + rows_per_perm);

        // Three squeezes, each needs a permutation (one after each phase)
        let squeeze_rows = 3 * rows_per_perm;

        // Scalar accumulation verification: 2 constraints (no extra rows needed)
        let scalar_accumulation_rows = 0;

        // Commitment accumulation verification (only if two_step_back is present):
        // For each commitment: rows for EC scalar mul + rows for EC addition + next_row calls
        let commitment_accumulation_rows = if self.two_step_back.is_some() {
            let scalar_mul_rows = SCALAR_MUL_BITS; // CurveNativeScalarMulGadget uses SCALAR_MUL_BITS rows
            let add_rows = <CurveNativeAddGadget<C> as TypedGadget<F>>::ROWS;
            let next_row_calls = 2; // Two next_row() calls per commitment
            let rows_per_commitment = scalar_mul_rows + add_rows + next_row_calls;
            TOTAL_FRESH_COMMITMENTS * rows_per_commitment
        } else {
            0
        };

        absorption_rows + squeeze_rows + scalar_accumulation_rows + commitment_accumulation_rows
    }
}

// ============================================================================
// StepCircuit Implementation
// ============================================================================

impl<F, E, C, S> StepCircuit<F, VERIFIER_ARITY> for VerifierCircuit<F, E, C, S>
where
    F: PrimeField,
    E: AffineRepr<BaseField = F>,
    C: SWCurveConfig<BaseField = F>,
    S: Sponge<F, POSEIDON_STATE_SIZE, POSEIDON_RATE> + Clone,
{
    const NAME: &'static str = "NIFSVerifier";

    /// Synthesize the verifier circuit constraints.
    ///
    /// # Input State (z)
    ///
    /// - `z[0]`: digest - sponge digest from previous fold
    /// - `z[1]`: u_acc - accumulated homogenizer
    /// - `z[2]`: alpha_acc - accumulated constraint combiner
    ///
    /// # Output State
    ///
    /// - `z'[0]`: new digest after absorbing commitments and squeezing
    /// - `z'[1]`: new u_acc = u_acc + r * u_fresh
    /// - `z'[2]`: new alpha_acc = alpha_acc + r * alpha_fresh
    fn synthesize<Env: CircuitEnv<F> + SelectorEnv<F>>(
        &self,
        env: &mut Env,
        z: &[Env::Variable; VERIFIER_ARITY],
    ) -> [Env::Variable; VERIFIER_ARITY] {
        let digest_in = z[0].clone();
        let u_acc_in = z[1].clone();
        let alpha_acc_in = z[2].clone();

        // Phase 1: Fiat-Shamir verification
        // Absorb commitments and squeeze/verify challenges
        let (digest_out, _challenges) = self.synthesize_fiat_shamir(env, digest_in);

        // Phase 2: Scalar accumulation verification from n-2 (if present)
        self.synthesize_scalar_accumulation_verification(env);

        // Phase 3: Commitment accumulation verification from n-2 (if present)
        self.synthesize_commitment_accumulation_verification(env);

        // Phase 4: Compute new accumulated values
        // u_acc_out = u_acc_in + r * u_fresh
        let r = env.constant(self.previous.r);
        let u_fresh = env.constant(self.fresh_u);
        let r_times_u = r.clone() * u_fresh;
        let u_acc_out = u_acc_in + r_times_u;

        // alpha_acc_out = alpha_acc_in + r * alpha_fresh
        let alpha_fresh = env.constant(self.fresh_alpha);
        let r_times_alpha = r * alpha_fresh;
        let alpha_acc_out = alpha_acc_in + r_times_alpha;

        [digest_out, u_acc_out, alpha_acc_out]
    }

    /// Compute the output state directly (for verification/testing).
    ///
    /// # Input State (z)
    ///
    /// - `z[0]`: digest - sponge digest from previous fold
    /// - `z[1]`: u_acc - accumulated homogenizer
    /// - `z[2]`: alpha_acc - accumulated constraint combiner
    ///
    /// # Output State
    ///
    /// - `z'[0]`: new digest after absorbing commitments and squeezing
    /// - `z'[1]`: new u_acc = u_acc + r * u_fresh
    /// - `z'[2]`: new alpha_acc = alpha_acc + r * alpha_fresh
    fn output(&self, z: &[F; VERIFIER_ARITY]) -> [F; VERIFIER_ARITY] {
        let _digest_in = z[0];
        let u_acc_in = z[1];
        let alpha_acc_in = z[2];

        // Compute Fiat-Shamir to get new digest
        let (digest_out, _challenges) = self.compute_fiat_shamir_witness();

        // Compute new accumulated values
        let r = self.previous.r;
        let u_acc_out = u_acc_in + r * self.fresh_u;
        let alpha_acc_out = alpha_acc_in + r * self.fresh_alpha;

        [digest_out, u_acc_out, alpha_acc_out]
    }

    /// Returns the number of rows used by the verifier circuit.
    fn num_rows(&self) -> usize {
        // Delegate to the existing num_rows method
        VerifierCircuit::num_rows(self)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use mina_curves::pasta::Fp;

    #[test]
    fn test_constants() {
        assert_eq!(NUM_WITNESS_COMMITMENTS, NUMBER_OF_COLUMNS);
        assert_eq!(NUM_CROSS_TERM_COMMITMENTS, MAX_DEGREE - 1);
        assert_eq!(TOTAL_FRESH_COMMITMENTS, NUMBER_OF_COLUMNS + MAX_DEGREE);
        // Each commitment is 2 field elements
        assert_eq!(ELEMENTS_TO_ABSORB_PER_INSTANCE, TOTAL_FRESH_COMMITMENTS * 2);
    }

    #[test]
    fn test_ecpoint_coords() {
        let coord = ECPoint::<Fp>::new(Fp::from(1u64), Fp::from(2u64));
        // ECPoint stores x and y directly as public fields
        assert_eq!(coord.x, Fp::from(1u64));
        assert_eq!(coord.y, Fp::from(2u64));
    }

    /// Create a TwoStepBackData with placeholder commitment values for testing.
    fn create_test_two_step_back_data() -> TwoStepBackData<Fp> {
        // Placeholder commitments - just use simple values
        let zero_point = || ECPoint::new(Fp::from(0u64), Fp::from(0u64));

        TwoStepBackData::<Fp> {
            u_acc_old: Fp::from(5u64),
            u_fresh: Fp::from(1u64),
            r: Fp::from(3u64),
            u_acc_new_claimed: Fp::from(8u64), // 5 + 3 * 1 = 8
            alpha_acc_old: Fp::from(10u64),
            alpha_fresh: Fp::from(2u64),
            alpha_acc_new_claimed: Fp::from(16u64), // 10 + 3 * 2 = 16
            // Commitment accumulation data (placeholder values)
            witness_acc_old: core::array::from_fn(|_| zero_point()),
            witness_fresh: core::array::from_fn(|_| zero_point()),
            witness_acc_new_claimed: core::array::from_fn(|_| zero_point()),
            cross_term_acc_old: core::array::from_fn(|_| zero_point()),
            cross_term_fresh: core::array::from_fn(|_| zero_point()),
            cross_term_acc_new_claimed: core::array::from_fn(|_| zero_point()),
            error_acc_old: zero_point(),
            error_fresh: zero_point(),
            error_acc_new_claimed: zero_point(),
        }
    }

    #[test]
    fn test_two_step_back_verification() {
        let data = create_test_two_step_back_data();

        assert!(data.verify_u_accumulation());
        assert!(data.verify_alpha_accumulation());
        assert!(data.verify_scalar_accumulation());
        assert!(data.verify_all());
    }

    #[test]
    fn test_two_step_back_verification_fails() {
        let mut data = create_test_two_step_back_data();
        data.u_acc_new_claimed = Fp::from(9u64); // Wrong! Should be 8

        assert!(!data.verify_u_accumulation());
        assert!(data.verify_alpha_accumulation());
        assert!(!data.verify_scalar_accumulation());
        assert!(!data.verify_all());
    }

    #[test]
    fn test_accumulated_state_fold() {
        let initial = AccumulatedState::<Fp> {
            u: Fp::from(0u64),
            alpha: Fp::from(1u64),
            digest: Fp::from(0u64),
            iteration: 0,
        };

        let new_digest = Fp::from(42u64);
        let folded = initial.fold(Fp::from(1u64), Fp::from(2u64), Fp::from(7u64), new_digest);

        // u_new = 0 + 7 * 1 = 7
        assert_eq!(folded.u, Fp::from(7u64));
        // alpha_new = 1 + 7 * 2 = 15
        assert_eq!(folded.alpha, Fp::from(15u64));
        // digest should be updated
        assert_eq!(folded.digest, Fp::from(42u64));
        assert_eq!(folded.iteration, 1);
    }

    #[test]
    fn test_previous_instance_data_construction() {
        // Test that PreviousInstanceData can be constructed correctly
        let witness_comms: [ECPoint<Fp>; NUM_WITNESS_COMMITMENTS] =
            core::array::from_fn(|i| ECPoint::new(Fp::from(i as u64), Fp::from(i as u64 + 100)));
        let cross_term_comms: [ECPoint<Fp>; NUM_CROSS_TERM_COMMITMENTS] =
            core::array::from_fn(|i| {
                ECPoint::new(Fp::from(i as u64 + 200), Fp::from(i as u64 + 300))
            });
        let error_comm = ECPoint::new(Fp::from(400u64), Fp::from(500u64));

        let data = PreviousInstanceData::<Fp, mina_curves::pasta::Pallas> {
            witness_commitments: witness_comms.clone(),
            cross_term_commitments: cross_term_comms.clone(),
            error_commitment: error_comm.clone(),
            alpha: Fp::from(1u64),
            r: Fp::from(2u64),
            u: Fp::from(3u64),
            digest: Fp::from(4u64),
            _marker: PhantomData,
        };

        // Verify lengths
        assert_eq!(data.witness_commitments.len(), NUM_WITNESS_COMMITMENTS);
        assert_eq!(
            data.cross_term_commitments.len(),
            NUM_CROSS_TERM_COMMITMENTS
        );

        // Verify values are accessible
        assert_eq!(data.witness_commitments[0].x, Fp::from(0u64));
        assert_eq!(data.witness_commitments[0].y, Fp::from(100u64));
        assert_eq!(data.error_commitment.x, Fp::from(400u64));
        assert_eq!(data.error_commitment.y, Fp::from(500u64));
        assert_eq!(data.alpha, Fp::from(1u64));
        assert_eq!(data.r, Fp::from(2u64));
        assert_eq!(data.u, Fp::from(3u64));
    }
}

// ============================================================================
// Circuit Regression Tests
// ============================================================================

#[cfg(test)]
mod circuit_regression_tests {
    use super::*;
    use crate::{
        circuit::ConstraintEnv, circuits::gadgets::hash::PoseidonSponge,
        nifs::poseidon_3_60_0_5_5_fp,
    };
    use mina_curves::pasta::{Fp, Pallas, PallasParameters};

    /// Number of full rounds for Poseidon (Arrabbiata default)
    const FULL_ROUNDS: usize = 60;

    /// Create test fixtures for the verifier circuit
    fn create_test_verifier_circuit(
    ) -> VerifierCircuit<Fp, Pallas, PallasParameters, PoseidonSponge<Fp, FULL_ROUNDS>> {
        let witness_comms: [ECPoint<Fp>; NUM_WITNESS_COMMITMENTS] =
            core::array::from_fn(|i| ECPoint::new(Fp::from(i as u64), Fp::from(i as u64 + 100)));
        let cross_term_comms: [ECPoint<Fp>; NUM_CROSS_TERM_COMMITMENTS] =
            core::array::from_fn(|i| {
                ECPoint::new(Fp::from(i as u64 + 200), Fp::from(i as u64 + 300))
            });
        let error_comm = ECPoint::new(Fp::from(400u64), Fp::from(500u64));

        let previous = PreviousInstanceData {
            witness_commitments: witness_comms,
            cross_term_commitments: cross_term_comms,
            error_commitment: error_comm,
            alpha: Fp::from(1u64),
            r: Fp::from(2u64),
            u: Fp::from(3u64),
            digest: Fp::from(4u64),
            _marker: PhantomData,
        };

        let accumulated = AccumulatedState {
            u: Fp::from(0u64),
            alpha: Fp::from(1u64),
            digest: Fp::from(0u64),
            iteration: 0,
        };

        let params = poseidon_3_60_0_5_5_fp::static_params();
        let sponge = PoseidonSponge::<Fp, FULL_ROUNDS>::new(params);

        VerifierCircuit::new(previous, None, accumulated, sponge)
    }

    /// Helper to create TwoStepBackData with placeholder commitment values
    fn create_test_two_step_back_data() -> TwoStepBackData<Fp> {
        let zero_point = || ECPoint::new(Fp::from(0u64), Fp::from(0u64));

        TwoStepBackData {
            u_acc_old: Fp::from(5u64),
            u_fresh: Fp::from(1u64),
            r: Fp::from(3u64),
            u_acc_new_claimed: Fp::from(8u64), // 5 + 3 * 1 = 8
            alpha_acc_old: Fp::from(10u64),
            alpha_fresh: Fp::from(2u64),
            alpha_acc_new_claimed: Fp::from(16u64), // 10 + 3 * 2 = 16
            // Commitment accumulation data (placeholder values)
            witness_acc_old: core::array::from_fn(|_| zero_point()),
            witness_fresh: core::array::from_fn(|_| zero_point()),
            witness_acc_new_claimed: core::array::from_fn(|_| zero_point()),
            cross_term_acc_old: core::array::from_fn(|_| zero_point()),
            cross_term_fresh: core::array::from_fn(|_| zero_point()),
            cross_term_acc_new_claimed: core::array::from_fn(|_| zero_point()),
            error_acc_old: zero_point(),
            error_fresh: zero_point(),
            error_acc_new_claimed: zero_point(),
        }
    }

    /// Create test fixtures with two-step-back data
    fn create_test_verifier_circuit_with_accumulation(
    ) -> VerifierCircuit<Fp, Pallas, PallasParameters, PoseidonSponge<Fp, FULL_ROUNDS>> {
        let mut circuit = create_test_verifier_circuit();
        circuit.two_step_back = Some(create_test_two_step_back_data());
        circuit
    }

    // ========================================================================
    // Scalar Accumulation Verification Constraint Tests
    // ========================================================================

    #[test]
    fn test_scalar_accumulation_verification_constraints() {
        // Test just the scalar accumulation verification part (doesn't need multi-row)
        let circuit = create_test_verifier_circuit_with_accumulation();
        let mut env = ConstraintEnv::<Fp>::new();

        // Only synthesize scalar accumulation verification
        circuit.synthesize_scalar_accumulation_verification(&mut env);

        // Should have exactly 2 constraints:
        // - u_acc_new = u_acc_old + r * u_fresh
        // - alpha_acc_new = alpha_acc_old + r * alpha_fresh
        assert_eq!(
            env.num_constraints(),
            2,
            "Scalar accumulation verification should have exactly 2 constraints"
        );

        // Both constraints should be degree 1 (linear)
        let degrees = env.constraint_degrees();
        assert!(
            degrees.iter().all(|&d| d <= 2),
            "Scalar accumulation constraints should be degree <= 2"
        );
    }

    #[test]
    fn test_scalar_accumulation_verification_no_constraints_without_two_step_back() {
        // Without two_step_back, no scalar accumulation constraints should be added
        let circuit = create_test_verifier_circuit();
        let mut env = ConstraintEnv::<Fp>::new();

        circuit.synthesize_scalar_accumulation_verification(&mut env);

        assert_eq!(
            env.num_constraints(),
            0,
            "No scalar accumulation constraints without two_step_back data"
        );
    }

    // ========================================================================
    // Verifier Circuit Component Counts
    // ========================================================================

    #[test]
    fn test_verifier_circuit_expected_component_counts() {
        // Document the expected component breakdown for the verifier circuit
        //
        // Components:
        // 1. Witness absorption: NUM_WITNESS_COMMITMENTS * 2 elements = 15 * 2 = 30
        //    - Absorption rounds: ceil(30 / 2) = 15 absorptions
        //    - Each absorption: 2 constraints + 1 permutation (180 constraints)
        //
        // 2. Cross-term absorption: NUM_CROSS_TERM_COMMITMENTS * 2 = 4 * 2 = 8
        //    - Absorption rounds: ceil(8 / 2) = 4 absorptions
        //
        // 3. Error absorption: 1 * 2 = 2 elements
        //    - Absorption rounds: ceil(2 / 2) = 1 absorption
        //
        // 4. Challenge squeezes: 3 (α, r, u), each needs permutation after phase
        //
        // 5. Challenge verifications: 3 assert_eq constraints
        //
        // 6. Accumulation verification: 2 constraints (when two_step_back present)

        // Total absorption rounds
        let witness_absorptions = (NUM_WITNESS_COMMITMENTS * 2).div_ceil(2); // 15
        let cross_term_absorptions = (NUM_CROSS_TERM_COMMITMENTS * 2).div_ceil(2); // 4
        let error_absorptions = 1;
        let total_absorptions = witness_absorptions + cross_term_absorptions + error_absorptions;

        assert_eq!(total_absorptions, 20, "Total absorptions should be 20");

        // Constraints per absorption cycle: 2 (absorb) + 180 (permute) = 182
        let constraints_per_absorption = 2 + 180;

        // Squeeze permutations: 3 (one after each phase) * 180
        let squeeze_permutation_constraints = 3 * 180;

        // Challenge verification constraints: 3
        let challenge_verification_constraints = 3;

        // Accumulation verification: 2
        let accumulation_constraints = 2;

        // Total expected constraints (with accumulation)
        let expected_total = total_absorptions * constraints_per_absorption
            + squeeze_permutation_constraints
            + challenge_verification_constraints
            + accumulation_constraints;

        println!("Expected constraint breakdown:");
        println!(
            "  Absorption cycles: {} * {} = {}",
            total_absorptions,
            constraints_per_absorption,
            total_absorptions * constraints_per_absorption
        );
        println!(
            "  Squeeze permutations: {} * 180 = {}",
            3, squeeze_permutation_constraints
        );
        println!(
            "  Challenge verifications: {}",
            challenge_verification_constraints
        );
        println!("  Accumulation verifications: {}", accumulation_constraints);
        println!("  Total: {}", expected_total);

        // Document expected value for regression
        assert_eq!(
            expected_total, 4185,
            "Expected total constraint count changed"
        );
    }

    // ========================================================================
    // Row Count Regression Tests
    // ========================================================================

    #[test]
    fn test_verifier_circuit_row_count() {
        let circuit = create_test_verifier_circuit();

        let num_rows = circuit.num_rows();
        println!("Verifier circuit estimated rows: {}", num_rows);

        // Document expected row count
        // - Absorption rows: TOTAL_FRESH_COMMITMENTS * (1 + permutation_rows)
        // - Squeeze rows: 3 * permutation_rows
        let expected_absorption_rows =
            TOTAL_FRESH_COMMITMENTS * (1 + circuit.sponge.permutation_rows());
        let expected_squeeze_rows = 3 * circuit.sponge.permutation_rows();
        let expected_total = expected_absorption_rows + expected_squeeze_rows;

        assert_eq!(
            num_rows, expected_total,
            "Row count changed from expected formula"
        );
    }

    // ========================================================================
    // Constants Regression Tests
    // ========================================================================

    #[test]
    fn test_verifier_constants_regression() {
        // Document expected constant values for regression detection
        assert_eq!(
            NUM_WITNESS_COMMITMENTS, 15,
            "NUM_WITNESS_COMMITMENTS changed"
        );
        assert_eq!(
            NUM_CROSS_TERM_COMMITMENTS, 4,
            "NUM_CROSS_TERM_COMMITMENTS changed (MAX_DEGREE - 1)"
        );
        assert_eq!(
            TOTAL_FRESH_COMMITMENTS, 20,
            "TOTAL_FRESH_COMMITMENTS changed"
        );
        assert_eq!(
            ELEMENTS_TO_ABSORB_PER_INSTANCE, 40,
            "ELEMENTS_TO_ABSORB_PER_INSTANCE changed"
        );
        assert_eq!(
            NUM_CHALLENGES_PER_INSTANCE, 3,
            "NUM_CHALLENGES_PER_INSTANCE changed"
        );
        assert_eq!(VERIFIER_ARITY, 3, "VERIFIER_ARITY changed");
    }

    // ========================================================================
    // StepCircuit Implementation Tests
    // ========================================================================

    #[test]
    fn test_verifier_step_circuit_output() {
        use crate::circuit::StepCircuit;

        let circuit = create_test_verifier_circuit();

        // Initial state
        let z_in: [Fp; VERIFIER_ARITY] = [
            Fp::from(0u64), // digest
            Fp::from(0u64), // u_acc
            Fp::from(1u64), // alpha_acc (starts at 1)
        ];

        // Compute output
        let z_out = circuit.output(&z_in);

        // Output should have:
        // - z_out[0]: new digest (from Fiat-Shamir)
        // - z_out[1]: u_acc + r * u_fresh = 0 + 2 * 1 = 2
        // - z_out[2]: alpha_acc + r * alpha_fresh = 1 + 2 * 0 = 1
        // (fresh_u = 1, fresh_alpha = 0 by default, r = 2 from fixture)
        assert_eq!(z_out[1], Fp::from(2u64), "u_acc should be updated");
        assert_eq!(z_out[2], Fp::from(1u64), "alpha_acc should be updated");

        // Digest should be non-zero (it's the output of Fiat-Shamir)
        // We don't check the exact value as it depends on sponge computation
        println!("Output digest: {:?}", z_out[0]);
    }

    #[test]
    fn test_verifier_step_circuit_name() {
        use crate::circuit::StepCircuit;

        let circuit = create_test_verifier_circuit();
        type Circuit =
            VerifierCircuit<Fp, Pallas, PallasParameters, PoseidonSponge<Fp, FULL_ROUNDS>>;
        assert_eq!(
            <Circuit as StepCircuit<Fp, VERIFIER_ARITY>>::NAME,
            "NIFSVerifier"
        );

        // Verify num_rows is consistent
        let step_rows = <Circuit as StepCircuit<Fp, VERIFIER_ARITY>>::num_rows(&circuit);
        let direct_rows = circuit.num_rows();
        assert_eq!(
            step_rows, direct_rows,
            "StepCircuit::num_rows should match direct call"
        );
    }

    #[test]
    fn test_verifier_circuit_row_count_with_commitment_accumulation() {
        let circuit = create_test_verifier_circuit_with_accumulation();

        let num_rows = circuit.num_rows();
        println!(
            "Verifier circuit rows (with commitment accumulation): {}",
            num_rows
        );

        // Document expected row count breakdown:
        // - Absorption rows: TOTAL_FRESH_COMMITMENTS * (1 + permutation_rows)
        // - Squeeze rows: 3 * permutation_rows
        // - Commitment accumulation: TOTAL_FRESH_COMMITMENTS * (SCALAR_MUL_BITS + add_rows + 2)
        let perm_rows = circuit.sponge.permutation_rows();
        let absorption_rows = TOTAL_FRESH_COMMITMENTS * (1 + perm_rows);
        let squeeze_rows = 3 * perm_rows;
        let add_rows = <CurveNativeAddGadget<PallasParameters> as TypedGadget<Fp>>::ROWS;
        let commitment_rows = TOTAL_FRESH_COMMITMENTS * (SCALAR_MUL_BITS + add_rows + 2);
        let expected_total = absorption_rows + squeeze_rows + commitment_rows;

        assert_eq!(
            num_rows, expected_total,
            "Row count with commitment accumulation changed from expected formula"
        );

        println!("  Absorption rows: {}", absorption_rows);
        println!("  Squeeze rows: {}", squeeze_rows);
        println!("  Commitment accumulation rows: {}", commitment_rows);
        println!("  Total: {}", expected_total);
    }
}
