//! Data structures for Pickles proofs.
//!
//! Perhaps we can see things like that:
//!
//! ```ignore
//! step circuit  wrap circuit   step circuit   wrap circuit
//!         |      /       |     /        |    /       |
//!         v     /        v    /         v   /        v
//!      step proof <- wrap proof <- step proof <- wrap proof
//!                        |                           |
//!                        v                           v
//!                     verifier                   verifier
//! ```
//!
//! where a wrap proof is the [`PicklesProof`] type below.
//!
//! Each proof essentially performs 3 layer deep verifications.
//!
//! **Depth 1**: It verifies the previous proof given some hints
//! (the deferred values for the IOP, and the folded generators for the IPA proof).
//! For the verifier circuit of the wrapped step, the hints were exposed in its statement/public input,
//! but not in the statement of the wrap circuit (so you won't see them here).
//! For the wrap verifier circuit, the hints are exposed in the wrap proof in `statement.proof_state.deferred_values`
//!
//! **Depth 2**: It verifies the deferred values used in the previous verifier circuit
//! (the previous verifier circuit got them as hints, and exposed them in the public input).
//! The next step verifier circuit will verify the hints given to the wrap verifier circuit and exposed in `statement.proof_state.deferred_values`
//!
//! **Depth 3**: It accumulates the folded generators used two verifier circuits ago.
//! The accumulation is done on the verifier side and must match what was done on the prover side in the previous proof (see depth 2).
//! The step proof exposed that data in `statement.messages_for_next_step_proof`.
//! The wrap proof exposed that data in `statement.proof_state.messages_for_next_wrap_proof`.
//!

//
// The main proof
//

use ark_ec::AffineCurve;

use crate::circuits::polynomial::COLUMNS;

/// The proof produced by pickles.
pub struct PicklesProof<G, AppState, const N: usize>
where
    G: AffineCurve,
{
    /// The statement proven by the pickle proof (the public input).
    statement: Statement<G, AppState, N>,

    /// Evaluations from the wrapped step proof.
    prev_evals: Evaluations<G>,

    /// The actual kimchi proof.
    proof: KimchiProof<G>,
}

//
// The statement part
//

/// The statement proven by the pickle proof (the public input).
/// It is "minimal", in the sense that it is optimized for wire transport,
/// and does not contain values that can easily be recomputed by the verifier.
/// It can be expanded into another struct (TODO: link to struct),
/// which can then be unpacked as the public input to verify the proof.
pub struct Statement<G, AppState, const N: usize>
where
    G: AffineCurve,
{
    // Values used by the wrap proof to verify the step proof.
    proof_state: ProofState<G, N>,

    /// Data that came from the step proof
    /// (untouched by the wrap verifier)
    /// the wrap verifier actually just sees that as a hash
    // TODO: should really be called "messages_for_next_step_circuit"
    messages_for_next_step_proof: MessagesForNextStepProof<G, AppState, N>,
}

/// This data structure contains two messages for the next step circuit:
///
/// 1. the application data of the wrapped step circuit
///    (for obvious reason, the next step circuit might want to use the output of the previous step circuit)
/// 2. halo-hint stuff (see below)
///
/// The next step proof will have to perform the Halo accumulation on the verifier side
/// (matching the accumulation done by the wrap prover).
/// This is the Halo trick that needs to happen due to the hints that were given to the wrapped step circuit when verifying other wrap proofs.
/// Note that wrap proofs is plural because a step circuit can verify multiple proofs.
///
/// ```ignore
/// wrap proofs <- step <- wrap <- step
///                 ^        ^       ^
///                 |        |     VC will have to accumulate
///        halo hints given  |      the halo hints as well
///                          |
///                  the prover accumulated halo hints
/// ```
pub struct MessagesForNextStepProof<G, AppState, const N: usize>
where
    G: AffineCurve,
{
    /// The actual application data.
    app_state: AppState,

    /// The halo hints (commitments of polynomials)
    challenge_polynomial_commitments: Vec<G>,

    /// The challenges required to compute the evaluation of the halo polynomials.
    old_bulletproof_challenges: Vec<[G::ScalarField; N]>,
}

pub struct ProofState<G, const N: usize>
where
    G: AffineCurve,
{
    /// These are all the values that were given as hints to verify the previous step proof,
    /// within the wrap (verifier) circuit.
    deferred_values: DeferredValues<G::BaseField, N>,

    /// The digest of the transcript up until absorbing evaluations.
    /// Since evaluations are absorbed in
    // TODO: shouldn't we check digest after evaluations as well?
    sponge_digest_before_evaluations: G::ScalarField,

    /// Due to Halo, the next step prover, and the next wrap VC, will need to do the accumlation
    /// should really be called "messages_for_next_step_prover_and_wrap_circuit"
    messages_for_next_wrap_proof: MessagesForNextWrapProof<G, N>,
}

/// See the documentation on [`MessagesForNextStepProof`].
/// Similarly, the next wrap verifier circuit will have to accumulate the Halo hint
/// that were used in the verification of a step proof by the wrap circuit.
///     
/// ```ignore
/// step proof <- wrap <- step <- wrap
///                 ^        ^       ^
///                 |        |     VC will have to accumulate
///        halo hints given  |      the halo hint as well
///                          |
///                  the prover will accumulate a halo hint
/// ```
pub struct MessagesForNextWrapProof<G, const N: usize>
where
    G: AffineCurve,
{
    /// The halo hint (commitment of polynomial)
    challenge_polynomial_commitment: G,

    /// The challenges required to compute the evaluation of the polynomial.
    bulletproof_challenges: [G::ScalarField; N],
}

/// In the wrap verifier circuit, some data was hinted in order to verify the step proof.
/// As this hinted data still needs to be verified,
/// we need to pass both the hints and the data that is required to recompute the hints.
pub struct DeferredValues<F, const N: usize> {
    // the challenges used to verify the wrapped step proof
    plonk: Plonk<F>,

    // hints given to the wrap VC, computed from step evals
    // TODO: these can be recomputed by the verifier (circuit), they don't need to be here
    combined_inner_product: F,
    b: F,
    xi: F,

    /// These are the challenges in bulletproof needed to compute the b poly.
    bulletproof_challenges: [F; N],

    /// Information on the specific step circuit that was verifier by the wrap proof.
    branch_data: BranchData,
}

/// Challenges that were used during the verification of the step proof.
pub struct Plonk<F> {
    alpha: F,
    beta: F,
    gamma: F,
    zeta: F,
    join_combiner: Option<F>,
}

/// Some metadata on the step circuit that was verified by the wrap proof.
/// This is important as a wrap proof can choose which step circuit to verify,
/// from a list of verifier keys.
pub struct BranchData {
    /// We only support 0, 1, or 2 verification of proofs in a step circuit.
    proofs_verified: u8,

    /// Needed for computing the vanishing polynomial
    // TODO: and perhaps zeta^n no?
    domain_log2: u32,
}

//
// Kimchi proof part
//

// TODO: can we just reuse the kimchi evaluations type?
pub struct Evaluations<F> {
    public_input: F,
    w: [F; COLUMNS],
    coefficients: [F; COLUMNS],
    z: F,
    s: [F; 6],
    generic_selector: F,
    poseidon_selector: F,
    lookup: Option<()>,
    ft_eval1: F,
}

// TODO: can we just reuse the kimchi proof type?
pub struct KimchiProof<G>
where
    G: AffineCurve,
{
    messages: Messages<G>,
    openings: Openings<G>,
}

// TODO: same
pub struct Messages<G>
where
    G: AffineCurve,
{
    w_comm: [G; COLUMNS],
    z_comm: G,
    t_comm: G,
    lookup: Option<()>,
}

// TODO: same
pub struct Openings<G>
where
    G: AffineCurve,
{
    proof: IPAProof<G>,
    evals: Evaluations<G::ScalarField>,
}

// TODO: same
pub struct IPAProof<G>
where
    G: AffineCurve,
{
    lr: Vec<(G, G)>,
    z_1: G::ScalarField,
    z_2: G::ScalarField,
    delta: G,
    challenge_polynomial_commitment: G,
}
