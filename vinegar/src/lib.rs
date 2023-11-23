#![allow(dead_code)]
#![allow(unused_imports)]
use ark_ff::PrimeField;
use kimchi::{
    circuits::{
        argument::Argument,
        expr,
        polynomials::{
            complete_add::CompleteAdd, endomul_scalar::EndomulScalar, endosclmul::EndosclMul,
            poseidon::Poseidon, varbasemul::VarbaseMul,
        },
    },
    curve::KimchiCurve,
    proof::{PointEvaluations, ProofEvaluations, ProverCommitments},
    prover_index::ProverIndex,
};
use poly_commitment::evaluation_proof::{OpeningProof, PreChallenges};

// Let F, K be the two fields (either (Fp, Fq) or (Fq, Fp)).
// Each proof over F has an accumulator state which contains
// - a set of IPA challenges c_0, ..., c_{k-1}, which can be interpreted as F elements.
// - a polynomial commitment challenge_polynomial_commitment, which has coordinates in K.
//
// This part of the accumulator state is finalized by checking that challenge_polynomial_commitment
// is a commitment to the polynomial
//
// f_c := prod_{i = 0}^{k-1} (1 + c_i x^{2^{k-1 - i}})
//
// When incrementally-verifying such a proof in a K-circuit (since we need K-arithmetic to perform
// the group operations on the F-polynomial-commitments that constitute the proof),
// instead of checking this, we get an evaluation E_c at a random point zeta and check
// that challenge_polynomial_commitment opens to E_c at zeta. Then we will need to check that
// E_c = f_c(zeta) = prod_{i = 0}^{k-1} (1 + c_i zeta^{2^{k-1 - i}}).
//
// However, because we are then in a K-circuit, we cannot actually compute f_c(zeta), which requires
// F-arithmetic.
//
// Therefore, after incrementally verifying the F-proof, the challenges (c_0, ..., c_{k-1}) which are
// part of the accumulator of the F-proof we just incrementally verified, must remain part of
// the accumulator of the K-proof, along with E_c (or at least some kind of commitment to it, which is
// what we actually do).
//
// Then, when we incrementally verify that K-proof in an F-circuit, we will check that E_c was
// computed correctly using c_0, ..., c_{k-1} and they along with E_c can be discarded.
//
// So, to summarize, the accumulator state for each proof P (corresponding to an F-circuit)
// contains
// - a set of IPA challenges (thought of as K-elements) for every proof that it incrementally verified inside its circuit
// - a challenge_polynomial_commitment (coordinates in F) for every proof that it incrementally verified inside its circuit
// - a challenge_polynomial_commitment (coordinates in K) corresponding to P's own inner-product argument
// - a set of IPA challenges (thought of as F-elements) corresponding to P's own inner-product argument

type G1 = mina_curves::pasta::Pallas;
type G2 = mina_curves::pasta::Vesta;
type Fp = mina_curves::pasta::Fp;
type Fq = mina_curves::pasta::Fq;

pub const MAX_PROOFS_VERIFIED: usize = 2;
pub const TICK_ROUNDS_N: usize = 16;

pub struct ScalarChallenge {}
pub struct ChallengePolynomialCommitments {}
pub struct BranchData {}
pub struct Challenge {}
pub struct AppState {} // should be two?
pub struct Features {}
pub struct Digest {}
pub struct UnfinalizedProofs {}
pub struct PlonkVerificationKeyEvals {}

//
// prechals = OpeningProof::prechallenges(proof, &mut sponge)
// mapped to a right domain:
//        let prechals =
//          Vector.of_list_and_length_exn
//            (Array.map prechals ~f:Bulletproof_challenge.unpack |> Array.to_list)
//            Tock.Rounds.n
pub struct BulletproofChallenges<F>(pub PreChallenges<F>);

/// This is data that can be computed in linear time from the proof + statement.
///
/// It doesn't need to be sent on the wire, but it does need to be provided to the verifier
pub struct BulletproofAdvice<F> {
    b: F,
    /// sum_i r^i sum_j xi^j f_j(pt_i)
    combined_inner_product: F,
}

//pub struct KimchiOracles {
//    type nonrec 'f oracles =
//  { o : 'f random_oracles
//  ; p_eval : 'f * 'f
//  ; opening_prechallenges : 'f array
//  ; digest_before_evaluations : 'f
//  }

/// Challenges from the PLONK IOP. These, plus the evaluations that
/// are already in the proof, are all that's needed to derive all the
/// values in the [In_circuit] version below.
///
/// See src/lib/pickles/plonk_checks/plonk_checks.ml for the
/// computation of the [In_circuit] value from the [Minimal] value.
pub struct StepScalarsMinimal {
    alpha: ScalarChallenge,
    beta: Challenge,
    gamma: Challenge,
    zeta: ScalarChallenge,
}

/// All scalar values deferred by a verifier circuit. The values in
/// [vbmul], [complete_add], [endomul], [endomul_scalar], and [perm]
/// are all scalars which will have been used to scale selector
/// polynomials during the computation of the linearized polynomial
/// commitment.
///
/// Then, we expose them so the next guy (who can do scalar
/// arithmetic) can check that they were computed correctly from the
/// evaluations in the proof and the challenges.
pub struct StepScalarsInCircuit {
    step_scalars_min: StepScalarsMinimal,
    // TODO: zeta_to_srs_length is kind of unnecessary.
    // Try to get rid of it when you can.
    zeta_to_srs_length: Fp,
    zeta_to_domain_size: Fp,
    perm: Fp,
}

/// Challenges from the PLONK IOP. These, plus the evaluations that
/// are already in the proof, are all that's needed to derive all the
/// values in the [In_circuit] version below.
///
/// See src/lib/pickles/plonk_checks/plonk_checks.ml for the
/// computation of the [In_circuit] value from the [Minimal] value.
pub struct WrapScalarsMinimal {
    alpha: ScalarChallenge,
    beta: Challenge,
    gamma: Challenge,
    zeta: ScalarChallenge,
    joint_combiner: Option<ScalarChallenge>,
    feature_flags: Features,
}

/// All scalar values deferred by a verifier circuit. We expose them
/// so the next guy (who can do scalar arithmetic) can check that they
/// were computed correctly from the evaluations in the proof and the
/// challenges.
pub struct WrapScalarsInCircuit {
    wrap_scalars_min: WrapScalarsMinimal,
    zeta_to_srs_length: Fp,
    zeta_to_domain_size: Fp,
    /// scalar used on one of the permutation polynomial commitments
    perm: Fp,
}

/// All the deferred values needed, comprising values from the PLONK IOP verification,
/// values from the inner-product argument, and [which_branch] which is needed to know
/// the proper domain to use.
pub struct WrapDeferredValues<WrapScalars> {
    /// Could be either WrapScalarsMinimal or WrapScalarsInCircuit
    plonk: WrapScalars,
    /// combined_inner_product = sum_{i < num_evaluation_points} sum_{j < num_polys} r^i xi^j f_j(pt_i)
    combined_inner_product: Fp,
    /// b = challenge_poly plonk.zeta + r * challenge_poly (domain_generrator * plonk.zeta)
    ///   where challenge_poly(x) = \prod_i (1 + bulletproof_challenges.(i) * x^{2^{k - 1 - i}})
    b: Fp,
    /// The challenge used for combining polynomials
    xi: ScalarChallenge,
    /// The challenges from the inner-product argument that was partially verified.
    bulletproof_challenges: BulletproofChallenges<Fp>,
    /// Data specific to which step branch of the proof-system was verified
    branch_data: BranchData,
}

/// All the scalar-field values needed to finalize the verification of a proof
/// by checking that the correct values were used in the "group operations" part of the
/// verifier.
///
/// Consists of some evaluations of PLONK polynomials (columns, permutation aggregation, etc.)
/// and the remainder are things related to the inner product argument.
pub struct StepDeferredValues<StepScalars> {
    /// Could be ei
    plonk: StepScalars,
    /// combined_inner_product = sum_{i < num_evaluation_points} sum_{j < num_polys} r^i xi^j f_j(pt_i)
    combined_inner_product: Fq,
    /// b = challenge_poly plonk.zeta + r * challenge_poly (domain_generrator * plonk.zeta)
    ///   where challenge_poly(x) = \prod_i (1 + bulletproof_challenges.(i) * x^{2^{k - 1 - i}})
    b: Fq,
    /// The challenge used for combining polynomials
    xi: ScalarChallenge,
    /// The challenges from the inner-product argument that was partially verified.
    bulletproof_challenges: BulletproofChallenges<Fq>,
}

/// In-circuit type for wrap proofs
pub struct WrapProofChecked {
    // in mina: w_comm, z_comm, t_comm, lookup
    messages: ProverCommitments<G1>,
    // in mina: // lr, z_1, z_2, delta, challenge_polynomial_commitment
    opening: OpeningProof<G1>,
}

pub struct AllEvals {
    evals: ProofEvaluations<PointEvaluations<Vec<Fp>>>,
    public_input: (Vec<Fp>, Vec<Fp>),
    ft_eval1: Fp,
}

/// Represents a proof (along with its accumulation state) which wraps a
/// "step" proof S on the other curve.
///
/// To have some notation, the proof S itself comes from a circuit that verified
/// up to 'max_proofs_verified many wrap proofs W_0, ..., W_max_proofs_verified.
pub struct StepWitness<WrapScalars> {
    /// The user-level statement corresponding to this proof.
    app_state: AppState,
    /// The polynomial commitments, polynomial evaluations, and
    /// opening proof corresponding to this latest wrap proof.
    wrap_proof: WrapProofChecked,
    /// The accumulator state corresponding to the above proof. Contains
    /// - `deferred_values`: The values necessary for finishing the deferred "scalar field" computations.
    /// That is, computations which are over the "step" circuit's internal field that the
    /// previous "wrap" circuit was unable to verify directly, due to its internal field
    /// being different.
    /// - `sponge_digest_before_evaluations`: the sponge state: TODO
    /// - `messages_for_next_wrap_proof`
    proof_state: WrapProofState<WrapScalars>,
    /// The evaluations from the step proof that this proof wraps
    prev_proof_evals: AllEvals,
    /// The challenges c_0, ... c_{k - 1} corresponding to each W_i.
    prev_challenges: [[Fp; TICK_ROUNDS_N]; MAX_PROOFS_VERIFIED],
    /// The commitments to the "challenge polynomials"
    /// \prod_{i = 0}^k (1 + c_{k - 1 - i} x^{2^i})
    /// corresponding to each of the "prev_challenges"
    prev_challenge_poly_coms: [G2; MAX_PROOFS_VERIFIED],
}

/// The component of the proof accumulation state that is only
/// computed on by the "stepping" proof system, and that can be
/// handled opaquely by any "wrap" circuits.
pub struct MessagesForNextStepProof {
    /// The actual application-level state (e.g., for Mina, this is
    /// the protocol state which contains the merkle root of the
    /// ledger, state related to consensus, etc.)
    app_state: AppState,
    /// The verification key corresponding to the wrap-circuit for
    /// this recursive proof system. It gets threaded through all the
    /// circuits so that the step circuits can verify proofs against
    /// it.
    dlog_plonk_index: PlonkVerificationKeyEvals,
    challenge_polynomial_commitments: ChallengePolynomialCommitments,
    old_bulletproof_challenges: BulletproofChallenges<Fq>,
}

/// The component of the proof accumulation state that is only
/// computed on by the "wrapping" proof system, and that can be
/// handled opaquely by any "step" circuits. *)
pub struct MessagesForNextWrapProof {
    challenge_polynomial_commitments: G1,
    old_bulletproof_challenges: BulletproofChallenges<Fp>,
}

/// For each proof that a /step/ circuit verifies, we do not verify the whole proof.
/// Specifically,
/// - we defer calculations involving the "other field" (i.e., the scalar-field of the group
///   elements involved in the proof.
/// - we do not fully verify the inner-product argument as that would be O(n) and instead
///   do the accumulator trick.
///
/// As a result, for each proof that a step circuit verifies, we must expose some data
/// related to it as part of the step circuit's statement, in order to allow those proofs
/// to be fully verified eventually.
///
/// This is that data.
pub struct PerProof<StepScalars> {
    /// Scalar values related to the proof
    deferred_values: StepDeferredValues<StepScalars>,
    /// We allow circuits in pickles proof systems to decide if it's
    /// OK that a proof did not recursively verify. In that case, when
    /// we expose the unfinalized bits, we need to communicate that
    /// it's OK if those bits do not "finalize". That's what this
    /// boolean is for.
    should_finalize: bool,
    sponge_digest_before_evaluations: Digest,
}

pub struct WrapProofState<WrapScalars> {
    deferred_values: WrapDeferredValues<WrapScalars>,
    sponge_digest_before_evaluations: Digest,
    /// Parts of the statement not needed by the other circuit. Represented as a hash inside the
    /// circuit which is then "unhashed"
    messages_for_next_wrap_proof: MessagesForNextStepProof,
}

pub struct StepProofState {
    /// A vector of the "per-proof" structures defined above, one for each proof
    /// that the step-circuit partially verifies.
    unfinalized_proofs: UnfinalizedProofs,
    /// The component of the proof accumulation state that is only computed on by the
    /// "stepping" proof system, and that can be handled opaquely by any "wrap" circuits.
    messages_for_next_step_proof: MessagesForNextStepProof,
}

/// This is the full statement for "wrap" proofs which contains
///       - the application-level statement (app_state)
///       - data needed to perform the final verification of the proof, which correspond
///         to parts of incompletely verified proofs.
pub struct WrapStatement<WrapScalars> {
    proof_state: WrapProofState<WrapScalars>,
    messages_for_next_step_proof: MessagesForNextStepProof,
}

pub struct StepStatement {
    proof_state: StepProofState,
    /// The component of the proof accumulation state that is only computed on by the
    /// "wrapping" proof system, and that can be handled opaquely by any "step" circuits.
    messages_for_next_wrap_proof: MessagesForNextWrapProof,
}

/// This type models an "inductive rule". It includes
///  - the list of previous statements which this one assumes
///  - the snarky main function
///
///  The types parameters are:
///  - ['prev_vars] the tuple-list of public input circuit types to the previous
///    proofs.
///    - For example, [Boolean.var * (Boolean.var * unit)] represents 2 previous
///      proofs whose public inputs are booleans
///  - ['prev_values] the tuple-list of public input non-circuit types to the
///    previous proofs.
///    - For example, [bool * (bool * unit)] represents 2 previous proofs whose
///      public inputs are booleans.
///  - ['widths] is a tuple list of the maximum number of previous proofs each
///    previous proof itself had.
///    - For example, [Nat.z Nat.s * (Nat.z * unit)] represents 2 previous
///      proofs where the first has at most 1 previous proof and the second had
///      zero previous proofs.
///  - ['heights] is a tuple list of the number of inductive rules in each of
///    the previous proofs
///    - For example, [Nat.z Nat.s Nat.s * (Nat.z Nat.s * unit)] represents 2
///      previous proofs where the first had 2 inductive rules and the second
///      had 1.
///  - ['a_var] is the in-circuit type of the [main] function's public input.
///  - ['a_value] is the out-of-circuit type of the [main] function's public
///    input.
///  - ['ret_var] is the in-circuit type of the [main] function's public output.
///  - ['ret_value] is the out-of-circuit type of the [main] function's public
///    output.
///  - ['auxiliary_var] is the in-circuit type of the [main] function's
///    auxiliary data, to be returned to the prover but not exposed in the
///    public input.
///  - ['auxiliary_value] is the out-of-circuit type of the [main] function's
///    auxiliary data, to be returned to the prover but not exposed in the
///    public input.
pub struct InductiveRule {
    identifier: String,
    //   prevs : ('prev_vars, 'prev_values, 'widths, 'heights) H4.T(Tag).t,
    prevs: (),
    //   main :
    //        'a_var main_input
    //     -> ('prev_vars, 'widths, 'ret_var, 'auxiliary_var) main_return,
    main: (),
    feature_flags: Features,
}

pub struct TypesMapBasic {}

pub struct TypesMapCompiledBasic {
    public_input: (),
    wrap_domain: (),
    step_domains: (),
    feature_flags: Features,
    zk_rows: usize,
}

pub struct TypesMapCompiled {
    branches: (),
    max_proofs_verified: (),
    /// for each branch in this rule, how many predecessor proofs does it have?
    proofs_verifieds: (),
    wrap_key: (),
    wrap_vk: (),
    basic: TypesMapCompiledBasic,
}

// exactly as compiled, but without wrap_vk
pub struct ForStep {
    branches: (),
    max_proofs_verified: (),
    /// for each branch in this rule, how many predecessor proofs does it have?
    proofs_verifieds: (),
    wrap_key: (),
    basic: TypesMapCompiledBasic,
}

pub fn prover() {}

pub fn verifier() {}
