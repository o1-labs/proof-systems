//! This crate provides a circuit to achieve Incremental Verifiable
//! Computation (IVC) based on a variant of the folding scheme described in the
//! paper [Nova](https://eprint.iacr.org/2021/370.pdf). For the rest of the
//! document, we do suppose that the curve is BN254.
//!
//! Note that in the rest of this document, we will mix the terms
//! "relaxation/relaxed" with "homogeneisation/homogeneous" polynomials. The
//! reason is explained in the [folding] library. The term "running relaxed
//! instance" can be rephrased as "an accumulator of evaluations of the
//! homogeneised polynomials describing the computation and commitments to them".
//!
//! ## A recap of the Nova IVC scheme
//!
//! The [Nova paper](https://eprint.iacr.org/2021/370.pdf) describes a IVC
//! scheme to be used by the folding scheme described in the same paper.
//!
//! The IVC scheme uses different notations for different concepts:
//! - `F` is the function to be computed. In our codebase, we call it the
//!   "application circuit".
//! - `F'` is the augmented function with the verifier computation. In our
//!   codebase, we call it the "IVC circuit + APP circuit", or also the "joint
//!   circuit".
//! - `U_i` is the accumulator of the function `F'` up to step `i`. For clarity,
//!   we will sometimes use the notation `acc_i` to denote the accumulator. The
//!   accumulator in the [folding] library is called the "left instance". It is a
//!   "running relaxed instance".
//! - `u_i` is the current instance of the function `F'` to be folded into the
//!   accumulator. In the [folding] library, it is called the "right instance".
//! - `U_(i + 1)` is the accumulator of the function `F'` up to step `i + 1`,
//!   i.e. the accumulation of `U_i` and `u_i`. In the [folding] library, it is
//!   called the "output instance" or the "folded output". The "folded output" and
//!   the "left instance" should be seen as both accumulators, and the right
//!   instance should be seen as the difference between both.
//!
//! The IVC scheme described in Fig 4 works as follow, for a given step `i`:
//! - In the circuit (or also called "the augmented function `F'`"), the prover
//!   will compute a hash of the left instance `acc_i`. It is a way to "compress"
//!   the information of the previous computation. It is described by the notation
//!   `u_i.x ?= Hash(i, z0, zi, U_i)` in the Fig 4 on the left.
//!   The value `u_i.x` is provided as a public input to the circuit. In the code,
//!   we could summarize with the following pseudo code:
//!   ```text
//!   left_commitments.into_iter().for_each(|comm| {
//!   env.process_hash(comm, LeftCommitment)
//!   })
//!   env.assert_eq(env.output_left, env.hash_state[LeftCommitment])
//!   ```
//! - The prover will also compute the expected hash for the next iteration, by
//!   computing the hash of the output instance `U_(i + 1)`. It is described by
//!   the notation `u_(i + 1).x ?= Hash(i + 1, z0, zi, U_(i + 1))` in the Fig 4 on
//!   the right. Note that `U_(i + 1)` will be, at step `i + 1`, the new left
//!   input. The value of the hash computed at step `i` will be compared at step
//!   `i + 1`. In the code, we could summarize with the following pseudo-code:
//!   ```text
//!   output_commitments.into_iter().for_each(|comm| {
//!   env.process_hash(comm, OutputCommitment)
//!   })
//!   env.assert_eq(env.output_left, env.hash_state[OutputCommitment])
//!   ```
//!
//! The order of the execution is encoded in the fact the hash contains the
//! step `i` when we check the left input and `i + 1` when we compress the
//! folded output. The fact that the prover encodes the computation on the same
//! initial input is encoded by adding the initial value `z0` into the hash for
//! both hash computation.
//! Therefore, the Nova IVC scheme encodes a **sequential** and **incremental**
//! computation, which can be verified later using a SNARK on the accumulated
//! instance.
//!
//! The job regarding the correct accumulation of the commitments and the
//! scalars are done in the middle square, i.e. `acc_(i + 1) = NIFS.V(acc_i,
//! u_i)`. It performs foreign field elliptic curve additions and scalars
//! additions.
//!
// The documentation below is outdated. Please, update it after bifolding is
// implemented.
//! ## Our design
//!
//! The circuit is implemented using the generic interpreter provided by the
//! crate [kimchi_msm].
//! The particularity of the implementation is that it doesn't use a cycle of
//! curves, aims to be as generic as possible, defer the scalar
//! multiplications to compute them in bulk and rely on the Poseidon hash.
//! Our argument will be mostly based on the state of the hash after we
//! executed the whole computation.
//!
//! The IVC circuit is divided into different sections/sets of constraints
//! described by multivariate polynomials, each
//! activated by (public) selectors that are defined at setup time.
//! The number of columns of the original computation defines the shape of the
//! circuit as it will define the values of the selectors.
//!
//! First, the folding scheme we use is described in the crate
//! [folding](folding::expressions) and is based on degree-3 polynomials.
//! We do suppose that each constraint are reduced to degree 2, and the third
//! degree is used to encode the aggregation of constraints.
//!
//! In the [Nova paper](https://eprint.iacr.org/2021/370.pdf), to provide
//! incremental verifiable computation, the authors propose a folding scheme
//! where the verifier has to compute the followings:
//!
//! ```text
//! // Accumulation of the homogeneous value `u`:
//! u'' = u + r u'
//! // Accumulation of all the PIOP challenges:
//! for each challenge c_i:
//!    c_i'' = c_i + r c_i'
//! for each alpha_i (aggregation of constraints):
//!    alpha_i'' = alpha_i + r alpha_i'
//! // Accumulation of the blinders for the commitment:
//! blinder'' = blinder + r + r^2 + r^3 blinder'
//! // Accumulation of the error terms (scalar multiplication)
//! E = E1 + r T0 + r^2 T1 + r^3 E2
//! // Randomized accumulation of the instance commitments (scalar multiplication)
//! for i in 0..N_COLUMNS
//!    (C_i)_O = (C_i)_L + r (C_i)_R
//! ```
//!
//! The accumulation of the challenges, the homogeneous value and the blinders
//! are done trivially as they are scalar field values.
//! After that, the verifier has to perform foreign field ellictic curve
//! additions and scalar multiplications `(r T0)`, `(r^2 T1)`, `(r^3 E2)` and
//! `(r (C_i)_R)` for each column.
//!
//! First, we decide to defer the computations of
//! the scalar multiplications, and we reduce the verifier work to compute only
//! the foreign field elliptic curve additions. Therefore, the verifier has
//! access already to the
//! result of `r T0`, `r^2 T1`, `r^3 E2` and `r (C_i)_R`, and must only perform the
//! addition. We call the commitments `r T0` the "scaled" commitment to `T0`, and
//! the same for the others. The commitments `(C_i)_L`, `(C_i)_R` and `(C_i)_O` are
//! called the "instance commitments".
//!
//! To perform foreign field elliptic curve addition, we split the commitments
//! into 17 chunks of 15 bits and use additive lookups as described in
//! [kimchi_msm::logup]. These 17 chunks will be used later to compute the
//! scalar multiplications using a variant of the scheme described in [the MSM
//! RFC](https://github.com/o1-labs/rfcs/blob/main/0013-efficient-msms-for-non-native-pickles-verification.md)
//!
//! The first component of our circuit is a hash function.
//! We decided to use the Poseidon hash function, and implemented a generic one
//! using the generic interpreter in [crate::poseidon_8_56_5_3_2]. The Poseidon
//! instance we decided to go with is the traditional full/partial rounds. For a
//! security of 128 bits, a substitution box of 5 and a state of 3 elements, we
//! need 8 full rounds and 56 partial rounds for the scalar field BN254.
//! Therefore, we can "absorb" 2 field elements per row (the third element is
//! kept as a buffer in the Sponge construction).
//!
//! The cost of a single Poseidon hash in terms of constraints is 432
//! constraints, and requires 435 columns, in addition to 192 round constants
//! considered as constants "selectors" in our constraints.
//! Note that having 432 constraints per Poseidon hash means that we must also
//! have 432 constraints to accumulate the challenges used to combine the
//! constraints. It is worth noting that these alphas are the same for all
//! poseidon hashes.
//! Combining constraints is done by using another selector, on a single row,
//! see below (TODO).
//! Note that the columns used by the poseidon hash must also be aggregated
//! while running the IVC.
//!
//! The Poseidon hash is used to absorb all the instance commitments, the
//! challenges and the scaled commitments.
//! In our circuit, we first start by absorbing all the elliptic curve points. A
//! particularity is that we will use different Poseidon instances for each
//! "side" of the addition. For each point, we do assume (*at the moment*) that
//! each point is encoded as 2 field elements in the field of the circuit
//! (FIXME: there is negligeable probability that it wraps over, as the
//! coordinates are in the base field).
// We will change this soon, by absorbing the coordinate x, and the sign of y.
// If we compute on one row the hash and on the next row the ECADD, the sign of
// y can be computed on the ECADD row, and accessed by the poseidon constraints.
//! For a given set of coordinates `(x, y)`, and by supposing an initial state of
//! our permutation `(s0, s1, s2)`, we will compute on a single row the absorbtion
//! of `(x, y)`, which consists of updating the state `(s0, s1, s2)` to
//! `(s0 + x, s1 + y, s2)`.
//! For each side, we will initialize a new Poseidon state, and we will keep
//! absorbing each column of the circuit.
//!
//! We end up with the following shape:
//! ```text
//! | q_poseidon | s0 | s1 | s2 | s0 + x | s1 + y | ... | s0' | s1' | s2' | side |
//! ```
//! where `(s0', s1', s2')` is the final state of the Poseidon permutation after
//! the execution of all the rounds, and `q_poseidon` will be a (public
//! selector) that will be set to `1` on the row that Poseidon will need to be
//! executed, `0` otherwise.
//!
//! ## IVC circuit: base case
//!
//! The base case of the IVC circuit is supported by multiplying each constraint
//! by a fold_iteration column. As it is `0` for the base case, the whole
//! circuit is "turned off".
//! We do not want to keep this in the final version, and aim to replace it with
//! a method that does not increase the degree of the constraints by one. The
//! column value is also under-constrained for now.
//!
//! The code for the base case is handled in
//! [crate::ivc::interpreter::ivc_circuit_base_case] and the corresponding
//! constraints are in [crate::ivc::constraints::constrain_ivc]. The fold
//! iteration column is set at each row by each process_* function in the
//! interpreter.

pub mod expr_eval;
pub mod ivc;
pub mod plonkish_lang;

/// Poseidon hash function with 55 full rounds, 0 partial rounds, sbox 7, a
/// state of 3 elements and constraints of degree 2
pub mod poseidon_55_0_7_3_2;

/// Poseidon hash function with 55 full rounds, 0 partial rounds, sbox 7,
/// a state of 3 elements and constraints of degree 7
pub mod poseidon_55_0_7_3_7;

/// Poseidon hash function with 8 full rounds, 56 partial rounds, sbox 5, a
/// state of 3 elements and constraints of degree 2
pub mod poseidon_8_56_5_3_2;

/// Poseidon parameters for 55 full rounds, 0 partial rounds, sbox 7, a state of
/// 3 elements
pub mod poseidon_params_55_0_7_3;

pub mod prover;
pub mod verifier;
