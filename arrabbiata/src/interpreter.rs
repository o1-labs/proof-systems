//! This module contains the implementation of the IVC scheme in addition to
//! running an arbitrary function that can use up to [crate::NUMBER_OF_COLUMNS]
//! columns.
//! At the moment, all constraints must be of maximum degree
//! [crate::MAX_DEGREE], but it might change in the future.
//!
//! The implementation relies on a representation of the circuit as a 2D array
//! of "data points" the interpreter can use.
//!
//! An interpreter defines what a "position" is in the circuit and allow to
//! perform operations using these positions.
//! Some of these positions will be considered as public inputs and might be
//! fixed at setup time while making a proof, when other will be considered as
//! private inputs.
//!
//! On top of these abstraction, gadgets are implemented.
//! For the Nova-like IVC schemes, we describe below the different gadgets and
//! how they are implemented with this abstraction.
//!
//! **Table of contents**:
//! - [Gadgets implemented](#gadgets-implemented)
//!   - [Elliptic curve addition](#elliptic-curve-addition)
//!     - [Gadget layout](#gadget-layout)
//!   - [Hash - Poseidon](#hash---poseidon)
//!     - [Gadget layout](#gadget-layout-1)
//!   - [Elliptic curve scalar multiplication](#elliptic-curve-scalar-multiplication)
//!     - [Gadget layout](#gadget-layout-2)
//! - [Handle the combinaison of constraints](#handle-the-combinaison-of-constraints)
//! - [Permutation argument](#permutation-argument)
//! - [Fiat-Shamir challenges](#fiat-shamir-challenges)
//! - [Folding](#folding)
//! - [Message passing](#message-passing)
//!
//! ## Gadgets implemented
//!
//! ### Elliptic curve addition
//!
//! The Nova augmented circuit requires to perform elliptic curve operations, in
//! particular additions and scalar multiplications.
//!
//! To reduce the number of operations, we consider the affine coordinates.
//! As a reminder, here are the equations to compute the addition of two
//! different points `P1 = (X1, Y1)` and `P2 = (X2, Y2)`. Let define `P3 = (X3,
//! Y3) = P1 + P2`.
//!
//! ```text
//! - λ = (Y1 - Y2) / (X1 - X2)
//! - X3 = λ^2 - X1 - X2
//! - Y3 = λ (X1 - X3) - Y1
//! ```
//!
//! Therefore, the addition of elliptic curve points can be computed using the
//! following degree-2 constraints
//!
//! ```text
//! - Constraint 1: λ (X1 - X2) - Y1 + Y2 = 0
//! - Constraint 2: X3 + X1 + X2 - λ^2 = 0
//! - Constraint 3: Y3 - λ (X1 - X3) + Y1 = 0
//! ```
//!
//! If the points are the same, the λ is computed as follows:
//!
//! ```text
//! - λ = (3 X1^2 + a) / (2Y1)
//! ```
//!
//! #### Gadget layout
//!
//! For given inputs (x1, y1) and (x2, y2), the layout will be as follow:
//!
//! ```text
//! | C1 | C2 | C3 | C4 | C5 | C6 | C7 | C8 | C9 | C10 | C11 | C12 | C13 | C14 | C15 |
//! | -- | -- | -- | -- | -- | -- | -- | -- | -- | --- | --- | --- | --- | --- | --- |
//! | x1 | y1 | x2 | y2 | b0 | λ  | x3 | y3 |    |     |     |     |     |     |     |
//! ```
//!
//! where `b0` is equal two `1` if the points are the same, and `0` otherwise.
//!
//! TBD/FIXME: supports negation and the infinity point.
//!
//! TBD/FIXME: the gadget layout might change when we will implement the
//! permutation argument. The values `(x1, y1)` can be public inputs.
//! The values `(x2, y2)` can be fetched from the permutation argument, and must
//! be the output of the elliptic curve scaling.
//!
//! The gadget requires therefore 7 columns.
//!
//! ### Hash - Poseidon
//!
//! Hashing is a crucial part of the IVC scheme. The hash function the
//! interpreter does use for the moment is an instance of the Poseidon hash
//! function with a fixed state size of
//! [crate::curve::PlonkSpongeConstants::SPONGE_WIDTH]. Increasing the
//! state size can be considered as it would potentially optimize the
//! number of rounds, and allow hashing more data on one row. We leave this for
//! future works.
//!
//! A direct optimisation would be to use
//! [Poseidon2](https://eprint.iacr.org/2023/323) as its performance on CPU is
//! better, for the same security level and the same cost in circuit. We leave
//! this for future works.
//!
//! For a first version, we consider an instance of the Poseidon hash function
//! that is suitable for curves whose field size is around 256 bits.
//! A security analysis for these curves give us a recommandation of 60 full
//! rounds if we consider a 128-bit security level and a low-degree
//! exponentiation of `5`, with only full rounds.
//! In the near future, we will consider the partial rounds strategy to reduce
//! the CPU cost. For a first version, we keep the full rounds strategy to keep
//! the design simple.
//!
//! When applying the full/partial round strategy, an optimisation can be used,
//! see [New Optimization techniques for PlonK's
//! arithmetisation](https://eprint.iacr.org/2022/462). The techniques described
//! in the paper can also be generalized to other constraints used in the
//! interpreter, but we leave this for future works.
//!
//! #### Gadget layout
//!
//! We start with the assumption that [crate::NUMBER_OF_COLUMNS] columns are
//! available for the whole circuit, and we can support constraints up to degree
//! [crate::MAX_DEGREE].
//! Therefore, we can compute 5 full rounds per row by using the "next row"
//! (i.e. adding an evaluation point at ζω). An implementation is provided in
//! the gadget [crate::column::Gadget::PoseidonFullRound] and
//! [crate::column::Gadget::PoseidonSpongeAbsorb].
//!
//! The layout for the one using the "next row" is as follow (5 full rounds):
//! ```text
//! | C1 | C2 | C3 | C4 | C5 | C6 | C7 | C8 | C9 | C10 | C11 | C12 | C13 | C14 | C15 |
//! | -- | -- | -- | -- | -- | -- | -- | -- | -- | --- | --- | --- | --- | --- | --- |
//! | x  | y  | z  | a1 | a2 | a3 | b1 | b2 | b3 | c1  | c2  | c3  | d1  | d2  | d3  |
//! | o1 | o2 | o2
//! ```
//! where (x, y, z) is the input of the current step, (o1, o2, o3) is the
//! output, and the other values are intermediary values. And we have the
//! following equalities:
//! ```text
//! (a1, a2, a3) = PoseidonRound(x, y, z)
//! (b1, b2, b3) = PoseidonRound(a1, a2, a3)
//! (c1, c2, c3) = PoseidonRound(b1, b2, b3)
//! (d1, d2, d3) = PoseidonRound(c1, c2, c3)
//! (o1, o2, o3) = PoseidonRound(d1, d2, d3)
//! ```
//!
//! Round constants are passed as public inputs. As a
//! reminder, public inputs are simply additional columns known by the prover
//! and verifier.
//! Also, the elements to absorb are added to the initial state at the beginning
//! of the call of the Poseidon full hash. The elements to absorb are supposed
//! to be passed as public inputs.
//!
//! ### Elliptic curve scalar multiplication
//!
//! The Nova-based IVC schemes require to perform scalar multiplications on
//! elliptic curve points. The scalar multiplication is computed using the
//! double-and-add algorithm.
//!
//! We will consider a basic implementation using the "next row". The
//! accumulators will be saved on the "next row". The decomposition of the
//! scalar will be incremental on each row.
//! The scalar used for the scalar multiplication will be fetched using the
//! permutation argument (FIXME: to be implemented).
//! More than one bit can be decomposed at the same time, and we could reduce
//! the number of rows.
//! We leave this for future work.
//!
//! #### Gadget layout
//!
//! For a (x, y) point and a scalar, we apply the double-and-add algorithm, one
//! step per row.
//!
//! Therefore, we have 255 rows to compute the scalar multiplication.
//! For a given step `i`, we have the following values:
//! - `tmp_x`, `tmp_y`: the temporary values used to keep the double.
//! - `res_x`, `res_y`: the result of the scalar multiplication i.e. the accumulator.
//! - `b`: the i-th bit of the scalar.
//! - `r_i` and `r_(i+1)`: scalars such that r_(i+1) = b + 2 * r_i.
//! - `λ'` and `λ`: the coefficients
//! - o'_x and o'_y equal to `res_plus_tmp_x` and `res_plus_tmp_y` if `b == 1`,
//!   otherwise equal to `o_x` and `o_y`.
//!
//! We have the following layout:
//!
//! ```text
//! | C1   |   C2   |      C3       |      C4       |    C5     | C7 |       C7       |       C8       | C9 | C10 |   C11    | C12 | C13 | C14 | C15 |
//! | --   | -----  | ------------- | ------------- | --------- | -- | -------------- | -------------- | -- | --- | -------- | --- | --- | --- | --- |
//! | o_x  |  o_y   | double_tmp_x  | double_tmp_y  |    r_i    | λ  | res_plus_tmp_x | res_plus_tmp_y | λ' |  b  |
//! | o'_x |  o'_y  | double_tmp'_x | double_tmp'_y |  r_(i+1)  |
//! ```
//!
//! FIXME: an optimisation can be implemented using "a bucket" style algorithm,
//! as described in [Efficient MSMs in Kimchi
//! Circuits](https://github.com/o1-labs/rfcs/blob/main/0013-efficient-msms-for-non-native-pickles-verification.md).
//! We leave this for future work.
//!
//! ## Handle the combinaison of constraints
//!
//! The prover will have to combine the constraints to generate the
//! full circuit at the end. The constraints will be combined using a
//! challenge (often called α) that will be generated in the verifier circuit by
//! simulating the Fiat-Shamir transformation.
//! The challenges will then be accumulated over time using the random coin used
//! by the folding argument.
//! The verifier circuit must be carefully implemented to ensure that all the
//! messages that the prover would have sent before coining the random combiner
//! for the constraints has been absorbed properly in the verifier circuit.
//!
//! Using this technique requires us a folding scheme that handles degree
//! `5 + 1` constraints, as the challenge will be considered as a variable.
//! The reader can refer to this [HackMD
//! document](https://hackmd.io/@dannywillems/Syo5MBq90) for more details.
//!
//! ## Permutation argument
//!
//! Communication between rows must be done using a permutation argument. The
//! argument we use will be a generalisation of the one used in the [PlonK
//! paper](https://eprint.iacr.org/2019/953).
//!
//! The construction of the permutations will be done using the methods prefixed
//! `save` and `load`. The index of the current row and the index of the
//! time the value has been written will be used to generate the permutation on
//! the fly.
//!
//! The permutation argument described in the PlonK paper is a kind of "inverse
//! lookup" protocol, like Plookup. The polynomials are defined as follows:
//!
//! ```text
//!            Can be seen as T[f(X)] = Χ
//!          --------
//!          |      |
//! f'(X) = f(X) + β X + γ
//!                      |--- Can be seen as the evaluation point.
//!                         |
//!                         |
//! g'(X) = g(X) + β σ(X) + γ
//!          |      |
//!          --------
//!          Can be seen as T[g(X)] = σ(X)
//! ```
//!
//! And from this, we build an accumulator, like for Plookup.
//! The accumulator requires to coin two challenges, β and γ, and it must be
//! done after the commitments to the columns have been absorbed.
//! The verifier at the next step will verify that the challenges have been
//! correctly computed.
//! In the implementation, the accumulator will be computed after the challenges
//! and the commitments. Note that the accumulator must also be aggregated, and
//! the aggregation must be performed by the verifier at the next step.
//!
//! The methods `save` and `load` will accept as arguments only a column that is
//! included in the permutation argument. For instance, `save_poseidon_state`
//! will only accept columns with index 3, 4 and 5, where the
//! `load_poseidon_state` will only accepts columns with index 0, 1 and 2.
//!
//! The permutations values will be saved in public values, and will contain the
//! index of the row. The permutation values will be encoded with a 32 bits
//! value (u32) as we can suppose a negligible probability that a user will use
//! more than 2^32 rows.
//!
//! The permutation argument also generates constraints that will be
//! homogenized with the gadget constraints.
//!
//! Note all rows might require to use the permutation argument. Therefore, a
//! selector will be added to activate/deactivate the permutation argument.
//! When a method calls `save` or `load`, the selector will be activated. By
//! default, the selector will be deactivated.
//!
//! TBD:
//! - number of columns
//! - accumulator column
//! - folding of the permutation argument
//!
//! TBD/FIXME: do we use a additive permutation argument to increase the number
//! of columns we can perform the permutation on?
//!
//! TBD/FIXME: We can have more than one permutation argument. For instance, we
//! can have a permutation argument for the columns 0, 1, 2, 3 and one for the
//! columns 4, 5, 6, 7. It can help to decrease the degree.
//!
//! ## Fiat-Shamir challenges
//!
//! The challenges sent by the verifier must also be simulated by the verifier
//! circuit. It is done by passing "messages" as public inputs to the next
//! instances. Diagrams recapitulating the messages that must be passed are
//! available in the section [Message passing](#message-passing).
//!
//! For a step `i + 1`, the challenges of the step `i` must be computed by the
//! verifier in the circuit, and check that it corresponds to the ones received
//! as a public input.
//!
//! TBD/FIXME: specify. Might require foreign field arithmetic.
//!
//! TBD/FIXME: do we need to aggregate them for the end?
//!
//! ## Folding
//!
//! Constraints must be homogenized for the folding scheme.
//! Homogenising a constraint means that we add a new variable (called "U" in
//! Nova for instance) that will be used to homogenize the degree of the monomials
//! forming the constraint.
//! Next to this, additional information, like the cross-terms and the error
//! terms must be computed.
//!
//! This computation depends on the constraints, and in particular on the
//! monomials describing the constraints.
//! The computation of the cross-terms and the error terms happen after the
//! witness has been built and the different arguments like the permutation and
//! lookups have been done. Therefore, the interpreter must provide a method to
//! compute it, and the constraints should be passed as an argument.
//!
//! When computing the cross-terms, we must compute the contribution of each
//! monomial to it.
//!
//! The implementation works as follow:
//! - Split the constraint in monomials
//! - For the monomials of degree `d`, compute the contribution when
//!   homogenizing to degree `d'`.
//! - Sum all the contributions.
//!
//! The library [mvpoly] can be used to compute the cross-terms and to
//! homogenize the constraints. The constraints can be converted into a type
//! implementing the trait [MVPoly](mvpoly::MVPoly) and the method
//! [compute_cross_terms](mvpoly::MVPoly::compute_cross_terms) can be used from
//! there.
//!
//! ## Message passing
//!
//! The message passing is a crucial part of the IVC scheme. The messages are
//! mostly commitments and challenges that must be passed from one step to
//! another, and by "jumping" between curves. In the implementation,
//! the messages are kept in an "application environment", located in the
//! "witness environment". The structure [crate::witness::Env] is used to keep
//! track of the messages that must be passed.
//! Each step starts with an "program state" and end with another that is
//! accumulated. The final state is passed through a "digest" to the next
//! instance. The digest is performed using a hash function (see [Hash -
//! Poseidon](#hash---poseidon)). We often use the term "sponge" to refer to the
//! hash function or the state of the hash function.
//!
//! The sponge state will be forked at different steps, to provide a
//! consistent state between the different instances and the different curves.
//! The challenges will be computed using the sponge state after hashing the
//! appropriate values from the appropriate initial state, and be kept in the
//! environment.
//!
//! In the diagram below, each object subscripted by `(p, n)` (resp. `(q, n)`)
//! means that they are related to the instance `n` whose circuit is defined in
//! the field `Fp` (resp. `Fq`), the scalar field of Vesta (resp. Pallas).
//!
//! In addition to that, we use
//! - `w_(p, n)` for the witness.
//! - `W_(p, n)` for the aggregated witness.
//! - `C_(p, n)` for the commitment to the witness `w_(p, n)`.
//! - `acc_(p, n)` for the accumulated commitments to the aggregated witness
//!   `W_(p, n)`.
//! - `α_(p, n)` for the challenge used to combine constraints.
//! - `β_(p, n)` and `γ_(p, n)` for the challenge used to for the
//!   permutation argument.
//! - `r_(p, n)` for the challenge used for the accumulation of the
//! - `t_(p, n, i)` for the evaluations of the cross-terms of degree `i`.
//! - `Ct_(p, n, i)` for the commitments to the cross-terms of degree `i`.
//!   witness/commitments.
//! - `u_(p, n)` for the challenge used to homogenize the constraints.
//! - `o_(p, n)` for the final digest of the sponge state.
//!
//! Here a diagram (FIXME: this is not complete) that shows the messages that
//! must be passed:
//!
//! ```text
//! +------------------------------------------+                      +------------------------+
//! |            Instance n                    |                      |     Instance n + 2     |
//! |        (witness w_(p, n))                |                      | (witness W_(p, n + 1)) |
//! |            ----------                    |                      |     ----------         |
//! |               Vesta                      |                      |         Vesta          |
//! |         (scalar field = Fp)              |                      |   (scalar field = Fp)  |
//! |         (base field   = Fq)              |                      |   (base field   = Fq)  |
//! |          (Sponge over Fq)                |                      |    (Sponge over Fq)    |
//! |                                          |                      |                        |
//! |          Generate as output              |                      |   Generate as output   |
//! |          ------------------              |                      |   ------------------   |
//! | Challenges:                              |                      | Challenges:            |
//! | - α_(p, n)                               |                      | - α_(p, n + 1)         |
//! | - β_(p, n)                               |                      | - β_(p, n + 1)         |
//! | - γ_(p, n)                               |                      | - γ_(p, n + 1)         |
//! | - r_(p, n)                               |                      | - r_(p, n + 1)         |
//! | - u_(p, n)                               |                      | - u_(p, n + 1)         |
//! | Commitments:                             |                      |          (...)         |
//! | - Cross-terms (`Ct_(p, n)`)              |                      +------------------------+
//! | - Witness columns (`w_(p, n)`)           |                                   ^
//! | Fiat-Shamir:                             |                                   |
//! | - digest of all messages read until      |                                   |
//! | now -> `o_(p, n)`                        |                                   |
//! |                                          |                                   |
//! |             Receive in PI                |                                   |
//! |             --------------               |                                   |
//! | - Commitments to w_(p, (n - 1))          |                                   |
//! | - Final digest of the program            |                                   |
//! | state at instance (n - 1)                |                                   |
//! | (o_(q, n - 1)).                          |                                   |
//! | - Final digest of the program            |                                   |
//! | state at instance (n - 2)                |                                   |
//! | (o_(p, n - 1)).                          |                                   |
//! |                                          |                                   |
//! |             Responsibility               |                                   |
//! |             --------------               |                                   |
//! | - Verify FS challenges (α_(q, n - 1),    |                                   |
//! | β_(q, n - 1), γ_(q, n - 1),              |                                   |
//! | r_(q, n - 1), u_(q, n - 1)               |                                   |
//! | (i.e. challenges of instance n - 1)      |                                   |
//! | from o_(q, n - 1)                        |                                   |
//! | - Aggregate witness columns w_(p, n)     |                                   |
//! | into W_(p, n).                           |                                   |
//! | - Aggregate error terms                  |                                   |
//! | from instance n - 2 with cross terms of  |                                   |
//! | instance n - 2                           |                                   |
//! +------------------------------------------+                                   |
//!                      |                                                         |
//!                      |                                                         |
//!                      |             +----------------------------+              |
//!                      |             |       Instance n + 1       |              |
//!                      |             |   (witness w_(q, n))       |              |
//!                      |             |       --------------       |              |
//!                      |             |           Pallas           |              |
//!                      |             |      (scalar field = Fq)   |              |
//!                      |-----------> |      (base field   = Fp)   |--------------
//!                                    |       (Sponge over Fp)     |
//! TODO: define msgs                  |                            |    TODO: define msgs
//!       format to pass               |            TODO            |     format to pass
//!         IO                         |                            |          IO
//!                                    |                            |
//!                                    |                            |
//!                                    +----------------------------+
//! ```
//!
//! ### Workflow example for handling a challenge
//!
//! Handling challenges is performed in two steps. Let's take the example of the
//! verifier coin `u` used to homogenize the constraints/polynomials in the
//! accumulation protocol. For the sake of simplicity, we only focus on the work
//! related to the challenges. In addition to that, a verifier coin `r` is used
//! to accumulate the challenges. Therefore, we start with the following
//! diagram:
//!
//! ```text
//! +------------------------------------------+
//! |            Instance n                    |
//! |        (witness w_(p, n))                |
//! |            ----------                    |
//! |               Vesta                      |
//! |         (scalar field = Fp)              |
//! |         (base field   = Fq)              |
//! |          (Sponge over Fq)                |
//! |                                          |
//! | Generate as output:                      |
//! | - u_(p, n)                               |
//! | - r                                      |
//! | - "accumulated u": u_p + r * u_(p, n)    |
//! |     (note the operations are over Fp)    |
//! +------------------------------------------+
//! ```
//!
//! The coins `u_(p, n)` and `r` are generated after absorbing a few committed
//! values (i.e. points over Fq). The verifier will have to check the following:
//! - `u_(p, n)` has been coined correctly (i.e. check a sponge state).
//! - `r` has been coined correctly (i.e. check a sponge staet).
//! - "accumulated u" has been computed correctly
//!
//! At the next iteration, the verifier is working over the field `Fq`, i.e. the
//! field that is used to generate the challenges. Therefore, it can perform the
//! first two checks. We have then the following diagram.
//!
//! ```text
//! +------------------------------------------+
//! |            Instance n                    |
//! |        (witness w_(p, n))                |
//! |            ----------                    |
//! |               Vesta                      |
//! |         (scalar field = Fp)              |
//! |         (base field   = Fq)              |
//! |          (Sponge over Fq)                |
//! |                                          |
//! | Generate as output:                      |
//! | - u_(p, n)                               |
//! | - r                                      |
//! | - "accumulated u": u_p + r * u_(p, n)    |
//! |     (note the operations are over Fp)    |
//! +------------------------------------------+
//!       |
//!       |
//!       |
//!       |               +-----------------------------+
//!       |               |       Instance (n + 1)      |
//!       |               |      (witness w_(q, n))     |
//!       |-------------> |          ----------         |
//!                       |          Pallas             |
//!                       |    (scalar field = Fq)      |
//!                       |    (base field   = Fp)      |
//!                       |     (Sponge over Fp)        |
//!                       |                             |
//!                       |     Receive as (public)     |
//!                       |           inputs            |
//!                       |       ---------------       |
//!                       | - commitments generated     |
//!                       | by instance n (Fq elements) |
//!                       | - u_(p, n)                  |
//!                       | - r                         |
//!                       | - (more but unused by       |
//!                       | the verifier)               |
//!                       |                             |
//!                       |      Verifier circuit       |
//!                       |      ----------------       |
//!                       | - run the sponge to         |
//!                       | check the value u_(p, n)    |
//!                       | and r                       |
//!                       +-----------------------------+
//! ```
//!
//! The last check, i.e. checking the accumulation of `u`, is "delayed" for the
//! instance (n + 2), to be able to perform the accumulation over Fp.
//!
//! Therefore, we end up with the following diagram:
//!
//! ```text
//! +------------------------------------------+            +-------------------------------------+
//! |            Instance n                    |            |            Instance (n + 2)         |
//! |        (witness w_(p, n))                |            |         (witness w_(p, n + 1))      |
//! |            ----------                    |            |            ----------               |
//! |               Vesta                      |            |               Vesta                 |
//! |         (scalar field = Fp)              |            |         (scalar field = Fp)         |
//! |         (base field   = Fq)              |            |         (base field   = Fq)         |
//! |          (Sponge over Fq)                |            |          (Sponge over Fq)           |
//! |                                          |            |                                     |
//!            Generate as output:             |            |        Receive as (public inputs)   |
//!              ---------------               |            |           -------------------       |
//! | - u_(p, n)                               |            | - `u_(p, n)`                        |
//! | - r                                      |            | - accumulated u, `acc_u`            |
//! | - "accumulated u": u_p + r * u_(p, n)    |            | - random coin `r`                   |
//! |     (note the operations are over Fp)    |            | - "old accumulated value" u_p       |
//! +------------------------------------------+            |           Verifier circuit          |
//!       |                                                 |           ----------------          |
//!       |                                                 | - check that                        |
//!       |                                                 | `acc_u = u_p + r * u_(p, n)`        |
//!       |                                                 +-------------------------------------+
//!       |                                                                 ^
//!       |                                                                 |
//!       |                                                                 |
//!       |               +-----------------------------+                   |
//!       |               |       Instance (n + 1)      |                   |
//!       |               |      (witness w_(q, n))     |                   |
//!       |-------------> |          ----------         |  ------------------
//!                       |          Pallas             |
//!                       |    (scalar field = Fq)      |
//!                       |    (base field   = Fp)      |
//!                       |     (Sponge over Fp)        |
//!                       |                             |
//!                       |     Receive as (public)     |
//!                       |           inputs            |
//!                       |       ---------------       |
//!                       | - commitments generated     |
//!                       | by instance n (Fq elements) |
//!                       | - u_(p, n)                  |
//!                       | - r                         |
//!                       | - (more but unused by       |
//!                       | the verifier)               |
//!                       |                             |
//!                       |      Verifier circuit       |
//!                       |      ----------------       |
//!                       | - run the sponge to         |
//!                       | check the value u_(p, n)    |
//!                       | and r                       |
//!                       +-----------------------------+
//! ```

use crate::{curve::PlonkSpongeConstants, MAXIMUM_FIELD_SIZE_IN_BITS, NUMBER_OF_COLUMNS};
use ark_ff::{One, Zero};
use log::debug;
use mina_poseidon::constants::SpongeConstants;
use num_bigint::BigInt;

/// A list of instruction/gadget implemented in the interpreter.
/// The control flow can be managed by implementing a function
/// `fetch_next_instruction` and `fetch_instruction` on a witness environnement.
/// See the [Witness environment](crate::witness::Env) for more details.
///
/// Mostly, the instructions will be used to build the verifier circuit, but it
/// can be generalized.
///
/// When the circuit is predefined, the instructions can be accompanied by a
/// public selector. When implementing a virtual machine, where instructions are
/// unknown at compile time, other methods can be used. We leave this for future
/// work.
///
/// For the moment, the type is not parametrized, on purpose, to keep it simple
/// (KISS method). However, IO could be encoded in the type, and encode a
/// typed control-flow. We leave this for future work.
#[derive(Copy, Clone, Debug)]
pub enum Instruction {
    /// This gadget implement the Poseidon hash instance described in the
    /// top-level documentation. In the current setup, with [NUMBER_OF_COLUMNS]
    /// columns, we can compute 5 full rounds per row.
    ///
    /// We split the Poseidon gadget in 13 sub-gadgets, one for each set of 5
    /// full rounds and one for the absorbtion. The parameter is the starting
    /// round of the permutation. It is expected to be a multiple of five.
    ///
    /// Note that, for now, the gadget can only be used by the verifier circuit.
    PoseidonFullRound(usize),
    /// Absorb [PlonkSpongeConstants::SPONGE_WIDTH - 1] elements into the
    /// sponge. The elements are absorbed into the last
    /// [PlonkSpongeConstants::SPONGE_WIDTH - 1] elements of the sponge state.
    ///
    /// The values to be absorbed depend on the state of the environment while
    /// executing this instruction.
    ///
    /// Note that, for now, the gadget can only be used by the verifier circuit.
    PoseidonSpongeAbsorb,
    EllipticCurveScaling(usize, u64),
    EllipticCurveAddition(usize),
    // The NoOp will simply do nothing
    NoOp,
}

/// The first instruction in the verifier circuit (often shortened in "IVC" in
/// the crate) is the Poseidon permutation. It is used to start hashing the
/// public input.
pub const VERIFIER_STARTING_INSTRUCTION: Instruction = Instruction::PoseidonSpongeAbsorb;

/// Define the side of the temporary accumulator.
/// When computing G1 + G2, the interpreter will load G1 and after that G2.
/// This enum is used to decide which side fetching into the cells.
/// In the near future, it can be replaced by an index.
pub enum Side {
    Left,
    Right,
}

/// An abstract interpreter that provides some functionality on the circuit. The
/// interpreter should be seen as a state machine with some built-in
/// functionality whose state is a matrix, and whose transitions are described
/// by polynomial functions.
pub trait InterpreterEnv {
    type Position: Clone + Copy;

    /// The variable should be seen as a certain object that can be built by
    /// multiplying and adding, i.e. the variable can be seen as a solution
    /// to a polynomial.
    /// When instantiating as expressions - "constraints" - it defines
    /// multivariate polynomials.
    type Variable: Clone
        + core::ops::Add<Self::Variable, Output = Self::Variable>
        + core::ops::Sub<Self::Variable, Output = Self::Variable>
        + core::ops::Mul<Self::Variable, Output = Self::Variable>
        + core::fmt::Debug
        + Zero
        + One;

    /// Allocate a new variable in the circuit for the current row
    fn allocate(&mut self) -> Self::Position;

    /// Allocate a new variable in the circuit for the next row
    fn allocate_next_row(&mut self) -> Self::Position;

    /// Return the corresponding variable at the given position
    fn read_position(&self, pos: Self::Position) -> Self::Variable;

    /// Set the value of the variable at the given position for the current row
    fn write_column(&mut self, col: Self::Position, v: Self::Variable) -> Self::Variable;

    /// Build the constant zero
    fn zero(&self) -> Self::Variable;

    /// Build the constant one
    fn one(&self) -> Self::Variable;

    fn constant(&self, v: BigInt) -> Self::Variable;

    /// Assert that the variable is zero
    fn assert_zero(&mut self, x: Self::Variable);

    /// Assert that the two variables are equal
    fn assert_equal(&mut self, x: Self::Variable, y: Self::Variable);

    fn add_constraint(&mut self, x: Self::Variable);

    fn constrain_boolean(&mut self, x: Self::Variable);

    /// Compute the square a field element
    fn square(&mut self, res: Self::Position, x: Self::Variable) -> Self::Variable;

    /// Flagged as unsafe as it does require an additional range check
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned value; callers must assert the
    /// relationship with the source variable `x` and that the returned value
    /// fits in `highest_bit - lowest_bit` bits.
    unsafe fn bitmask_be(
        &mut self,
        x: &Self::Variable,
        highest_bit: u32,
        lowest_bit: u32,
        position: Self::Position,
    ) -> Self::Variable;

    /// Fetch an input of the application
    // Witness-only
    fn fetch_input(&mut self, res: Self::Position) -> Self::Variable;

    /// Reset the environment to build the next row
    fn reset(&mut self);

    /// Return the folding combiner
    fn coin_folding_combiner(&mut self, pos: Self::Position) -> Self::Variable;

    /// Compute the x^5 of the given variable
    fn compute_x5(&self, x: Self::Variable) -> Self::Variable {
        let x_square = x.clone() * x.clone();
        let x_cubed = x_square.clone() * x.clone();
        x_cubed * x_square.clone()
    }

    // ---- Poseidon gadget -----
    /// Load the state of the Poseidon hash function into the environment
    fn load_poseidon_state(&mut self, pos: Self::Position, i: usize) -> Self::Variable;

    /// Save the state of poseidon into the environment
    ///
    /// # Safety
    ///
    /// It does not have any effect on the constraints
    unsafe fn save_poseidon_state(&mut self, v: Self::Variable, i: usize);

    /// Return the Poseidon round constants as a constant.
    fn get_poseidon_round_constant(&self, round: usize, i: usize) -> Self::Variable;

    /// Return the requested MDS matrix coefficient
    fn get_poseidon_mds_matrix(&mut self, i: usize, j: usize) -> Self::Variable;

    /// Load the value to absorb at the current step at the position given by
    /// `pos`.
    ///
    /// The values and the absorption order is defined by the
    /// state of the environment itself.
    ///
    /// IMPROVEME: we could have in the environment an heterogeneous typed list,
    /// and we pop values call after call. However, we try to keep the
    /// interpreter simple.
    ///
    /// # Safety
    ///
    /// No constraint is added. It should be used with caution.
    unsafe fn fetch_value_to_absorb(&mut self, pos: Self::Position) -> Self::Variable;
    // -------------------------

    /// Check if the points given by (x1, y1) and (x2, y2) are equals.
    ///
    /// # Safety
    ///
    /// No constraint is added. It should be used with caution.
    unsafe fn is_same_ec_point(
        &mut self,
        pos: Self::Position,
        x1: Self::Variable,
        y1: Self::Variable,
        x2: Self::Variable,
        y2: Self::Variable,
    ) -> Self::Variable;

    /// Inverse of a variable
    ///
    /// # Safety
    ///
    /// Zero is not allowed as an input.
    /// Witness only
    // IMPROVEME: when computing the witness, we could have an additional column
    // that would stand for the inverse, and compute all inverses at the end
    // using a batch inversion.
    unsafe fn inverse(&mut self, pos: Self::Position, x: Self::Variable) -> Self::Variable;

    /// Compute the coefficient λ used in the elliptic curve addition.
    /// If the two points are the same, the λ is computed as follows:
    /// - λ = (3 X1^2 + a) / (2Y1)
    ///
    /// Otherwise, the λ is computed as follows:
    /// - λ = (Y1 - Y2) / (X1 - X2)
    fn compute_lambda(
        &mut self,
        pos: Self::Position,
        is_same_point: Self::Variable,
        x1: Self::Variable,
        y1: Self::Variable,
        x2: Self::Variable,
        y2: Self::Variable,
    ) -> Self::Variable;

    /// Double the elliptic curve point given by the affine coordinates
    /// `(x1, y1)` and save the result in the registers `pos_x` and `pos_y`.
    /// The last argument, `row`, is used to decide if the result should be
    /// written in the current or the next row of the variable position `pos_x`
    /// and `pos_y`.
    fn double_ec_point(
        &mut self,
        pos_x: Self::Position,
        pos_y: Self::Position,
        x1: Self::Variable,
        y1: Self::Variable,
    ) -> (Self::Variable, Self::Variable);

    /// Load the affine coordinates of the elliptic curve point currently saved
    /// in the temporary accumulators. Temporary accumulators could be seen as
    /// a CPU cache, an intermediate storage between the RAM (random access
    /// memory) and the CPU registers (memory cells that are constrained).
    ///
    /// For now, it can only be used to load affine coordinates of elliptic
    /// curve points given in the short Weierstrass form.
    ///
    /// Temporary accumulators could also be seen as return values of a function.
    ///
    /// # Safety
    ///
    /// No constraints are enforced. It is not also enforced that the
    /// accumulators have been cleaned between two different gadgets.
    unsafe fn load_temporary_accumulators(
        &mut self,
        pos_x: Self::Position,
        pos_y: Self::Position,
        side: Side,
    ) -> (Self::Variable, Self::Variable);

    /// Save temporary accumulators into the environment
    ///
    /// # Safety
    ///
    /// It does not have any effect on the constraints.
    unsafe fn save_temporary_accumulators(
        &mut self,
        _v1: Self::Variable,
        _v2: Self::Variable,
        _side: Side,
    );
}

/// Run the application
pub fn run_app<E: InterpreterEnv>(env: &mut E) {
    let x1 = {
        let pos = env.allocate();
        env.fetch_input(pos)
    };
    let _x1_square = {
        let res = env.allocate();
        env.square(res, x1.clone())
    };
}

/// Run an iteration of the IVC scheme
///
/// It consists of the following steps:
/// 1. Compute the hash of the public input.
/// 2. Compute the elliptic curve addition.
/// 3. Run the polynomial-time function.
/// 4. Compute the hash of the output.
///
/// The environment is updated over time.
/// When the environment is the one described in the [Witness
/// environment](crate::witness::Env), the structure will be updated
/// with the new accumulator, the new public input, etc. The public output will
/// be in the structure also. The user can simply rerun the function for the
/// next iteration.
///
/// A row must be created to generate a challenge to combine the constraints
/// later. The challenge will be also accumulated over time.
///
/// FIXME: the resulting constraints do not include the selectors, yet. The
/// resulting constraints must be multiplied by the corresponding selectors.
pub fn run_ivc<E: InterpreterEnv>(env: &mut E, instr: Instruction) {
    match instr {
        Instruction::EllipticCurveScaling(i_comm, processing_bit) => {
            assert!(processing_bit < MAXIMUM_FIELD_SIZE_IN_BITS, "Invalid bit index. The fields are maximum on {MAXIMUM_FIELD_SIZE_IN_BITS} bits, therefore we cannot process the bit {processing_bit}");
            assert!(i_comm < NUMBER_OF_COLUMNS, "Invalid index. We do only support the scaling of the commitments to the columns, for now. We must additionally support the scaling of cross-terms and error terms");
            debug!("Processing scaling of commitment {i_comm}, bit {processing_bit}");
            // When processing the first bit, we must load the scalar, and it
            // comes from previous computation.
            // The two first columns are supposed to be used for the output.
            // It will be used to write the result of the scalar multiplication
            // in the next row.
            let res_col_x = env.allocate();
            let res_col_y = env.allocate();
            let tmp_col_x = env.allocate();
            let tmp_col_y = env.allocate();
            let scalar_col = env.allocate();
            let next_row_res_col_x = env.allocate_next_row();
            let next_row_res_col_y = env.allocate_next_row();
            let next_row_tmp_col_x = env.allocate_next_row();
            let next_row_tmp_col_y = env.allocate_next_row();
            let next_row_scalar_col = env.allocate_next_row();

            // For the bit, we do have two cases. If we are processing the first
            // bit, we must load the bit from a previous computed value. In the
            // case of folding, it will be the output of the Poseidon hash.
            // Therefore we do need the permutation argument.
            // If it is not the first bit, we suppose the previous value has
            // been written in the previous step in the current row.
            let scalar = if processing_bit == 0 {
                env.coin_folding_combiner(scalar_col)
            } else {
                env.read_position(scalar_col)
            };
            // FIXME: we do add the blinder. We must subtract it at the end.
            // Perform the following algorithm (double-and-add):
            // res = O <-- blinder
            // tmp = P
            // for i in 0..256:
            //   if r[i] == 1:
            //     res = res + tmp
            //   tmp = tmp + tmp
            //
            // - `processing_bit` is the i-th bit of the scalar, i.e. i in the loop
            // described above.
            // - `i_comm` is used to fetch the commitment.
            //
            // If it is the first bit, we must load the commitment using the
            // permutation argument.
            // FIXME: the initial value of the result should be a non-zero
            // point. However, it must be a public value otherwise the prover
            // might lie on the initial value.
            // We do have 15 public inputs on each row, we could use some of them.
            let (res_x, res_y) = if processing_bit == 0 {
                // Load the commitment
                unsafe { env.load_temporary_accumulators(res_col_x, res_col_y, Side::Right) }
            } else {
                // Otherwise, the previous step has written the previous result
                // in its "next row", i.e. this row.
                let res_x = { env.read_position(res_col_x) };
                let res_y = { env.read_position(res_col_y) };
                (res_x, res_y)
            };
            // Same for the accumulated temporary value
            let (tmp_x, tmp_y) = if processing_bit == 0 {
                unsafe { env.load_temporary_accumulators(tmp_col_x, tmp_col_y, Side::Left) }
            } else {
                (env.read_position(tmp_col_x), env.read_position(tmp_col_y))
            };
            // Conditional addition:
            // if bit == 1, then res = tmp + res
            // else res = res
            // First we compute tmp + res
            // FIXME: we do suppose that res != tmp -> no doubling and no check
            // if they are the same
            // IMPROVEME: reuse elliptic curve addition
            let (res_plus_tmp_x, res_plus_tmp_y) = {
                let lambda = {
                    let pos = env.allocate();
                    env.compute_lambda(
                        pos,
                        env.zero(),
                        tmp_x.clone(),
                        tmp_y.clone(),
                        res_x.clone(),
                        res_y.clone(),
                    )
                };
                // x3 = λ^2 - x1 - x2
                let x3 = {
                    let pos = env.allocate();
                    let lambda_square = lambda.clone() * lambda.clone();
                    let res = lambda_square.clone() - tmp_x.clone() - res_x.clone();
                    env.write_column(pos, res)
                };
                // y3 = λ (x1 - x3) - y1
                let y3 = {
                    let pos = env.allocate();
                    let x1_minus_x3 = tmp_x.clone() - x3.clone();
                    let res = lambda.clone() * x1_minus_x3.clone() - tmp_y.clone();
                    env.write_column(pos, res)
                };
                (x3, y3)
            };
            // tmp = tmp + tmp
            // Compute the double of the temporary value
            // The slope is saved in a column created in the call to
            // `double_ec_point`
            // We ignore the result as it will be used at the next step only.
            let (_double_tmp_x, _double_tmp_y) = {
                env.double_ec_point(
                    next_row_tmp_col_x,
                    next_row_tmp_col_y,
                    tmp_x.clone(),
                    tmp_y.clone(),
                )
            };
            let bit = {
                let pos = env.allocate();
                unsafe { env.bitmask_be(&scalar, 1, 0, pos) }
            };
            // Checking it is a boolean -> degree 2
            env.constrain_boolean(bit.clone());
            let next_scalar = {
                unsafe {
                    env.bitmask_be(
                        &scalar,
                        MAXIMUM_FIELD_SIZE_IN_BITS.try_into().unwrap(),
                        1,
                        next_row_scalar_col,
                    )
                }
            };
            // Degree 1
            env.assert_equal(
                scalar.clone(),
                bit.clone() + env.constant(BigInt::from(2)) * next_scalar.clone(),
            );
            let _x3 = {
                let res = bit.clone() * res_plus_tmp_x.clone()
                    + (env.one() - bit.clone()) * res_x.clone();
                env.write_column(next_row_res_col_x, res)
            };
            let _y3 = {
                let res = bit.clone() * res_plus_tmp_y.clone()
                    + (env.one() - bit.clone()) * res_y.clone();
                env.write_column(next_row_res_col_y, res)
            };
        }
        Instruction::EllipticCurveAddition(i_comm) => {
            assert!(i_comm < NUMBER_OF_COLUMNS, "Invalid index. We do only support the addition of the commitments to the columns, for now. We must additionally support the scaling of cross-terms and error terms");
            let (x1, y1) = {
                let x1 = env.allocate();
                let y1 = env.allocate();
                unsafe { env.load_temporary_accumulators(x1, y1, Side::Left) }
            };
            let (x2, y2) = {
                let x2 = env.allocate();
                let y2 = env.allocate();
                unsafe { env.load_temporary_accumulators(x2, y2, Side::Right) }
            };
            let is_same_point = {
                let pos = env.allocate();
                unsafe { env.is_same_ec_point(pos, x1.clone(), y1.clone(), x2.clone(), y2.clone()) }
            };
            let lambda = {
                let pos = env.allocate();
                env.compute_lambda(
                    pos,
                    is_same_point,
                    x1.clone(),
                    y1.clone(),
                    x2.clone(),
                    y2.clone(),
                )
            };
            // x3 = λ^2 - x1 - x2
            let x3 = {
                let pos = env.allocate();
                let lambda_square = lambda.clone() * lambda.clone();
                let res = lambda_square.clone() - x1.clone() - x2.clone();
                env.write_column(pos, res)
            };
            // y3 = λ (x1 - x3) - y1
            {
                let pos = env.allocate();
                let x1_minus_x3 = x1.clone() - x3.clone();
                let res = lambda.clone() * x1_minus_x3.clone() - y1.clone();
                env.write_column(pos, res)
            };
        }
        Instruction::PoseidonFullRound(starting_round) => {
            assert!(
                starting_round < PlonkSpongeConstants::PERM_ROUNDS_FULL,
                "Invalid round index. Only values below {} are allowed.",
                PlonkSpongeConstants::PERM_ROUNDS_FULL
            );
            assert!(
                starting_round.is_multiple_of(5),
                "Invalid round index. Only values that are multiple of 5 are allowed."
            );
            debug!(
                "Executing instruction Poseidon starting from round {starting_round} to {}",
                starting_round + 5
            );

            let round_input_positions: Vec<E::Position> = (0..PlonkSpongeConstants::SPONGE_WIDTH)
                .map(|_i| env.allocate())
                .collect();

            let round_output_positions: Vec<E::Position> = (0..PlonkSpongeConstants::SPONGE_WIDTH)
                .map(|_i| env.allocate_next_row())
                .collect();

            let state: Vec<E::Variable> = if starting_round == 0 {
                round_input_positions
                    .iter()
                    .enumerate()
                    .map(|(i, pos)| env.load_poseidon_state(*pos, i))
                    .collect()
            } else {
                round_input_positions
                    .iter()
                    .map(|pos| env.read_position(*pos))
                    .collect()
            };

            // 5 is the number of rounds we treat per row
            (0..5).fold(state, |state, idx_round| {
                let state: Vec<E::Variable> =
                    state.iter().map(|x| env.compute_x5(x.clone())).collect();

                let round = starting_round + idx_round;

                let rcs: Vec<E::Variable> = (0..PlonkSpongeConstants::SPONGE_WIDTH)
                    .map(|i| env.get_poseidon_round_constant(round, i))
                    .collect();

                let state: Vec<E::Variable> = rcs
                    .iter()
                    .enumerate()
                    .map(|(i, rc)| {
                        let acc: E::Variable =
                            state.iter().enumerate().fold(env.zero(), |acc, (j, x)| {
                                acc + env.get_poseidon_mds_matrix(i, j) * x.clone()
                            });
                        // The last iteration is written on the next row.
                        if idx_round == 4 {
                            env.write_column(round_output_positions[i], acc + rc.clone())
                        } else {
                            // Otherwise, we simply allocate a new position
                            // in the circuit.
                            let pos = env.allocate();
                            env.write_column(pos, acc + rc.clone())
                        }
                    })
                    .collect();

                // If we are at the last round, we save the state in the
                // environment.
                // FIXME/IMPROVEME: we might want to execute more Poseidon
                // full hash in sequentially, and then save one row. For
                // now, we will save the state at the end of the last round
                // and reload it at the beginning of the next Poseidon full
                // hash.
                if round == PlonkSpongeConstants::PERM_ROUNDS_FULL - 1 {
                    state.iter().enumerate().for_each(|(i, x)| {
                        unsafe { env.save_poseidon_state(x.clone(), i) };
                    });
                };

                state
            });
        }
        Instruction::PoseidonSpongeAbsorb => {
            let round_input_positions: Vec<E::Position> = (0..PlonkSpongeConstants::SPONGE_WIDTH
                - 1)
                .map(|_i| env.allocate())
                .collect();

            let state: Vec<E::Variable> = round_input_positions
                .iter()
                .enumerate()
                .map(|(i, pos)| env.load_poseidon_state(*pos, i + 1))
                .collect();

            let values_to_absorb: Vec<E::Variable> = (0..PlonkSpongeConstants::SPONGE_WIDTH - 1)
                .map(|_i| unsafe {
                    let pos = env.allocate();
                    env.fetch_value_to_absorb(pos)
                })
                .collect();

            let output: Vec<E::Variable> = state
                .iter()
                .zip(values_to_absorb.iter())
                .map(|(s, v)| {
                    let pos = env.allocate();
                    env.write_column(pos, s.clone() + v.clone())
                })
                .collect();

            output
                .iter()
                .enumerate()
                .for_each(|(i, o)| unsafe { env.save_poseidon_state(o.clone(), i + 1) })
        }
        Instruction::NoOp => {}
    }

    // Compute the hash of the public input
    // FIXME: add the verification key. We should have a hash of it.
}

/// Describe the control-flow for the verifier circuit.
pub fn fetch_next_instruction(current_instruction: Instruction) -> Instruction {
    match current_instruction {
        Instruction::PoseidonFullRound(i) => {
            if i < PlonkSpongeConstants::PERM_ROUNDS_FULL - 5 {
                Instruction::PoseidonFullRound(i + 5)
            } else {
                // FIXME: for now, we continue absorbing because the current
                // code, while fetching the values to absorb, raises an
                // exception when we absorbed everythimg, and the main file
                // handles the halt by filling as many rows as expected (see
                // [VERIFIER_CIRCUIT_SIZE]).
                Instruction::PoseidonSpongeAbsorb
            }
        }
        Instruction::PoseidonSpongeAbsorb => {
            // Whenever we absorbed a value, we run the permutation.
            Instruction::PoseidonFullRound(0)
        }
        Instruction::EllipticCurveScaling(i_comm, bit) => {
            // TODO: we still need to subtract (or not?) the blinder.
            // Maybe we can avoid this by aggregating them.
            // TODO: we also need to aggregate the cross-terms.
            // Therefore i_comm must also take into the account the number
            // of cross-terms.
            assert!(i_comm < NUMBER_OF_COLUMNS, "Maximum number of columns reached ({NUMBER_OF_COLUMNS}), increase the number of columns");
            assert!(bit < MAXIMUM_FIELD_SIZE_IN_BITS, "Maximum number of bits reached ({MAXIMUM_FIELD_SIZE_IN_BITS}), increase the number of bits");
            if bit < MAXIMUM_FIELD_SIZE_IN_BITS - 1 {
                Instruction::EllipticCurveScaling(i_comm, bit + 1)
            } else if i_comm < NUMBER_OF_COLUMNS - 1 {
                Instruction::EllipticCurveScaling(i_comm + 1, 0)
            } else {
                // We have computed all the bits for all the columns
                Instruction::NoOp
            }
        }
        Instruction::EllipticCurveAddition(i_comm) => {
            if i_comm < NUMBER_OF_COLUMNS - 1 {
                Instruction::EllipticCurveAddition(i_comm + 1)
            } else {
                Instruction::NoOp
            }
        }
        Instruction::NoOp => Instruction::NoOp,
    }
}
