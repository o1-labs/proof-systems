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
//! ## Gadgets implemented
//!
//! ### Elliptic curve addition
//!
//! The Nova augmented circuit requires to perform elliptic curve operations, in
//! particular additions and scalar multiplications.
//!
//! To reduce the number of operations, we consider the affine coordinates.
//! As a reminder, here the equations to compute the addition of two different
//! points `P1 = (X1, Y1)` and `P2 = (X2, Y2)`. Let define `P3 = (X3, Y3) = P1 +
//! P2`.
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
//! FIXME: supports negation and the infinity point.
//!
//! The gadget requires therefore 7 columns.
//!
//! ### Hash - Poseidon
//!
//! Hashing is a crucial part of the IVC scheme. The hash function the
//! interpreter does use for the moment is an instance of the Poseidon hash
//! function with a fixed state size of [POSEIDON_STATE_SIZE]. Increasing the
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
//! We start with the assumption that 17 columns are available for the whole
//! circuit, and we can support constraints up to degree 5.
//! Therefore, we can compute 4 full rounds per row.
//!
//! FIXME: we can do one more by using "the next row". Also, we can optimize
//! this by using a partial/full round instance of Poseidon. We leave this when
//! we move to Poseidon2.
//!
//! ### Elliptic curve scalar multiplication
//!
//! The Nova-based IVC schemes require to perform scalar multiplications on
//! elliptic curve points. The scalar multiplication is computed using the
//! double-and-add algorithm.
//! First, the scalar is converted to its binary representation. We do use 17
//! rows using 17 columns to compute the 256 bits of the scalar.
//!
//! On a first row, we decompose the scalar into 16 bits chunks, with additional
//! range check constraints.
//! On the next 16 rows, we split each 16 chunks into 16 bits chunks.
//!
//! FIXME: we could avoid the lookup and simply decomposing on 17 rows, with
//! chunks of 15 bits (usual method).
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
//! The reader can refer to the folding library available in this monorepo for
//! more contexts.

use crate::{
    MAXIMUM_FIELD_SIZE_IN_BITS, NUMBER_OF_COLUMNS, POSEIDON_ROUNDS_FULL, POSEIDON_STATE_SIZE,
};
use ark_ff::{One, Zero};
use log::debug;
use num_bigint::BigInt;

/// A list of instruction/gadget implemented in the interpreter.
/// The control flow can be managed by implementing a function
/// `fetch_next_instruction` and `fetch_instruction` on a witness environnement.
/// See the [Witness environment](crate::witness::Env) for more details.
///
/// Mostly, the instructions will be used to build the IVC circuit, but it can be
/// generalized.
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
    SixteenBitsDecomposition,
    BitDecompositionFrom16Bits(usize),
    Poseidon(usize),
    EllipticCurveScaling(usize, u64),
    EllipticCurveAddition(usize),
    // The NoOp will simply do nothing
    NoOp,
}

/// Define the side of the elliptic curve addition.
/// When computing G1 + G2, the interpreter will load G1 and after that G2.
/// This enum is used to decide which side fetching into the cells.
// FIXME: It is now used by temporary accumulators. We should rename this.
pub enum ECAdditionSide {
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
        + std::ops::Add<Self::Variable, Output = Self::Variable>
        + std::ops::Sub<Self::Variable, Output = Self::Variable>
        + std::ops::Mul<Self::Variable, Output = Self::Variable>
        + std::fmt::Debug
        + Zero
        + One;

    /// Allocate a new variable in the circuit
    fn allocate(&mut self) -> Self::Position;

    fn allocate_public_input(&mut self) -> Self::Position;

    fn write_column(&mut self, col: Self::Position, v: Self::Variable) -> Self::Variable;

    /// Write the corresponding public inputs.
    // FIXME: This design might not be the best. Feel free to come up with a
    // better solution. The PI should be static for all witnesses
    fn write_public_input(&mut self, x: Self::Position, v: BigInt) -> Self::Variable;

    /// Build the constant zero
    fn zero(&self) -> Self::Variable;

    /// Build the constant one
    fn one(&self) -> Self::Variable;

    fn constant(&self, v: BigInt) -> Self::Variable;

    /// Assert that the variable is zero
    fn assert_zero(&mut self, x: Self::Variable);

    /// Assert that the two variables are equal
    fn assert_equal(&mut self, x: Self::Variable, y: Self::Variable);

    /// Check if the variable is between [0, 2^16 - 1]
    fn range_check16(&mut self, x: Self::Position);

    fn add_constraint(&mut self, x: Self::Variable);

    fn constrain_boolean(&mut self, x: Self::Variable);

    /// Compute the square a field element
    fn square(&mut self, res: Self::Position, x: Self::Variable) -> Self::Variable;

    /// Flagged as unsafe as it does require an additional range check
    ///
    /// # Safety
    ///
    /// There are no constraints on the returned value; callers must assert the relationship with
    /// the source variable `x` and that the returned value fits in `highest_bit - lowest_bit`
    /// bits.
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

    /// Get the 16bits chunks of the folding combiner, and save it into `pos`.
    ///
    /// # Safety
    ///
    /// There are no constraints saying that it is actually the previous
    /// computed value. We should do something like a runtime lookup/permutation
    /// check. It is left for when the lookup is implemented.
    unsafe fn read_sixteen_bits_chunks_folding_combiner(
        &mut self,
        pos: Self::Position,
        i: u32,
    ) -> Self::Variable;

    /// Read the i-th bit of the folding combiner, in little endian, and safe it
    /// in the column given by `pos`.
    ///
    /// # Safety
    ///
    /// There is no check that the output is actually a boolean
    unsafe fn read_bit_of_folding_combiner(
        &mut self,
        pos: Self::Position,
        i: u64,
    ) -> Self::Variable;

    /// Compute the x^5 of the given variable
    fn compute_x5(&self, x: Self::Variable) -> Self::Variable {
        let x_square = x.clone() * x.clone();
        let x_cubed = x_square.clone() * x.clone();
        x_cubed * x_square.clone()
    }

    /// Load the state of the Poseidon hash function into the environment
    fn load_poseidon_state(&mut self, pos: Self::Position, i: usize) -> Self::Variable;

    /// Save the state of poseidon into the environment
    ///
    /// # Safety
    ///
    /// It does not have any effect on the constraints
    unsafe fn save_poseidon_state(&mut self, v: Self::Variable, i: usize);

    fn get_poseidon_round_constant(
        &mut self,
        pos: Self::Position,
        round: usize,
        i: usize,
    ) -> Self::Variable;

    /// Return the requested MDS matrix coefficient
    fn get_poseidon_mds_matrix(&mut self, i: usize, j: usize) -> Self::Variable;

    /// Load the affine coordinates of the elliptic curve point given by the
    /// index `i` into the cell `pos_x` and `pos_y`.
    fn load_ec_point(
        &mut self,
        pos_x: Self::Position,
        pos_y: Self::Position,
        i: usize,
        side: ECAdditionSide,
    ) -> (Self::Variable, Self::Variable);

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
        side: ECAdditionSide,
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
        _side: ECAdditionSide,
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

/// Run an iteration of the IVC scheme.
/// It consists of the following steps:
/// 1. Compute the hash of the public input.
/// 2. Compute the elliptic curve addition.
/// 3. Run the polynomial-time function.
/// 4. Compute the hash of the output.
/// The environment is updated over time.
/// When the environment is the one described in the [Witness
/// environment](crate::witness::Env), the structure will be updated
/// with the new accumulator, the new public input, etc. The public output will
/// be in the structure also. The user can simply rerun the function for the
/// next iteration.
/// A row must be created to generate a challenge to combine the constraints
/// later. The challenge will be also accumulated over time.
///
/// FIXME: homogeneize
/// FIXME: compute error terms
pub fn run_ivc<E: InterpreterEnv>(env: &mut E, instr: Instruction) {
    match instr {
        Instruction::SixteenBitsDecomposition => {
            // Decompositing the random coin in chunks of 16 bits. One row.
            // FIXME: verify the combiner is correctly returned from the sponge.
            let r = {
                let pos = env.allocate();
                env.coin_folding_combiner(pos)
            };
            let decomposition_16bits: Vec<E::Variable> = (0..16)
                .map(|i| {
                    let pos = env.allocate();
                    env.range_check16(pos);
                    unsafe { env.bitmask_be(&r, (i + 1) * 16, i * 16, pos) }
                })
                .collect();

            let cstr = decomposition_16bits
                .iter()
                .enumerate()
                .fold(r, |acc, (i, x)| {
                    acc - env.constant(BigInt::from(1_usize) << (i * 16)) * x.clone()
                });
            env.assert_zero(cstr);
        }
        Instruction::BitDecompositionFrom16Bits(i) => {
            if i < 16 {
                // FIXME: simulate a RW into a memory cell. Not necessarily
                // constrained?
                let sixteen_i = {
                    let pos = env.allocate();
                    unsafe { env.read_sixteen_bits_chunks_folding_combiner(pos, i as u32) }
                };
                let bit_decompo: Vec<E::Variable> = (0..16)
                    .map(|j| {
                        let pos = env.allocate();
                        unsafe { env.bitmask_be(&sixteen_i, (j + 1) as u32, j as u32, pos) }
                    })
                    .collect();

                // Contrain to be one or zero
                bit_decompo
                    .iter()
                    .for_each(|x| env.constrain_boolean(x.clone()));

                let cstr = bit_decompo
                    .iter()
                    .enumerate()
                    .fold(sixteen_i, |acc, (i, x)| {
                        acc - env.constant(BigInt::from(1_usize) << i) * x.clone()
                    });
                env.assert_zero(cstr);
            } else {
                panic!("Invalid index: it is supposed to be less than 16 as we fetch 16 chunks of 16bits.");
            }
        }
        Instruction::EllipticCurveScaling(i_comm, processing_bit) => {
            assert!(processing_bit < MAXIMUM_FIELD_SIZE_IN_BITS, "Invalid bit index. The fields are maximum on {MAXIMUM_FIELD_SIZE_IN_BITS} bits, therefore we cannot process the bit {processing_bit}");
            assert!(i_comm < NUMBER_OF_COLUMNS, "Invalid index. We do only support the scaling of the commitments to the columns, for now. We must additionally support the scaling of cross-terms and error terms");
            // FIXME: we do add the blinder. We must substract it at the end.
            // Perform the following algorithm (double-and-add):
            // res = O
            // tmp = P
            // for i in 0..256:
            //   if r[i] == 1:
            //     res = res + tmp
            //   tmp = tmp + tmp
            //
            // - `processing_bit` is the i-th bit of the scalar, i.e. i in the loop
            // described above.
            // - `i_comm` is used to fetch the commitment.
            // The temporary values res and tmp will be stored in the temporary
            // accumulators, and loaded with `load_temporary_accumulators`.
            // At the end of the execution, the temporary accumulators will be
            // saved with `save_temporary_accumulators`.
            let bit = {
                let pos = env.allocate();
                unsafe { env.read_bit_of_folding_combiner(pos, processing_bit) }
            };
            let (tmp_x, tmp_y) = {
                let pos_x = env.allocate();
                let pos_y = env.allocate();
                unsafe { env.load_temporary_accumulators(pos_x, pos_y, ECAdditionSide::Left) }
            };
            let (res_x, res_y) = {
                let pos_x = env.allocate();
                let pos_y = env.allocate();
                unsafe { env.load_temporary_accumulators(pos_x, pos_y, ECAdditionSide::Right) }
            };
            // tmp = tmp + tmp
            // Compute the double of the temporary value
            let (tmp_prime_x, tmp_prime_y) = {
                let pos_x = env.allocate();
                let pos_y = env.allocate();
                env.double_ec_point(pos_x, pos_y, tmp_x.clone(), tmp_y.clone())
            };
            unsafe {
                env.save_temporary_accumulators(tmp_prime_x, tmp_prime_y, ECAdditionSide::Left);
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
            let x3 = {
                let pos = env.allocate();
                let res = bit.clone() * res_plus_tmp_x.clone()
                    + (env.one() - bit.clone()) * res_x.clone();
                env.write_column(pos, res)
            };
            let y3 = {
                let pos = env.allocate();
                let res = bit.clone() * res_plus_tmp_y.clone()
                    + (env.one() - bit.clone()) * res_y.clone();
                env.write_column(pos, res)
            };
            unsafe {
                env.save_temporary_accumulators(x3, y3, ECAdditionSide::Right);
            };
        }
        Instruction::EllipticCurveAddition(i_comm) => {
            let (x1, y1) = {
                let x1 = env.allocate();
                let y1 = env.allocate();
                env.load_ec_point(x1, y1, i_comm, ECAdditionSide::Left)
            };
            let (x2, y2) = {
                let x2 = env.allocate();
                let y2 = env.allocate();
                env.load_ec_point(x2, y2, i_comm, ECAdditionSide::Right)
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
        Instruction::Poseidon(curr_round) => {
            debug!("Executing instruction Poseidon({curr_round})");
            if curr_round < POSEIDON_ROUNDS_FULL {
                let state: Vec<E::Variable> = (0..POSEIDON_STATE_SIZE)
                    .map(|i| {
                        let pos = env.allocate();
                        env.load_poseidon_state(pos, i)
                    })
                    .collect();

                let state = (0..4).fold(state, |state, i| {
                    let state: Vec<E::Variable> =
                        state.iter().map(|x| env.compute_x5(x.clone())).collect();

                    let round = curr_round + i;

                    let rcs: Vec<E::Variable> = (0..POSEIDON_STATE_SIZE)
                        .map(|i| {
                            let pos = env.allocate_public_input();
                            env.get_poseidon_round_constant(pos, round, i)
                        })
                        .collect();

                    let state: Vec<E::Variable> = rcs
                        .iter()
                        .enumerate()
                        .map(|(i, rc)| {
                            let pos = env.allocate();
                            let acc: E::Variable =
                                state.iter().enumerate().fold(env.zero(), |acc, (j, x)| {
                                    acc + env.get_poseidon_mds_matrix(i, j) * x.clone()
                                });
                            env.write_column(pos, acc + rc.clone())
                        })
                        .collect();
                    state
                });

                state.iter().enumerate().for_each(|(i, x)| {
                    unsafe { env.save_poseidon_state(x.clone(), i) };
                })
            } else {
                panic!("Invalid index: it is supposed to be less than {POSEIDON_ROUNDS_FULL}");
            }
        }
        Instruction::NoOp => {}
    }

    // Compute the hash of the public input
    // FIXME: add the verification key. We should have a hash of it.
}
