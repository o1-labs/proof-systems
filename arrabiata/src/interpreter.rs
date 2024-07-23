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
//! For the Nova IVC scheme, we describe below the different gadgets and how
//! they are implemented with this abstraction.
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
//! - λ = (Y2 - Y1) / (X2 - X1)
//! - X3 = λ^2 - X1 - X2
//! - Y3 = λ (X3 - X1) + Y1
//! ```
//!
//! Therefore, the addition of elliptic curve points can be computed using the
//! following degree-2 constraints
//!
//! ```text
//! - Constraint 1: λ (X2 - X1) - Y2 - Y1 = 0
//! - Constraint 2: X3 + X1 + X2 - λ^2 = 0
//! - Constraint 3: Y3 - λ (X3 - X1) - Y1 = 0
//! ```
//!
//! The gadget requires therefore 7 columns.
//!
//! ### Hash - Poseidon
//!
//! Hashing is a crucial part of the Nova IVC scheme. The hash function the
//! interpreter does use for the moment is an instance of the Poseidon hash
//! function with a fixed state size of 3. Increasing the state size can be a
//! considerable option as it would potentially optimize the number of rounds,
//! and allow hashing more data on one row. We leave this for future works.
//!
//! A direct optimisation would be to use
//! [Poseidon2](https://eprint.iacr.org/2023/323) as its performance on CPU is
//! better, for the same security level and the same cost in circuit. We leave
//! this for future works.
//!
//! For a first version, we consider an instance of the Poseidon hash function
//! that it suitable for curves whose field size is around 256 bits.
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
//! The Nova IVC scheme requires to perform scalar multiplications on elliptic
//! curve points. The scalar multiplication is computed using the double-and-add
//! algorithm.
//! First, the scalar is converted to its binary representation. We do use 17
//! rows using 17 columns to compute the 256 bits of the scalar.
//!
//! On a first row, we decompose the scalar into 16 bits chunks, with additional
//! range check constraints.
//! On the next 16 rows, we split each 16 chunks into 16 bits chunks.
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
//! Using this technique requires us a folding scheme that handles degree 3
//! constraints, as the challenge will be considered as a variable.
//! The reader can refer to the folding library available in this monorepo for
//! more contexts.

use crate::POSEIDON_ROUNDS_FULL;
use ark_ff::{One, Zero};
use log::debug;
use num_bigint::BigUint;

// FIXME: Can we use an "instruction" kind of circuit?
// We do use a "fetch_next_instruction" method to mention what is the next
// gadget/isntruction to run
#[derive(Copy, Clone, Debug)]
pub enum Instruction {
    SixteenBitsDecomposition,
    BitDecompositionFrom16Bits(usize),
    Poseidon(usize),
    EllipticCurveScaling(usize),
    EllipticCurveAddition(usize),
    // The NoOp will simply do nothing
    NoOp,
}

/// Define the side of the elliptic curve addition.
/// When computing G1 + G2, the interpreter will load G1 and after that G2.
/// This enum is used to decide which side fetching into the cells.
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
    fn write_public_input(&mut self, x: Self::Position, v: BigUint) -> Self::Variable;

    /// Build a variable from the given position
    fn variable(&self, position: Self::Position) -> Self::Variable;

    fn constant(&self, v: BigUint) -> Self::Variable;

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
    unsafe fn get_sixteen_bits_chunks_folding_combiner(
        &mut self,
        pos: Self::Position,
        i: u32,
    ) -> Self::Variable;

    /// Compute the x^5 of the given variable
    fn compute_x5(&self, x: Self::Variable) -> Self::Variable {
        let x_square = x.clone() * x.clone();
        let x_cubed = x_square.clone() * x.clone();
        x_cubed * x_square.clone()
    }

    /// Get the state of the Poseidon hash function
    fn get_poseidon_state(&mut self, pos: Self::Position, i: usize) -> Self::Variable;

    fn update_poseidon_state(&mut self, v: Self::Variable, i: usize);

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
                    acc - env.constant(BigUint::from(1_usize) << (i * 16)) * x.clone()
                });
            env.assert_zero(cstr);
        }
        Instruction::BitDecompositionFrom16Bits(i) => {
            if i < 16 {
                // FIXME: simulate a RW into a memory cell. Not necessarily
                // constrained?
                let sixteen_i = {
                    let pos = env.allocate();
                    unsafe { env.get_sixteen_bits_chunks_folding_combiner(pos, i as u32) }
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
                        acc - env.constant(BigUint::from(1_usize) << i) * x.clone()
                    });
                env.assert_zero(cstr);
            } else {
                panic!("Invalid index: it is supposed to be less than 16 as we fetch 16 chunks of 16bits.");
            }
        }
        Instruction::EllipticCurveScaling(i_comm) => {
            panic!("Not implemented yet for {i_comm}")
        }
        Instruction::EllipticCurveAddition(i_comm) => {
            let (_x1, _y1) = {
                let x1 = env.allocate();
                let y1 = env.allocate();
                env.load_ec_point(x1, y1, i_comm, ECAdditionSide::Left)
            };
            let (_x2, _y2) = {
                let x2 = env.allocate();
                let y2 = env.allocate();
                env.load_ec_point(x2, y2, i_comm, ECAdditionSide::Right)
            };
        }
        Instruction::Poseidon(curr_round) => {
            debug!("Executing instruction Poseidon({curr_round})");
            if curr_round < POSEIDON_ROUNDS_FULL {
                let x0 = {
                    let pos = env.allocate();
                    env.get_poseidon_state(pos, 0)
                };
                let x1 = {
                    let pos = env.allocate();
                    env.get_poseidon_state(pos, 1)
                };
                let x2 = {
                    let pos = env.allocate();
                    env.get_poseidon_state(pos, 2)
                };
                let mut state: Vec<E::Variable> = vec![x0, x1, x2];

                (0..4).for_each(|i| {
                    let x0_five = env.compute_x5(state[0].clone());
                    let x1_five = env.compute_x5(state[1].clone());
                    let x2_five = env.compute_x5(state[2].clone());

                    let round = curr_round + i;
                    let rc_0 = {
                        let pos = env.allocate_public_input();
                        env.get_poseidon_round_constant(pos, round, 0)
                    };
                    let rc_1 = {
                        let pos = env.allocate_public_input();
                        env.get_poseidon_round_constant(pos, round, 1)
                    };
                    let rc_2 = {
                        let pos = env.allocate_public_input();
                        env.get_poseidon_round_constant(pos, round, 2)
                    };

                    let x0_prime = {
                        let pos = env.allocate();
                        let res = env.get_poseidon_mds_matrix(0, 0) * x0_five.clone()
                            + env.get_poseidon_mds_matrix(0, 1) * x1_five.clone()
                            + env.get_poseidon_mds_matrix(0, 2) * x2_five.clone()
                            + rc_0.clone();
                        let x0_prime = env.write_column(pos, res.clone());
                        env.assert_equal(x0_prime.clone(), res);
                        x0_prime
                    };
                    let x1_prime = {
                        let pos = env.allocate();
                        let res = env.get_poseidon_mds_matrix(1, 0) * x0_five.clone()
                            + env.get_poseidon_mds_matrix(1, 1) * x1_five.clone()
                            + env.get_poseidon_mds_matrix(1, 2) * x2_five.clone()
                            + rc_1.clone();
                        let x1_prime = env.write_column(pos, res.clone());
                        env.assert_equal(x1_prime.clone(), res);
                        x1_prime
                    };
                    let x2_prime = {
                        let pos = env.allocate();
                        let res = env.get_poseidon_mds_matrix(2, 0) * x0_five.clone()
                            + env.get_poseidon_mds_matrix(2, 1) * x1_five.clone()
                            + env.get_poseidon_mds_matrix(2, 2) * x2_five.clone()
                            + rc_2.clone();
                        let x2_prime = env.write_column(pos, res.clone());
                        env.assert_equal(x2_prime.clone(), res);
                        x2_prime
                    };

                    state[0] = x0_prime;
                    state[1] = x1_prime;
                    state[2] = x2_prime;
                });

                env.update_poseidon_state(state[0].clone(), 0);
                env.update_poseidon_state(state[1].clone(), 1);
                env.update_poseidon_state(state[2].clone(), 2);
            } else {
                panic!("Invalid index: it is supposed to be less than {POSEIDON_ROUNDS_FULL}");
            }
        }
        Instruction::NoOp => {}
    }

    // Compute the hash of the public input
    // FIXME: add the verification key. We should have a hash of it.
}
