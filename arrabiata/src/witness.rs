use ark_ec::{models::short_weierstrass::SWCurveConfig, AffineRepr};
use ark_ff::PrimeField;
use ark_poly::Evaluations;
use kimchi::circuits::{domains::EvaluationDomains, gate::CurrOrNext};
use log::{debug, info};
use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use o1_utils::field_helpers::FieldHelpers;
use poly_commitment::{commitment::CommitmentCurve, ipa::SRS, PolyComm, SRS as _};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use std::time::Instant;

use crate::{
    columns::{Column, Gadget},
    interpreter::{Instruction, InterpreterEnv, Side},
    poseidon_3_60_0_5_5_fp, poseidon_3_60_0_5_5_fq, BIT_DECOMPOSITION_NUMBER_OF_CHUNKS,
    MAXIMUM_FIELD_SIZE_IN_BITS, NUMBER_OF_COLUMNS, NUMBER_OF_PUBLIC_INPUTS, NUMBER_OF_SELECTORS,
    NUMBER_OF_VALUES_TO_ABSORB_PUBLIC_IO, POSEIDON_ALPHA, POSEIDON_ROUNDS_FULL,
    POSEIDON_STATE_SIZE,
};

pub const IVC_STARTING_INSTRUCTION: Instruction = Instruction::Poseidon(0);

/// An environment that can be shared between IVC instances.
///
/// It contains all the accumulators that can be picked for a given fold
/// instance k, including the sponges.
///
/// The environment is run over big integers to avoid performing
/// reduction at all step. Instead the user implementing the interpreter can
/// reduce in the corresponding field when they want.
pub struct Env<
    Fp: PrimeField,
    Fq: PrimeField,
    E1: AffineRepr<ScalarField = Fp, BaseField = Fq>,
    E2: AffineRepr<ScalarField = Fq, BaseField = Fp>,
> {
    // ----------------
    // Setup related (domains + SRS)
    /// Domain for Fp
    pub domain_fp: EvaluationDomains<Fp>,

    /// Domain for Fq
    pub domain_fq: EvaluationDomains<Fq>,

    /// SRS for the first curve
    pub srs_e1: SRS<E1>,

    /// SRS for the second curve
    pub srs_e2: SRS<E2>,
    // ----------------

    // ----------------
    // Information related to the IVC, which will be used by the prover/verifier
    // at the end of the whole execution
    // FIXME: use a blinded comm and also fold the blinder
    pub ivc_accumulator_e1: Vec<PolyComm<E1>>,

    // FIXME: use a blinded comm and also fold the blinder
    pub ivc_accumulator_e2: Vec<PolyComm<E2>>,

    /// Commitments to the previous instances
    pub previous_commitments_e1: Vec<PolyComm<E1>>,
    pub previous_commitments_e2: Vec<PolyComm<E2>>,
    // ----------------

    // ----------------
    // Data only used by the interpreter while building the witness over time
    /// The index of the latest allocated variable in the circuit.
    /// It is used to allocate new variables without having to keep track of the
    /// position.
    pub idx_var: usize,

    pub idx_var_next_row: usize,

    /// The index of the latest allocated public inputs in the circuit.
    /// It is used to allocate new public inputs without having to keep track of
    /// the position.
    pub idx_var_pi: usize,

    /// Current processing row. Used to build the witness.
    pub current_row: usize,

    /// State of the current row in the execution trace
    pub state: [BigInt; NUMBER_OF_COLUMNS],

    /// Next row in the execution trace. It is useful when we deal with
    /// polynomials accessing "the next row", i.e. witness columns where we do
    /// evaluate at ζ and ζω.
    pub next_state: [BigInt; NUMBER_OF_COLUMNS],

    /// Contain the public state
    // FIXME: I don't like this design. Feel free to suggest a better solution
    pub public_state: [BigInt; NUMBER_OF_PUBLIC_INPUTS],

    /// Selectors to activate the gadgets.
    /// The size of the outer vector must be equal to the number of gadgets in
    /// the circuit.
    /// The size of the inner vector must be equal to the number of rows in
    /// the circuit.
    ///
    /// The layout columns/rows is used to avoid rebuilding the arrays per
    /// column when committing to the witness.
    pub selectors: Vec<Vec<bool>>,

    /// While folding, we must keep track of the challenges the verifier would
    /// have sent in the SNARK, and we must aggregate them.
    // FIXME: nothing is done yet, and the challenges haven't been decided yet.
    // See top-level documentation of the interpreter for more information.
    pub challenges: Vec<BigInt>,

    /// Keep the current executed instruction
    /// This can be used to identify which gadget the interpreter is currently
    /// building.
    pub current_instruction: Instruction,

    /// The sponges will be used to simulate the verifier messages, and will
    /// also be used to verify the consistency of the computation by hashing the
    /// public IO.
    // IMPROVEME: use a list of BigInt? It might be faster as the CPU will
    // already have in its cache the values, and we can use a flat array
    pub sponge_e1: [BigInt; POSEIDON_STATE_SIZE],
    pub sponge_e2: [BigInt; POSEIDON_STATE_SIZE],

    /// The current iteration of the IVC
    pub current_iteration: u64,

    /// A previous hash, encoded in 2 chunks of 128 bits.
    pub previous_hash: [u128; 2],

    /// The coin folding combiner will be used to generate the combinaison of
    /// folding instances
    pub r: BigInt,

    /// Temporary registers for elliptic curve points in affine coordinates than
    /// can be used to save values between instructions.
    ///
    /// These temporary registers can be loaded into the state by using the
    /// function `load_temporary_accumulators`.
    ///
    /// The registers can, and must, be cleaned after the gadget is computed.
    ///
    /// The values are considered as BigInt, even though we should add some
    /// type. As we want to apply the KISS method, we tend to avoid adding
    /// types. We leave this for future work.
    ///
    /// Two registers are provided, represented by a tuple for the coordinates
    /// (x, y).
    pub temporary_accumulators: ((BigInt, BigInt), (BigInt, BigInt)),

    /// Index of the values to absorb in the sponge
    pub idx_values_to_absorb: usize,
    // ----------------
    /// The witness of the current instance of the circuit.
    /// The size of the outer vector must be equal to the number of columns in the
    /// circuit.
    /// The size of the inner vector must be equal to the number of rows in
    /// the circuit.
    ///
    /// The layout columns/rows is used to avoid rebuilding the witness per
    /// column when committing to the witness.
    pub witness: Vec<Vec<BigInt>>,

    // --------------
    // Inputs
    /// Initial input
    pub z0: BigInt,

    /// Current input
    pub zi: BigInt,
    // ---------------

    // ---------------
    // Only used to have type safety and think about the design at the
    // type-level
    pub _marker: std::marker::PhantomData<(Fp, Fq, E1, E2)>,
    // ---------------
}

// The condition on the parameters for E1 and E2 is to get the coefficients and
// convert them into biguint.
// The condition SWModelParameters is to get the parameters of the curve as
// biguint to use them to compute the slope in the elliptic curve addition
// algorithm.
impl<
        Fp: PrimeField,
        Fq: PrimeField,
        E1: CommitmentCurve<ScalarField = Fp, BaseField = Fq>,
        E2: CommitmentCurve<ScalarField = Fq, BaseField = Fp>,
    > InterpreterEnv for Env<Fp, Fq, E1, E2>
where
    <E1::Params as ark_ec::CurveConfig>::BaseField: PrimeField,
    <E2::Params as ark_ec::CurveConfig>::BaseField: PrimeField,
{
    type Position = (Column, CurrOrNext);

    /// For efficiency, and for having a single interpreter, we do not use one
    /// of the fields. We use a generic BigInt to represent the values.
    /// When building the witness, we will reduce into the corresponding field.
    // FIXME: it might not be efficient as I initially thought. We do need to
    // make some transformations between biguint and bigint, with an extra cost
    // for allocations.
    type Variable = BigInt;

    fn allocate(&mut self) -> Self::Position {
        assert!(self.idx_var < NUMBER_OF_COLUMNS, "Maximum number of columns reached ({NUMBER_OF_COLUMNS}), increase the number of columns");
        let pos = Column::X(self.idx_var);
        self.idx_var += 1;
        (pos, CurrOrNext::Curr)
    }

    fn allocate_next_row(&mut self) -> Self::Position {
        assert!(self.idx_var_next_row < NUMBER_OF_COLUMNS, "Maximum number of columns reached ({NUMBER_OF_COLUMNS}), increase the number of columns");
        let pos = Column::X(self.idx_var_next_row);
        self.idx_var_next_row += 1;
        (pos, CurrOrNext::Next)
    }

    fn read_position(&self, pos: Self::Position) -> Self::Variable {
        let (col, row) = pos;
        let Column::X(idx) = col else {
            unimplemented!("Only works for private inputs")
        };
        match row {
            CurrOrNext::Curr => self.state[idx].clone(),
            CurrOrNext::Next => self.next_state[idx].clone(),
        }
    }

    fn allocate_public_input(&mut self) -> Self::Position {
        assert!(self.idx_var_pi < NUMBER_OF_PUBLIC_INPUTS, "Maximum number of public inputs reached ({NUMBER_OF_PUBLIC_INPUTS}), increase the number of public inputs");
        let pos = Column::PublicInput(self.idx_var_pi);
        self.idx_var_pi += 1;
        (pos, CurrOrNext::Curr)
    }

    fn write_column(&mut self, pos: Self::Position, v: Self::Variable) -> Self::Variable {
        let (col, row) = pos;
        let Column::X(idx) = col else {
            unimplemented!("Only works for private inputs")
        };
        let modulus: BigInt = if self.current_iteration % 2 == 0 {
            Fp::modulus_biguint().into()
        } else {
            Fq::modulus_biguint().into()
        };
        let v = v.mod_floor(&modulus);
        match row {
            CurrOrNext::Curr => {
                self.state[idx] = v.clone();
            }
            CurrOrNext::Next => {
                self.next_state[idx] = v.clone();
            }
        }
        v
    }

    fn write_public_input(&mut self, pos: Self::Position, v: BigInt) -> Self::Variable {
        let (col, _row) = pos;
        let Column::PublicInput(idx) = col else {
            unimplemented!("Only works for public input columns")
        };
        let modulus: BigInt = if self.current_iteration % 2 == 0 {
            Fp::modulus_biguint().into()
        } else {
            Fq::modulus_biguint().into()
        };
        let v = v.mod_floor(&modulus);
        self.public_state[idx] = v.clone();
        v
    }

    /// Activate the gadget for the current row
    fn activate_gadget(&mut self, gadget: Gadget) {
        // IMPROVEME: it should be called only once per row
        self.selectors[gadget as usize][self.current_row] = true;
    }

    fn constrain_boolean(&mut self, x: Self::Variable) {
        let modulus: BigInt = if self.current_iteration % 2 == 0 {
            Fp::modulus_biguint().into()
        } else {
            Fq::modulus_biguint().into()
        };
        let x = x.mod_floor(&modulus);
        assert!(x == BigInt::from(0_usize) || x == BigInt::from(1_usize));
    }

    fn constant(&self, v: BigInt) -> Self::Variable {
        v
    }

    fn add_constraint(&mut self, _x: Self::Variable) {
        unimplemented!("Only when building the constraints")
    }

    fn assert_zero(&mut self, var: Self::Variable) {
        assert_eq!(var, BigInt::from(0_usize));
    }

    fn assert_equal(&mut self, x: Self::Variable, y: Self::Variable) {
        assert_eq!(x, y);
    }

    // FIXME: it should not be a check, but it should build the related logup
    // values
    // FIXME: we should have additional columns for the lookups.
    // This will be implemented when the first version of the IVC is
    // implemented and we can make recursive arguments
    fn range_check16(&mut self, pos: Self::Position) {
        let (col, _) = pos;
        let Column::X(idx) = col else {
            unimplemented!("Only works for private columns")
        };
        let x = self.state[idx].clone();
        assert!(x < BigInt::from(2_usize).pow(16));
    }

    fn square(&mut self, pos: Self::Position, x: Self::Variable) -> Self::Variable {
        let res = x.clone() * x.clone();
        self.write_column(pos, res.clone());
        res
    }

    /// Flagged as unsafe as it does require an additional range check
    unsafe fn bitmask_be(
        &mut self,
        x: &Self::Variable,
        highest_bit: u32,
        lowest_bit: u32,
        pos: Self::Position,
    ) -> Self::Variable {
        let diff: u32 = highest_bit - lowest_bit;
        if diff == 0 {
            self.write_column(pos, BigInt::from(0_usize))
        } else {
            assert!(
                diff > 0,
                "The difference between the highest and lowest bit should be greater than 0"
            );
            let rht = (BigInt::from(1_usize) << diff) - BigInt::from(1_usize);
            let lft = x >> lowest_bit;
            let res: BigInt = lft & rht;
            self.write_column(pos, res)
        }
    }

    // FIXME: for now, we use the row number and compute the square.
    // This is only for testing purposes, and having something to build the
    // witness.
    fn fetch_input(&mut self, pos: Self::Position) -> Self::Variable {
        let x = BigInt::from(self.current_row as u64);
        self.write_column(pos, x.clone());
        x
    }

    /// Reset the environment to build the next row
    fn reset(&mut self) {
        // Save the current state in the witness
        self.state.iter().enumerate().for_each(|(i, x)| {
            self.witness[i][self.current_row] = x.clone();
        });
        // We increment the row
        // TODO: should we check that we are not going over the domain size?
        self.current_row += 1;
        // We reset the indices for the variables
        self.idx_var = 0;
        self.idx_var_next_row = 0;
        self.idx_var_pi = 0;
        // We keep track of the values we already set.
        self.state = self.next_state.clone();
        // And we reset the next state
        self.next_state = std::array::from_fn(|_| BigInt::from(0_usize));
    }

    /// FIXME: check if we need to pick the left or right sponge
    fn coin_folding_combiner(&mut self, pos: Self::Position) -> Self::Variable {
        let r = if self.current_iteration % 2 == 0 {
            self.sponge_e1[0].clone()
        } else {
            self.sponge_e2[0].clone()
        };
        let (col, _) = pos;
        let Column::X(idx) = col else {
            unimplemented!("Only works for private columns")
        };
        self.state[idx] = r.clone();
        self.r = r.clone();
        r
    }

    unsafe fn read_sixteen_bits_chunks_folding_combiner(
        &mut self,
        pos: Self::Position,
        i: u32,
    ) -> Self::Variable {
        let r = self.r.clone();
        self.bitmask_be(&r, 16 * (i + 1), 16 * i, pos)
    }

    unsafe fn read_bit_of_folding_combiner(
        &mut self,
        pos: Self::Position,
        i: u64,
    ) -> Self::Variable {
        let r = self.r.clone();
        let bit = (r >> i) & BigInt::from(1_usize);
        self.write_column(pos, bit.clone());
        bit
    }

    fn load_poseidon_state(&mut self, pos: Self::Position, i: usize) -> Self::Variable {
        assert!(
            self.selectors[Gadget::PermutationArgument as usize][self.current_row],
            "The permutation argument should be activated"
        );
        let state = if self.current_iteration % 2 == 0 {
            self.sponge_e1[i].clone()
        } else {
            self.sponge_e2[i].clone()
        };
        self.write_column(pos, state)
    }

    fn get_poseidon_round_constant(
        &mut self,
        pos: Self::Position,
        round: usize,
        i: usize,
    ) -> Self::Variable {
        let rc = if self.current_iteration % 2 == 0 {
            poseidon_3_60_0_5_5_fp::static_params().round_constants[round][i]
                .to_biguint()
                .into()
        } else {
            poseidon_3_60_0_5_5_fq::static_params().round_constants[round][i]
                .to_biguint()
                .into()
        };
        self.write_public_input(pos, rc)
    }

    fn get_poseidon_mds_matrix(&mut self, i: usize, j: usize) -> Self::Variable {
        if self.current_iteration % 2 == 0 {
            poseidon_3_60_0_5_5_fp::static_params().mds[i][j]
                .to_biguint()
                .into()
        } else {
            poseidon_3_60_0_5_5_fq::static_params().mds[i][j]
                .to_biguint()
                .into()
        }
    }

    unsafe fn save_poseidon_state(&mut self, x: Self::Variable, i: usize) {
        assert!(
            self.selectors[Gadget::PermutationArgument as usize][self.current_row],
            "The permutation argument should be activated"
        );
        if self.current_iteration % 2 == 0 {
            let modulus: BigInt = Fp::modulus_biguint().into();
            self.sponge_e1[i] = x.mod_floor(&modulus)
        } else {
            let modulus: BigInt = Fq::modulus_biguint().into();
            self.sponge_e2[i] = x.mod_floor(&modulus)
        }
    }

    // The following values are expected to be absorbed in order:
    // - z0
    // - z1
    // - acc[0]
    // - acc[1]
    // - ...
    // - acc[N_COL - 1]
    // FIXME: for now, we will only absorb the accumulators as z0 and z1 are not
    // updated yet.
    unsafe fn fetch_value_to_absorb(
        &mut self,
        pos: Self::Position,
        curr_round: usize,
    ) -> Self::Variable {
        let (col, _) = pos;
        let Column::PublicInput(_idx) = col else {
            panic!("Only works for public inputs")
        };
        // If we are not the round 0, we must absorb nothing.
        if curr_round != 0 {
            self.write_public_input(pos, self.zero())
        } else {
            // FIXME: we must absorb z0, z1 and i!
            // We multiply by 2 as we have two coordinates
            let idx = self.idx_values_to_absorb;
            let res = if idx < 2 * NUMBER_OF_COLUMNS {
                let idx_col = idx / 2;
                debug!("Absorbing the accumulator for the column index {idx_col}. After this, there will still be {} elements to absorb", NUMBER_OF_VALUES_TO_ABSORB_PUBLIC_IO - idx - 1);
                if self.current_iteration % 2 == 0 {
                    let (pt_x, pt_y) = self.ivc_accumulator_e2[idx_col].chunks[0]
                        .to_coordinates()
                        .unwrap();
                    if idx % 2 == 0 {
                        self.write_public_input(pos, pt_x.to_biguint().into())
                    } else {
                        self.write_public_input(pos, pt_y.to_biguint().into())
                    }
                } else {
                    let (pt_x, pt_y) = self.ivc_accumulator_e1[idx_col].chunks[0]
                        .to_coordinates()
                        .unwrap();
                    if idx % 2 == 0 {
                        self.write_public_input(pos, pt_x.to_biguint().into())
                    } else {
                        self.write_public_input(pos, pt_y.to_biguint().into())
                    }
                }
            } else {
                unimplemented!(
                    "We only absorb the accumulators for now. Of course, this is not sound."
                )
            };
            self.idx_values_to_absorb += 1;
            res
        }
    }

    unsafe fn load_temporary_accumulators(
        &mut self,
        pos_x: Self::Position,
        pos_y: Self::Position,
        side: Side,
    ) -> (Self::Variable, Self::Variable) {
        assert!(
            self.selectors[Gadget::PermutationArgument as usize][self.current_row],
            "The permutation argument should be activated"
        );
        match self.current_instruction {
            Instruction::EllipticCurveScaling(i_comm, bit) => {
                // If we're processing the leftmost bit (i.e. bit == 0), we must load
                // the initial value into the accumulators from the environment.
                // In the left accumulator, we keep track of the value we keep doubling.
                // In the right accumulator, we keep the result.
                if bit == 0 {
                    if self.current_iteration % 2 == 0 {
                        match side {
                            Side::Left => {
                                let pt = self.previous_commitments_e2[i_comm].chunks[0];
                                // We suppose we never have a commitment equals to the
                                // point at infinity
                                let (pt_x, pt_y) = pt.to_coordinates().unwrap();
                                let pt_x = self.write_column(pos_x, pt_x.to_biguint().into());
                                let pt_y = self.write_column(pos_y, pt_y.to_biguint().into());
                                (pt_x, pt_y)
                            }
                            // As it is the first iteration, we must use the point at infinity.
                            // However, to avoid handling the case equal to zero, we will
                            // use a blinder, that we will substract at the end.
                            // As we suppose the probability to get a folding combiner
                            // equals to zero is negligible, we know we have a negligible
                            // probability to request to compute `0 * P`.
                            // FIXME: ! check this statement !
                            Side::Right => {
                                let pt = self.srs_e2.h;
                                let (pt_x, pt_y) = pt.to_coordinates().unwrap();
                                let pt_x = self.write_column(pos_x, pt_x.to_biguint().into());
                                let pt_y = self.write_column(pos_y, pt_y.to_biguint().into());
                                (pt_x, pt_y)
                            }
                        }
                    } else {
                        match side {
                            Side::Left => {
                                let pt = self.previous_commitments_e1[i_comm].chunks[0];
                                // We suppose we never have a commitment equals to the
                                // point at infinity
                                let (pt_x, pt_y) = pt.to_coordinates().unwrap();
                                let pt_x = self.write_column(pos_x, pt_x.to_biguint().into());
                                let pt_y = self.write_column(pos_y, pt_y.to_biguint().into());
                                (pt_x, pt_y)
                            }
                            // As it is the first iteration, we must use the point at infinity.
                            // However, to avoid handling the case equal to zero, we will
                            // use a blinder, that we will substract at the end.
                            // As we suppose the probability to get a folding combiner
                            // equals to zero is negligible, we know we have a negligible
                            // probability to request to compute `0 * P`.
                            // FIXME: ! check this statement !
                            Side::Right => {
                                let pt = self.srs_e1.h;
                                let (pt_x, pt_y) = pt.to_coordinates().unwrap();
                                let pt_x = self.write_column(pos_x, pt_x.to_biguint().into());
                                let pt_y = self.write_column(pos_x, pt_y.to_biguint().into());
                                (pt_x, pt_y)
                            }
                        }
                    }
                } else {
                    panic!("We should not load the temporary accumulators for the bits different than 0 when using the elliptic curve scaling. It has been deactivated since we use the 'next row'");
                }
            }
            Instruction::EllipticCurveAddition(i_comm) => {
                // FIXME: we must get the scaled commitment, not simply the commitment
                let (pt_x, pt_y): (BigInt, BigInt) = match side {
                    Side::Left => {
                        if self.current_iteration % 2 == 0 {
                            let pt = self.ivc_accumulator_e2[i_comm].chunks[0];
                            let (x, y) = pt.to_coordinates().unwrap();
                            (x.to_biguint().into(), y.to_biguint().into())
                        } else {
                            let pt = self.ivc_accumulator_e1[i_comm].chunks[0];
                            let (x, y) = pt.to_coordinates().unwrap();
                            (x.to_biguint().into(), y.to_biguint().into())
                        }
                    }
                    Side::Right => {
                        if self.current_iteration % 2 == 0 {
                            let pt = self.previous_commitments_e2[i_comm].chunks[0];
                            let (x, y) = pt.to_coordinates().unwrap();
                            (x.to_biguint().into(), y.to_biguint().into())
                        } else {
                            let pt = self.previous_commitments_e1[i_comm].chunks[0];
                            let (x, y) = pt.to_coordinates().unwrap();
                            (x.to_biguint().into(), y.to_biguint().into())
                        }
                    }
                };
                let pt_x = self.write_column(pos_x, pt_x.clone());
                let pt_y = self.write_column(pos_y, pt_y.clone());
                (pt_x, pt_y)
            }
            _ => unimplemented!("For now, the accumulators can only be used by the elliptic curve scaling gadget and {:?} is not supported. This should be changed as soon as the gadget is implemented.", self.current_instruction),
        }
    }

    unsafe fn save_temporary_accumulators(
        &mut self,
        x: Self::Variable,
        y: Self::Variable,
        side: Side,
    ) {
        assert!(
            self.selectors[Gadget::PermutationArgument as usize][self.current_row],
            "The permutation argument should be activated"
        );
        match side {
            Side::Left => {
                self.temporary_accumulators.0 = (x, y);
            }
            Side::Right => {
                self.temporary_accumulators.1 = (x, y);
            }
        }
    }

    // It is unsafe as no constraint is added
    unsafe fn is_same_ec_point(
        &mut self,
        pos: Self::Position,
        x1: Self::Variable,
        y1: Self::Variable,
        x2: Self::Variable,
        y2: Self::Variable,
    ) -> Self::Variable {
        let res = if x1 == x2 && y1 == y2 {
            BigInt::from(1_usize)
        } else {
            BigInt::from(0_usize)
        };
        self.write_column(pos, res)
    }

    fn zero(&self) -> Self::Variable {
        BigInt::from(0_usize)
    }

    fn one(&self) -> Self::Variable {
        BigInt::from(1_usize)
    }

    /// Inverse of a variable
    ///
    /// # Safety
    ///
    /// Zero is not allowed as an input.
    unsafe fn inverse(&mut self, pos: Self::Position, x: Self::Variable) -> Self::Variable {
        let res = if self.current_iteration % 2 == 0 {
            Fp::from_biguint(&x.to_biguint().unwrap())
                .unwrap()
                .inverse()
                .unwrap()
                .to_biguint()
                .into()
        } else {
            Fq::from_biguint(&x.to_biguint().unwrap())
                .unwrap()
                .inverse()
                .unwrap()
                .to_biguint()
                .into()
        };
        self.write_column(pos, res)
    }

    fn compute_lambda(
        &mut self,
        pos: Self::Position,
        is_same_point: Self::Variable,
        x1: Self::Variable,
        y1: Self::Variable,
        x2: Self::Variable,
        y2: Self::Variable,
    ) -> Self::Variable {
        let modulus: BigInt = if self.current_iteration % 2 == 0 {
            Fp::modulus_biguint().into()
        } else {
            Fq::modulus_biguint().into()
        };
        // If it is not the same point, we compute lambda as:
        // - λ = (Y1 - Y2) / (X1 - X2)
        let (num, denom): (BigInt, BigInt) = if is_same_point == BigInt::from(0_usize) {
            let num: BigInt = y1.clone() - y2.clone();
            let x1_minus_x2: BigInt = (x1.clone() - x2.clone()).mod_floor(&modulus);
            // We temporarily store the inverse of the denominator into the
            // given position.
            let denom = unsafe { self.inverse(pos, x1_minus_x2) };
            (num, denom)
        } else {
            // Otherwise, we compute λ as:
            // - λ = (3X1^2 + a) / (2Y1)
            let denom = {
                let double_y1 = y1.clone() + y1.clone();
                // We temporarily store the inverse of the denominator into the
                // given position.
                unsafe { self.inverse(pos, double_y1) }
            };
            let num = {
                let a: BigInt = if self.current_iteration % 2 == 0 {
                    (E2::Params::COEFF_A).to_biguint().into()
                } else {
                    (E1::Params::COEFF_A).to_biguint().into()
                };
                let x1_square = x1.clone() * x1.clone();
                let two_x1_square = x1_square.clone() + x1_square.clone();
                two_x1_square + x1_square + a
            };
            (num, denom)
        };
        let res = (num * denom).mod_floor(&modulus);
        self.write_column(pos, res)
    }

    /// Double the elliptic curve point given by the affine coordinates
    /// `(x1, y1)` and save the result in the registers `pos_x` and `pos_y`.
    fn double_ec_point(
        &mut self,
        pos_x: Self::Position,
        pos_y: Self::Position,
        x1: Self::Variable,
        y1: Self::Variable,
    ) -> (Self::Variable, Self::Variable) {
        let modulus: BigInt = if self.current_iteration % 2 == 0 {
            Fp::modulus_biguint().into()
        } else {
            Fq::modulus_biguint().into()
        };
        // - λ = (3X1^2 + a) / (2Y1)
        // We compute λ and use an additional column as a temporary value
        // otherwise, we get a constraint of degree higher than 5
        let lambda_pos = self.allocate();
        let denom = {
            let double_y1 = y1.clone() + y1.clone();
            // We temporarily store the inverse of the denominator into the
            // given position.
            unsafe { self.inverse(lambda_pos, double_y1) }
        };
        let num = {
            let a: BigInt = if self.current_iteration % 2 == 0 {
                (E2::Params::COEFF_A).to_biguint().into()
            } else {
                (E1::Params::COEFF_A).to_biguint().into()
            };
            let x1_square = x1.clone() * x1.clone();
            let two_x1_square = x1_square.clone() + x1_square.clone();
            two_x1_square + x1_square + a
        };
        let lambda = (num * denom).mod_floor(&modulus);
        self.write_column(lambda_pos, lambda.clone());
        // - X3 = λ^2 - X1 - X2
        let x3 = {
            let double_x1 = x1.clone() + x1.clone();
            let res = lambda.clone() * lambda.clone() - double_x1.clone();
            self.write_column(pos_x, res.clone())
        };
        // - Y3 = λ(X1 - X3) - Y1
        let y3 = {
            let x1_minus_x3 = x1.clone() - x3.clone();
            let res = lambda.clone() * x1_minus_x3 - y1.clone();
            self.write_column(pos_y, res.clone())
        };
        (x3, y3)
    }
}

impl<
        Fp: PrimeField,
        Fq: PrimeField,
        E1: CommitmentCurve<ScalarField = Fp, BaseField = Fq>,
        E2: CommitmentCurve<ScalarField = Fq, BaseField = Fp>,
    > Env<Fp, Fq, E1, E2>
{
    pub fn new(
        srs_log2_size: usize,
        z0: BigInt,
        sponge_e1: [BigInt; 3],
        sponge_e2: [BigInt; 3],
    ) -> Self {
        {
            assert!(Fp::MODULUS_BIT_SIZE <= MAXIMUM_FIELD_SIZE_IN_BITS.try_into().unwrap(), "The size of the field Fp is too large, it should be less than {MAXIMUM_FIELD_SIZE_IN_BITS}");
            assert!(Fq::MODULUS_BIT_SIZE <= MAXIMUM_FIELD_SIZE_IN_BITS.try_into().unwrap(), "The size of the field Fq is too large, it should be less than {MAXIMUM_FIELD_SIZE_IN_BITS}");
            let modulus_fp = Fp::modulus_biguint();
            assert!(
                (modulus_fp - BigUint::from(1_u64)).gcd(&BigUint::from(POSEIDON_ALPHA))
                    == BigUint::from(1_u64),
                "The modulus of Fp should be coprime with {POSEIDON_ALPHA}"
            );
            let modulus_fq = Fq::modulus_biguint();
            assert!(
                (modulus_fq - BigUint::from(1_u64)).gcd(&BigUint::from(POSEIDON_ALPHA))
                    == BigUint::from(1_u64),
                "The modulus of Fq should be coprime with {POSEIDON_ALPHA}"
            );
        }
        let srs_size = 1 << srs_log2_size;
        let domain_fp = EvaluationDomains::<Fp>::create(srs_size).unwrap();
        let domain_fq = EvaluationDomains::<Fq>::create(srs_size).unwrap();

        info!("Create an SRS of size {srs_log2_size} for the first curve");
        let srs_e1: SRS<E1> = {
            let start = Instant::now();
            let mut srs = SRS::create(srs_size);
            debug!("SRS for E1 created in {:?}", start.elapsed());
            let start = Instant::now();
            srs.add_lagrange_basis(domain_fp.d1);
            debug!("Lagrange basis for E1 added in {:?}", start.elapsed());
            srs
        };
        info!("Create an SRS of size {srs_log2_size} for the second curve");
        let srs_e2: SRS<E2> = {
            let start = Instant::now();
            let mut srs = SRS::create(srs_size);
            debug!("SRS for E2 created in {:?}", start.elapsed());
            let start = Instant::now();
            srs.add_lagrange_basis(domain_fq.d1);
            debug!("Lagrange basis for E2 added in {:?}", start.elapsed());
            srs
        };

        let mut witness: Vec<Vec<BigInt>> = Vec::with_capacity(NUMBER_OF_COLUMNS);
        {
            let mut vec: Vec<BigInt> = Vec::with_capacity(srs_size);
            (0..srs_size).for_each(|_| vec.push(BigInt::from(0_usize)));
            (0..NUMBER_OF_COLUMNS).for_each(|_| witness.push(vec.clone()));
        };

        let mut selectors: Vec<Vec<bool>> = Vec::with_capacity(NUMBER_OF_SELECTORS);
        {
            let mut vec: Vec<bool> = Vec::with_capacity(srs_size);
            (0..srs_size).for_each(|_| vec.push(false));
            (0..NUMBER_OF_SELECTORS).for_each(|_| selectors.push(vec.clone()));
        };

        // Default set to the blinders. Using double to make the EC scaling happy.
        let previous_commitments_e1: Vec<PolyComm<E1>> = (0..NUMBER_OF_COLUMNS)
            .map(|_| PolyComm::new(vec![(srs_e1.h + srs_e1.h).into()]))
            .collect();
        let previous_commitments_e2: Vec<PolyComm<E2>> = (0..NUMBER_OF_COLUMNS)
            .map(|_| PolyComm::new(vec![(srs_e2.h + srs_e2.h).into()]))
            .collect();
        // FIXME: zero will not work.
        let ivc_accumulator_e1: Vec<PolyComm<E1>> = (0..NUMBER_OF_COLUMNS)
            .map(|_| PolyComm::new(vec![srs_e1.h]))
            .collect();
        let ivc_accumulator_e2: Vec<PolyComm<E2>> = (0..NUMBER_OF_COLUMNS)
            .map(|_| PolyComm::new(vec![srs_e2.h]))
            .collect();

        // FIXME: challenges
        let challenges: Vec<BigInt> = vec![];

        Self {
            // -------
            // Setup
            domain_fp,
            domain_fq,
            srs_e1,
            srs_e2,
            // -------
            // -------
            // IVC only
            ivc_accumulator_e1,
            ivc_accumulator_e2,
            previous_commitments_e1,
            previous_commitments_e2,
            // ------
            // ------
            idx_var: 0,
            idx_var_next_row: 0,
            idx_var_pi: 0,
            current_row: 0,
            state: std::array::from_fn(|_| BigInt::from(0_usize)),
            next_state: std::array::from_fn(|_| BigInt::from(0_usize)),
            public_state: std::array::from_fn(|_| BigInt::from(0_usize)),
            selectors,
            challenges,
            current_instruction: IVC_STARTING_INSTRUCTION,
            sponge_e1,
            sponge_e2,
            current_iteration: 0,
            previous_hash: [0; 2],
            r: BigInt::from(0_usize),
            // Initialize the temporary accumulators with 0
            temporary_accumulators: (
                (BigInt::from(0_u64), BigInt::from(0_u64)),
                (BigInt::from(0_u64), BigInt::from(0_u64)),
            ),
            idx_values_to_absorb: 0,
            // ------
            // ------
            // Used by the interpreter
            // Used to allocate variables
            // Witness builder related
            witness,
            // ------
            // Inputs
            z0: z0.clone(),
            zi: z0,
            // ------
            _marker: std::marker::PhantomData,
        }
    }

    /// Reset the environment to build the next iteration
    pub fn reset_for_next_iteration(&mut self) {
        // Rest the state for the next row
        self.current_row = 0;
        self.state = std::array::from_fn(|_| BigInt::from(0_usize));
        self.idx_var = 0;
        self.current_instruction = IVC_STARTING_INSTRUCTION;
        self.idx_values_to_absorb = 0;
    }

    /// The blinder used to commit, to avoid committing to the zero polynomial
    /// and accumulate it in the IVC.
    ///
    /// It is part of the instance, and it is accumulated in the IVC.
    pub fn accumulate_commitment_blinder(&mut self) {
        // TODO
    }

    /// Compute the commitments to the current witness, and update the previous
    /// instances.
    // Might be worth renaming this function
    pub fn compute_and_update_previous_commitments(&mut self) {
        if self.current_iteration % 2 == 0 {
            let comms: Vec<PolyComm<E1>> = self
                .witness
                .par_iter()
                .map(|evals| {
                    let evals: Vec<Fp> = evals
                        .par_iter()
                        .map(|x| Fp::from_biguint(&x.to_biguint().unwrap()).unwrap())
                        .collect();
                    let evals = Evaluations::from_vec_and_domain(evals.to_vec(), self.domain_fp.d1);
                    self.srs_e1
                        .commit_evaluations_non_hiding(self.domain_fp.d1, &evals)
                })
                .collect();
            self.previous_commitments_e1 = comms
        } else {
            let comms: Vec<PolyComm<E2>> = self
                .witness
                .iter()
                .map(|evals| {
                    let evals: Vec<Fq> = evals
                        .par_iter()
                        .map(|x| Fq::from_biguint(&x.to_biguint().unwrap()).unwrap())
                        .collect();
                    let evals = Evaluations::from_vec_and_domain(evals.to_vec(), self.domain_fq.d1);
                    self.srs_e2
                        .commit_evaluations_non_hiding(self.domain_fq.d1, &evals)
                })
                .collect();
            self.previous_commitments_e2 = comms
        }
    }

    /// Compute the output of the application on the previous output
    // TODO: we should compute the hash of the previous commitments, only on
    // CPU?
    pub fn compute_output(&mut self) {
        self.zi = BigInt::from(42_usize)
    }

    pub fn fetch_instruction(&self) -> Instruction {
        self.current_instruction
    }

    /// Describe the control-flow for the IVC circuit.
    ///
    /// For a step i + 1, the IVC circuit receives as public input the following
    /// values:
    ///
    /// - The commitments to the previous witnesses.
    /// - The previous challenges (α_{i}, β_{i}, γ_{i}) - the challenges β and γ
    /// are used by the permutation argument where α is used by the quotient
    /// polynomial, generated after also absorbing the accumulator of the
    /// permutation argument.
    /// - The previous accumulators (acc_1, ..., acc_17).
    /// - The previous output z_i.
    /// - The initial input z_0.
    /// - The natural i describing the previous step.
    ///
    /// The control flow is as follow:
    /// - We compute the hash of the previous commitments and verify the hash
    /// corresponds to the public input:
    ///
    /// ```text
    /// hash = H(i, acc_1, ..., acc_17, z_0, z_i)
    /// ```
    ///
    /// - We also have to check that the previous challenges (α, β, γ) have been
    /// correctly generated. Therefore, we must compute the hashes of the
    /// witnesses and verify they correspond to the public input.
    ///
    /// TODO
    ///
    /// - We compute the output of the application (TODO)
    ///
    /// ```text
    /// z_(i + 1) = F(w_i, z_i)
    /// ```
    ///
    /// - We decompose the scalar `r`, the random combiner, into bits to compute
    /// the MSM for the next step.
    ///
    /// - We compute the MSM (verifier)
    ///
    /// ```text
    /// acc_(i + 1)_j = acc_i + r C_j
    /// ```
    /// And also the cross-terms:
    ///
    /// ```text
    /// E = E1 - r T1 - r^2 T2 - ... - r^d T^d + r^(d+1) E2
    ///   = E1 - r (T1 + r (T2 + ... + r T^(d - 1)) - r E2)
    /// ```
    /// where (d + 1) is the degree of the highest gate.
    ///
    /// - We compute the next hash we give to the next instance
    ///
    /// ```text
    /// hash' = H(i + 1, acc'_1, ..., acc'_17, z_0, z_(i + 1))
    /// ```
    pub fn fetch_next_instruction(&mut self) -> Instruction {
        match self.current_instruction {
            Instruction::SixteenBitsDecomposition => Instruction::BitDecompositionFrom16Bits(0),
            Instruction::BitDecomposition(i) => {
                if i < BIT_DECOMPOSITION_NUMBER_OF_CHUNKS - 1 {
                    Instruction::BitDecomposition(i + 1)
                } else {
                    Instruction::EllipticCurveScaling(0, 0)
                }
            }
            Instruction::Poseidon(i) => {
                if i < POSEIDON_ROUNDS_FULL - 4 {
                    // We perform 4 rounds per row
                    // FIXME: we can do 5 by using the "next row", see
                    // PoseidonNextRow
                    Instruction::Poseidon(i + 4)
                } else {
                    // If we absorbed all the elements, we go to the next instruction
                    // In this case, it is the decomposition of the folding combiner
                    // FIXME: it is not the correct next instruction.
                    // We must check the computed value is the one given as a
                    // public input.
                    if self.idx_values_to_absorb >= NUMBER_OF_VALUES_TO_ABSORB_PUBLIC_IO {
                        Instruction::BitDecomposition(0)
                    } else {
                        // Otherwise, we continue absorbing
                        Instruction::Poseidon(0)
                    }
                }
            }
            Instruction::PoseidonNextRow(i) => {
                if i < POSEIDON_ROUNDS_FULL - 5 {
                    Instruction::PoseidonNextRow(i + 5)
                } else {
                    // If we absorbed all the elements, we go to the next instruction
                    // In this case, it is the decomposition of the folding combiner
                    // FIXME: it is not the correct next instruction.
                    // We must check the computed value is the one given as a
                    // public input.
                    if self.idx_values_to_absorb >= NUMBER_OF_VALUES_TO_ABSORB_PUBLIC_IO {
                        Instruction::BitDecomposition(0)
                    } else {
                        // Otherwise, we continue absorbing
                        Instruction::PoseidonNextRow(0)
                    }
                }
            }
            Instruction::BitDecompositionFrom16Bits(i) => {
                if i < 15 {
                    Instruction::BitDecompositionFrom16Bits(i + 1)
                } else {
                    Instruction::Poseidon(0)
                }
            }
            Instruction::EllipticCurveScaling(i_comm, bit) => {
                // TODO: we still need to substract (or not?) the blinder.
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
}
