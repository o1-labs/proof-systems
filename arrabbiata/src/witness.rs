use ark_ec::CurveConfig;
use ark_ff::PrimeField;
use ark_poly::Evaluations;
use kimchi::circuits::gate::CurrOrNext;
use log::debug;
use mina_poseidon::constants::SpongeConstants;
use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use o1_utils::field_helpers::FieldHelpers;
use poly_commitment::{commitment::CommitmentCurve, PolyComm, SRS as _};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

use crate::{
    challenge::{ChallengeTerm, Challenges},
    column::{Column, Gadget},
    curve::{ArrabbiataCurve, PlonkSpongeConstants},
    interpreter::{Instruction, InterpreterEnv, Side},
    setup, MAXIMUM_FIELD_SIZE_IN_BITS, NUMBER_OF_COLUMNS, NUMBER_OF_PUBLIC_INPUTS,
    NUMBER_OF_SELECTORS, NUMBER_OF_VALUES_TO_ABSORB_PUBLIC_IO,
};

/// The first instruction in the verifier circuit (often shortened in "IVC" in
/// the crate) is the Poseidon permutation. It is used to start hashing the
/// public input.
pub const VERIFIER_STARTING_INSTRUCTION: Instruction = Instruction::PoseidonSpongeAbsorb;

/// An environment is used to contain the state of a long "running program".
///
/// The running program is composed of two parts: one user application and one
/// verifier application. The verifier application is used to encode the
/// correctness of previous program states computations.
///
/// The term "app(lication) state" will be used to refer to the state of the
/// user application, and the term "IVC state" will be used to refer to the
/// state of the verifier application. The term program state will be used to refer to
/// the state of the whole program.
///
/// The environment contains all the accumulators that can be picked for a given
/// fold instance k, including the sponges.
///
/// The environment is run over big integers to avoid performing
/// reduction at all step. Instead the user implementing the interpreter can
/// reduce in the corresponding field when they want.
///
/// The environment is generic over two curves (called E1 and E2) that are
/// supposed to form a cycle.
pub struct Env<
    Fp: PrimeField,
    Fq: PrimeField,
    E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
    E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
> where
    E1::BaseField: PrimeField,
    E2::BaseField: PrimeField,
{
    /// The relation this witness environment is related to.
    pub indexed_relation: setup::IndexedRelation<Fp, Fq, E1, E2>,

    // ----------------
    // Information related to the IVC, which will be used by the prover/verifier
    // at the end of the whole execution
    // FIXME: use a blinded comm and also fold the blinder
    pub accumulated_committed_state_e1: Vec<PolyComm<E1>>,

    // FIXME: use a blinded comm and also fold the blinder
    pub accumulated_committed_state_e2: Vec<PolyComm<E2>>,

    /// Commitments to the previous program states.
    pub previous_committed_state_e1: Vec<PolyComm<E1>>,
    pub previous_committed_state_e2: Vec<PolyComm<E2>>,

    /// Accumulated witness for the program state over E1
    /// The size of the outer vector must be equal to the number of columns in
    /// the circuit.
    /// The size of the inner vector must be equal to the number of rows in
    /// the circuit.
    pub accumulated_program_state_e1: Vec<Vec<E1::ScalarField>>,

    /// Accumulated witness for the program state over E2
    /// The size of the outer vector must be equal to the number of columns in
    /// the circuit.
    /// The size of the inner vector must be equal to the number of rows in
    /// the circuit.
    pub accumulated_program_state_e2: Vec<Vec<E2::ScalarField>>,
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
    pub challenges: Challenges<BigInt>,

    /// List of the accumulated challenges over time, over the curve E1.
    pub accumulated_challenges_e1: Challenges<BigInt>,

    /// List of the accumulated challenges over time, over the curve E2.
    pub accumulated_challenges_e2: Challenges<BigInt>,

    /// Challenges coined over E1 during the last computation.
    /// This field is useful to keep track of the challenges that must be
    /// verified in circuit.
    pub previous_challenges_e1: Challenges<BigInt>,

    /// Challenges coined over E2 during the last computation.
    /// This field is useful to keep track of the challenges that must be
    /// verified in circuit.
    pub previous_challenges_e2: Challenges<BigInt>,

    /// Keep the current executed instruction.
    /// This can be used to identify which gadget the interpreter is currently
    /// building.
    pub current_instruction: Instruction,

    /// The sponges will be used to simulate the verifier messages, and will
    /// also be used to verify the consistency of the computation by hashing the
    /// public IO.
    // IMPROVEME: use a list of BigInt? It might be faster as the CPU will
    // already have in its cache the values, and we can use a flat array
    pub sponge_e1: [BigInt; PlonkSpongeConstants::SPONGE_WIDTH],
    pub sponge_e2: [BigInt; PlonkSpongeConstants::SPONGE_WIDTH],

    /// Sponge state used by the prover for the current iteration.
    ///
    /// This sponge is used at the current iteration to absorb commitments of
    /// the program state and generate the challenges for the current iteration.
    /// The outputs of the sponge will be verified by the verifier of the next
    /// iteration.
    pub prover_sponge_state: [BigInt; PlonkSpongeConstants::SPONGE_WIDTH],

    /// Sponge state used by the verifier for the current iteration.
    ///
    /// This sponge is used at the current iteration to build the verifier
    /// circuit. The state will need to match with the previous prover sopnge
    /// state.
    pub verifier_sponge_state: [BigInt; PlonkSpongeConstants::SPONGE_WIDTH],

    /// The current iteration of the IVC.
    pub current_iteration: u64,

    /// The digest of the program state before executing the last iteration.
    /// The value will be used to initialize the execution trace of the verifier
    /// in the next iteration, in particular to verify that the challenges have
    /// been generated correctly.
    ///
    /// The value is a 128bits value.
    pub last_program_digest_before_execution: BigInt,

    /// The digest of the program state after executing the last iteration.
    /// The value will be used to initialize the sponge before committing to the
    /// next iteration.
    ///
    /// The value is a 128bits value.
    pub last_program_digest_after_execution: BigInt,

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
    /// The size of the outer vector must be equal to the number of columns in
    /// the circuit.
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
}

// The condition on the parameters for E1 and E2 is to get the coefficients and
// convert them into biguint.
// The condition SWModelParameters is to get the parameters of the curve as
// biguint to use them to compute the slope in the elliptic curve addition
// algorithm.
impl<
        Fp: PrimeField,
        Fq: PrimeField,
        E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
        E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
    > InterpreterEnv for Env<Fp, Fq, E1, E2>
where
    E1::BaseField: PrimeField,
    E2::BaseField: PrimeField,
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
        let (modulus, srs_size): (BigInt, usize) = if self.current_iteration % 2 == 0 {
            (
                E1::ScalarField::modulus_biguint().into(),
                self.indexed_relation.get_srs_size(),
            )
        } else {
            (
                E2::ScalarField::modulus_biguint().into(),
                self.indexed_relation.get_srs_size(),
            )
        };
        let v = v.mod_floor(&modulus);
        match row {
            CurrOrNext::Curr => {
                self.state[idx].clone_from(&v);
            }
            CurrOrNext::Next => {
                assert!(self.current_row < srs_size - 1, "The witness builder is writing on the last row. It does not make sense to write on the next row after the last row");
                self.next_state[idx].clone_from(&v);
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
            E1::ScalarField::modulus_biguint().into()
        } else {
            E2::ScalarField::modulus_biguint().into()
        };
        let v = v.mod_floor(&modulus);
        self.public_state[idx].clone_from(&v);
        v
    }

    /// Activate the gadget for the current row
    fn activate_gadget(&mut self, gadget: Gadget) {
        // IMPROVEME: it should be called only once per row
        let gadget = usize::from(gadget);
        self.selectors[gadget][self.current_row] = true;
    }

    fn constrain_boolean(&mut self, x: Self::Variable) {
        let modulus: BigInt = if self.current_iteration % 2 == 0 {
            E1::ScalarField::modulus_biguint().into()
        } else {
            E2::ScalarField::modulus_biguint().into()
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
            self.witness[i][self.current_row].clone_from(x);
        });
        // We increment the row
        // TODO: should we check that we are not going over the domain size?
        self.current_row += 1;
        // We reset the indices for the variables
        self.idx_var = 0;
        self.idx_var_next_row = 0;
        self.idx_var_pi = 0;
        // We keep track of the values we already set.
        self.state.clone_from(&self.next_state);
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
        self.state[idx].clone_from(&r);
        self.r.clone_from(&r);
        r
    }

    fn load_poseidon_state(&mut self, pos: Self::Position, i: usize) -> Self::Variable {
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
            E1::sponge_params().round_constants[round][i]
                .to_biguint()
                .into()
        } else {
            E2::sponge_params().round_constants[round][i]
                .to_biguint()
                .into()
        };
        self.write_public_input(pos, rc)
    }

    fn get_poseidon_round_constant_as_constant(&self, round: usize, i: usize) -> Self::Variable {
        if self.current_iteration % 2 == 0 {
            E1::sponge_params().round_constants[round][i]
                .to_biguint()
                .into()
        } else {
            E2::sponge_params().round_constants[round][i]
                .to_biguint()
                .into()
        }
    }

    fn get_poseidon_mds_matrix(&mut self, i: usize, j: usize) -> Self::Variable {
        if self.current_iteration % 2 == 0 {
            E1::sponge_params().mds[i][j].to_biguint().into()
        } else {
            E2::sponge_params().mds[i][j].to_biguint().into()
        }
    }

    unsafe fn save_poseidon_state(&mut self, x: Self::Variable, i: usize) {
        if self.current_iteration % 2 == 0 {
            let modulus: BigInt = E1::ScalarField::modulus_biguint().into();
            self.sponge_e1[i] = x.mod_floor(&modulus)
        } else {
            let modulus: BigInt = E2::ScalarField::modulus_biguint().into();
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
                    let (pt_x, pt_y) = self.accumulated_committed_state_e2[idx_col]
                        .get_first_chunk()
                        .to_coordinates()
                        .unwrap();
                    if idx % 2 == 0 {
                        self.write_public_input(pos, pt_x.to_biguint().into())
                    } else {
                        self.write_public_input(pos, pt_y.to_biguint().into())
                    }
                } else {
                    let (pt_x, pt_y) = self.accumulated_committed_state_e1[idx_col]
                        .get_first_chunk()
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

    unsafe fn fetch_value_to_absorb_in_sponge(&mut self, pos: Self::Position) -> Self::Variable {
        let (col, curr_or_next) = pos;
        // Purely arbitrary for now
        let Column::X(_idx) = col else {
            panic!("Only private inputs can be accepted to load the values to be absorbed")
        };
        assert_eq!(
            curr_or_next,
            CurrOrNext::Curr,
            "Only the current row can be used to load the values to be absorbed"
        );
        // FIXME: for now, we only absorb the commitments to the columns
        let idx = self.idx_values_to_absorb;
        let res = if idx < 2 * NUMBER_OF_COLUMNS {
            let idx_col = idx / 2;
            debug!("Absorbing the accumulator for the column index {idx_col}. After this, there will still be {} elements to absorb", NUMBER_OF_VALUES_TO_ABSORB_PUBLIC_IO - idx - 1);
            if self.current_iteration % 2 == 0 {
                let (pt_x, pt_y) = self.accumulated_committed_state_e2[idx_col]
                    .get_first_chunk()
                    .to_coordinates()
                    .unwrap();
                if idx % 2 == 0 {
                    self.write_column(pos, pt_x.to_biguint().into())
                } else {
                    self.write_column(pos, pt_y.to_biguint().into())
                }
            } else {
                let (pt_x, pt_y) = self.accumulated_committed_state_e1[idx_col]
                    .get_first_chunk()
                    .to_coordinates()
                    .unwrap();
                if idx % 2 == 0 {
                    self.write_column(pos, pt_x.to_biguint().into())
                } else {
                    self.write_column(pos, pt_y.to_biguint().into())
                }
            }
        } else {
            unimplemented!("We only absorb the accumulators for now. Of course, this is not sound.")
        };
        self.idx_values_to_absorb += 1;
        res
    }

    unsafe fn load_temporary_accumulators(
        &mut self,
        pos_x: Self::Position,
        pos_y: Self::Position,
        side: Side,
    ) -> (Self::Variable, Self::Variable) {
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
                                let pt = self.previous_committed_state_e2[i_comm].get_first_chunk();
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
                                let pt = self.indexed_relation.srs_e2.h;
                                let (pt_x, pt_y) = pt.to_coordinates().unwrap();
                                let pt_x = self.write_column(pos_x, pt_x.to_biguint().into());
                                let pt_y = self.write_column(pos_y, pt_y.to_biguint().into());
                                (pt_x, pt_y)
                            }
                        }
                    } else {
                        match side {
                            Side::Left => {
                                let pt = self.previous_committed_state_e1[i_comm].get_first_chunk();
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
                                let blinder = self.indexed_relation.srs_e1.h;
                                let pt = blinder;
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
                            let pt = self.accumulated_committed_state_e2[i_comm].get_first_chunk();
                            let (x, y) = pt.to_coordinates().unwrap();
                            (x.to_biguint().into(), y.to_biguint().into())
                        } else {
                            let pt = self.accumulated_committed_state_e1[i_comm].get_first_chunk();
                            let (x, y) = pt.to_coordinates().unwrap();
                            (x.to_biguint().into(), y.to_biguint().into())
                        }
                    }
                    Side::Right => {
                        if self.current_iteration % 2 == 0 {
                            let pt = self.previous_committed_state_e2[i_comm].get_first_chunk();
                            let (x, y) = pt.to_coordinates().unwrap();
                            (x.to_biguint().into(), y.to_biguint().into())
                        } else {
                            let pt = self.previous_committed_state_e1[i_comm].get_first_chunk();
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
            E1::ScalarField::from_biguint(&x.to_biguint().unwrap())
                .unwrap()
                .inverse()
                .unwrap()
                .to_biguint()
                .into()
        } else {
            E2::ScalarField::from_biguint(&x.to_biguint().unwrap())
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
            E1::ScalarField::modulus_biguint().into()
        } else {
            E2::ScalarField::modulus_biguint().into()
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
                    let a: E2::BaseField = E2::get_curve_params().0;
                    a.to_biguint().into()
                } else {
                    let a: E1::BaseField = E1::get_curve_params().0;
                    a.to_biguint().into()
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
            E1::ScalarField::modulus_biguint().into()
        } else {
            E2::ScalarField::modulus_biguint().into()
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
                let a: E2::BaseField = E2::get_curve_params().0;
                a.to_biguint().into()
            } else {
                let a: E1::BaseField = E1::get_curve_params().0;
                a.to_biguint().into()
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
        E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
        E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
    > Env<Fp, Fq, E1, E2>
where
    E1::BaseField: PrimeField,
    E2::BaseField: PrimeField,
    <<E1 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
    <<E2 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
{
    pub fn new(
        z0: BigInt,
        sponge_e1: [BigInt; PlonkSpongeConstants::SPONGE_WIDTH],
        sponge_e2: [BigInt; PlonkSpongeConstants::SPONGE_WIDTH],
        indexed_relation: setup::IndexedRelation<Fp, Fq, E1, E2>,
    ) -> Self {
        let srs_size = indexed_relation.get_srs_size();
        let (blinder_e1, blinder_e2) = indexed_relation.get_srs_blinders();

        let mut witness: Vec<Vec<BigInt>> = Vec::with_capacity(NUMBER_OF_COLUMNS);
        {
            let mut vec: Vec<BigInt> = Vec::with_capacity(srs_size);
            (0..srs_size).for_each(|_| vec.push(BigInt::from(0_usize)));
            (0..NUMBER_OF_COLUMNS).for_each(|_| witness.push(vec.clone()));
        };

        let mut accumulated_program_state_e1: Vec<Vec<E1::ScalarField>> =
            Vec::with_capacity(NUMBER_OF_COLUMNS);
        {
            let mut vec: Vec<E1::ScalarField> = Vec::with_capacity(srs_size);
            (0..srs_size).for_each(|_| vec.push(E1::ScalarField::zero()));
            (0..NUMBER_OF_COLUMNS).for_each(|_| accumulated_program_state_e1.push(vec.clone()));
        };

        let mut accumulated_program_state_e2: Vec<Vec<E2::ScalarField>> =
            Vec::with_capacity(NUMBER_OF_COLUMNS);
        {
            let mut vec: Vec<E2::ScalarField> = Vec::with_capacity(srs_size);
            (0..srs_size).for_each(|_| vec.push(E2::ScalarField::zero()));
            (0..NUMBER_OF_COLUMNS).for_each(|_| accumulated_program_state_e2.push(vec.clone()));
        };

        let mut selectors: Vec<Vec<bool>> = Vec::with_capacity(NUMBER_OF_SELECTORS);
        {
            let mut vec: Vec<bool> = Vec::with_capacity(srs_size);
            (0..srs_size).for_each(|_| vec.push(false));
            (0..NUMBER_OF_SELECTORS).for_each(|_| selectors.push(vec.clone()));
        };

        // Default set to the blinders. Using double to make the EC scaling happy.
        let previous_committed_state_e1: Vec<PolyComm<E1>> = (0..NUMBER_OF_COLUMNS)
            .map(|_| PolyComm::new(vec![(blinder_e1 + blinder_e1).into()]))
            .collect();
        let previous_committed_state_e2: Vec<PolyComm<E2>> = (0..NUMBER_OF_COLUMNS)
            .map(|_| PolyComm::new(vec![(blinder_e2 + blinder_e2).into()]))
            .collect();
        // FIXME: zero will not work.
        let accumulated_committed_state_e1: Vec<PolyComm<E1>> = (0..NUMBER_OF_COLUMNS)
            .map(|_| PolyComm::new(vec![blinder_e1]))
            .collect();
        let accumulated_committed_state_e2: Vec<PolyComm<E2>> = (0..NUMBER_OF_COLUMNS)
            .map(|_| PolyComm::new(vec![blinder_e2]))
            .collect();

        // FIXME: challenges
        let challenges: Challenges<BigInt> = Challenges::default();
        let accumulated_challenges_e1: Challenges<BigInt> = Challenges::default();
        let accumulated_challenges_e2: Challenges<BigInt> = Challenges::default();
        let previous_challenges_e1: Challenges<BigInt> = Challenges::default();
        let previous_challenges_e2: Challenges<BigInt> = Challenges::default();

        let prover_sponge_state: [BigInt; PlonkSpongeConstants::SPONGE_WIDTH] =
            std::array::from_fn(|_| BigInt::from(0_u64));
        let verifier_sponge_state: [BigInt; PlonkSpongeConstants::SPONGE_WIDTH] =
            std::array::from_fn(|_| BigInt::from(0_u64));

        Self {
            // -------
            // Setup
            indexed_relation,
            // -------
            // -------
            // verifier only
            accumulated_committed_state_e1,
            accumulated_committed_state_e2,
            previous_committed_state_e1,
            previous_committed_state_e2,
            accumulated_program_state_e1,
            accumulated_program_state_e2,
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
            accumulated_challenges_e1,
            accumulated_challenges_e2,
            previous_challenges_e1,
            previous_challenges_e2,

            current_instruction: VERIFIER_STARTING_INSTRUCTION,
            sponge_e1,
            sponge_e2,
            prover_sponge_state,
            verifier_sponge_state,
            current_iteration: 0,
            // FIXME: set a correct value
            last_program_digest_before_execution: BigInt::from(0_u64),
            // FIXME: set a correct value
            last_program_digest_after_execution: BigInt::from(0_u64),
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
        }
    }

    /// Reset the environment to build the next iteration
    pub fn reset_for_next_iteration(&mut self) {
        // Rest the state for the next row
        self.current_row = 0;
        self.state = std::array::from_fn(|_| BigInt::from(0_usize));
        self.idx_var = 0;
        self.current_instruction = VERIFIER_STARTING_INSTRUCTION;
        self.idx_values_to_absorb = 0;
    }

    /// The blinder used to commit, to avoid committing to the zero polynomial
    /// and accumulated in the IVC.
    ///
    /// It is part of the instance, and it is accumulated in the IVC.
    pub fn accumulate_commitment_blinder(&mut self) {
        // TODO
    }

    /// Commit to the program state and updating the environment with the
    /// result.
    ///
    /// This method is supposed to be called after a new iteration of the
    /// program has been executed.
    pub fn commit_state(&mut self) {
        if self.current_iteration % 2 == 0 {
            assert_eq!(
                self.current_row as u64,
                self.indexed_relation.domain_fp.d1.size,
                "The program has not been fully executed. Missing {} rows",
                self.indexed_relation.domain_fp.d1.size - self.current_row as u64,
            );
            let comms: Vec<PolyComm<E1>> = self
                .witness
                .par_iter()
                .map(|evals| {
                    let evals: Vec<E1::ScalarField> = evals
                        .par_iter()
                        .map(|x| E1::ScalarField::from_biguint(&x.to_biguint().unwrap()).unwrap())
                        .collect();
                    let evals = Evaluations::from_vec_and_domain(
                        evals.to_vec(),
                        self.indexed_relation.domain_fp.d1,
                    );
                    self.indexed_relation
                        .srs_e1
                        .commit_evaluations_non_hiding(self.indexed_relation.domain_fp.d1, &evals)
                })
                .collect();
            self.previous_committed_state_e1 = comms
        } else {
            assert_eq!(
                self.current_row as u64,
                self.indexed_relation.domain_fq.d1.size,
                "The program has not been fully executed. Missing {} rows",
                self.indexed_relation.domain_fq.d1.size - self.current_row as u64,
            );
            let comms: Vec<PolyComm<E2>> = self
                .witness
                .iter()
                .map(|evals| {
                    let evals: Vec<E2::ScalarField> = evals
                        .par_iter()
                        .map(|x| E2::ScalarField::from_biguint(&x.to_biguint().unwrap()).unwrap())
                        .collect();
                    let evals = Evaluations::from_vec_and_domain(
                        evals.to_vec(),
                        self.indexed_relation.domain_fq.d1,
                    );
                    self.indexed_relation
                        .srs_e2
                        .commit_evaluations_non_hiding(self.indexed_relation.domain_fq.d1, &evals)
                })
                .collect();
            self.previous_committed_state_e2 = comms
        }
    }

    /// Absorb the last committed program state in the correct sponge.
    ///
    /// For a description of the messages to be given to the sponge, including
    /// the expected instantiation, refer to the section "Message Passing" in
    /// [crate::interpreter].
    pub fn absorb_state(&mut self) {
        if self.current_iteration % 2 == 0 {
            let mut sponge = E1::create_new_sponge();
            let previous_state: E1::BaseField = E1::BaseField::from_biguint(
                &self
                    .last_program_digest_after_execution
                    .to_biguint()
                    .unwrap(),
            )
            .unwrap();
            E1::absorb_fq(&mut sponge, previous_state);
            self.previous_committed_state_e1
                .iter()
                .for_each(|comm| E1::absorb_curve_points(&mut sponge, &comm.chunks));
            let state: Vec<BigInt> = sponge
                .sponge
                .state
                .iter()
                .map(|x| x.to_biguint().into())
                .collect();
            self.prover_sponge_state = state.try_into().unwrap()
        } else {
            let mut sponge = E2::create_new_sponge();
            let previous_state: E2::BaseField = E2::BaseField::from_biguint(
                &self
                    .last_program_digest_after_execution
                    .to_biguint()
                    .unwrap(),
            )
            .unwrap();
            E2::absorb_fq(&mut sponge, previous_state);
            self.previous_committed_state_e2
                .iter()
                .for_each(|comm| E2::absorb_curve_points(&mut sponge, &comm.chunks));

            let state: Vec<BigInt> = sponge
                .sponge
                .state
                .iter()
                .map(|x| x.to_biguint().into())
                .collect();
            self.prover_sponge_state = state.try_into().unwrap()
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
    /// For a step i + 1, the verifier circuit receives as public input the
    /// following values:
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
            Instruction::Poseidon(i) => {
                if i < PlonkSpongeConstants::PERM_ROUNDS_FULL - 5 {
                    Instruction::Poseidon(i + 5)
                } else {
                    // FIXME: we continue absorbing
                    Instruction::Poseidon(0)
                }
            }
            Instruction::PoseidonPermutation(i) => {
                if i < PlonkSpongeConstants::PERM_ROUNDS_FULL - 5 {
                    Instruction::PoseidonPermutation(i + 5)
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
                Instruction::PoseidonPermutation(0)
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

    /// Simulate an interaction with the verifier by requesting to coin a
    /// challenge from the current prover sponge state.
    ///
    /// This method supposes that all the messages have been sent to the
    /// verifier previously, and the attribute [self.prover_sponge_state] has
    /// been updated accordingly by absorbing all the messages correctly.
    ///
    /// The side-effect of this method will be to run a permutation on the
    /// sponge state _after_ coining the challenge.
    /// There is an hypothesis on the sponge state that the inner permutation
    /// has been correctly executed if the absorbtion rate had been reached at
    /// the last absorbtion.
    ///
    /// The challenge will be added to the [self.challenges] attribute at the
    /// position given by the challenge `chal`.
    ///
    /// Internally, the method is implemented by simply loading the prover
    /// sponge state, and squeezing a challenge from it, relying on the
    /// implementation of the sponge. Usually, the challenge would be the first
    /// N bits of the first element, but it is left as an implementation detail
    /// of the sponge given by the curve.
    pub fn coin_challenge(&mut self, chal: ChallengeTerm) {
        if self.current_iteration % 2 == 0 {
            let mut sponge = E1::create_new_sponge();
            self.prover_sponge_state.iter().for_each(|x| {
                E1::absorb_fq(
                    &mut sponge,
                    E1::BaseField::from_biguint(&x.to_biguint().unwrap()).unwrap(),
                )
            });
            let verifier_answer = E1::squeeze_challenge(&mut sponge).to_biguint().into();
            self.challenges[chal] = verifier_answer;
            sponge.sponge.poseidon_block_cipher();
            let state: Vec<BigInt> = sponge
                .sponge
                .state
                .iter()
                .map(|x| x.to_biguint().into())
                .collect();
            self.prover_sponge_state = state.try_into().unwrap();
        } else {
            let mut sponge = E2::create_new_sponge();
            self.prover_sponge_state.iter().for_each(|x| {
                E2::absorb_fq(
                    &mut sponge,
                    E2::BaseField::from_biguint(&x.to_biguint().unwrap()).unwrap(),
                )
            });
            let verifier_answer = E2::squeeze_challenge(&mut sponge).to_biguint().into();
            self.challenges[chal] = verifier_answer;
            sponge.sponge.poseidon_block_cipher();
            let state: Vec<BigInt> = sponge
                .sponge
                .state
                .iter()
                .map(|x| x.to_biguint().into())
                .collect();
            self.prover_sponge_state = state.try_into().unwrap();
        }
    }

    /// Accumulate the program state (or in other words,
    /// the witness), by adding the last computed program state into the
    /// program state accumulator.
    ///
    /// This method is supposed to be called after the program state has been
    /// committed (by calling [self.commit_state]) and absorbed (by calling
    /// [self.absorb_state]). The "relation randomiser" must also have been
    /// coined and saved in the environment before, by calling
    /// [self.coin_challenge].
    ///
    /// The program state is accumulated into a different accumulator, depending
    /// on the curve currently being used.
    ///
    /// This is part of the work the prover of the accumulation/folding scheme.
    ///
    /// This must translate the following equation:
    /// ```text
    /// acc_(p, n + 1) = acc_(p, n) * chal w
    ///               OR
    /// acc_(q, n + 1) = acc_(q, n) * chal w
    /// ```
    /// where acc and w are vectors of the same size.
    pub fn accumulate_program_state(&mut self) {
        let chal = self.challenges[ChallengeTerm::RelationCombiner].clone();
        if self.current_iteration % 2 == 0 {
            let modulus: BigInt = E1::ScalarField::modulus_biguint().into();
            self.accumulated_program_state_e1 = self
                .accumulated_program_state_e1
                .iter()
                .zip(self.witness.iter()) // This iterate over the columns
                .map(|(evals_accumulator, evals_witness)| {
                    evals_accumulator
                        .iter()
                        .zip(evals_witness.iter()) // This iterate over the rows
                        .map(|(acc, w)| {
                            let rhs: BigInt = (chal.clone() * w).mod_floor(&modulus);
                            let rhs: BigUint = rhs.to_biguint().unwrap();
                            let res = E1::ScalarField::from_biguint(&rhs).unwrap();
                            *acc + res
                        })
                        .collect()
                })
                .collect();
        } else {
            let modulus: BigInt = E2::ScalarField::modulus_biguint().into();
            self.accumulated_program_state_e2 = self
                .accumulated_program_state_e2
                .iter()
                .zip(self.witness.iter()) // This iterate over the columns
                .map(|(evals_accumulator, evals_witness)| {
                    evals_accumulator
                        .iter()
                        .zip(evals_witness.iter()) // This iterate over the rows
                        .map(|(acc, w)| {
                            let rhs: BigInt = (chal.clone() * w).mod_floor(&modulus);
                            let rhs: BigUint = rhs.to_biguint().unwrap();
                            let res = E2::ScalarField::from_biguint(&rhs).unwrap();
                            *acc + res
                        })
                        .collect()
                })
                .collect();
        }
    }

    /// Accumulate the committed state by adding the last committed state into
    /// the committed state accumulator.
    ///
    /// The commitments are accumulated into a different accumulator, depending
    /// on the curve currently being used.
    ///
    /// This is part of the work the prover of the accumulation/folding scheme.
    ///
    /// This must translate the following equation:
    /// ```text
    /// C_(p, n + 1) = C_(p, n) + chal * comm
    ///               OR
    /// C_(q, n + 1) = C_(q, n) + chal * comm
    /// ```
    ///
    /// Note that the committed program state is encoded in
    /// [crate::NUMBER_OF_COLUMNS] values, therefore we must iterate over all
    /// the columns to accumulate the committed state.
    pub fn accumulate_committed_state(&mut self) {
        if self.current_iteration % 2 == 0 {
            let chal = self.challenges[ChallengeTerm::RelationCombiner].clone();
            let chal: BigUint = chal.to_biguint().unwrap();
            let chal: E2::ScalarField = E2::ScalarField::from_biguint(&chal).unwrap();
            self.accumulated_committed_state_e2 = self
                .accumulated_committed_state_e2
                .iter()
                .zip(self.previous_committed_state_e2.iter())
                .map(|(l, r)| l + &r.scale(chal))
                .collect();
        } else {
            let chal = self.challenges[ChallengeTerm::RelationCombiner].clone();
            let chal: BigUint = chal.to_biguint().unwrap();
            let chal: E1::ScalarField = E1::ScalarField::from_biguint(&chal).unwrap();
            self.accumulated_committed_state_e1 = self
                .accumulated_committed_state_e1
                .iter()
                .zip(self.previous_committed_state_e1.iter())
                .map(|(l, r)| l + &r.scale(chal))
                .collect();
        }
    }
}
