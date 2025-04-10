use ark_ec::CurveConfig;
use ark_ff::PrimeField;
use kimchi::circuits::gate::CurrOrNext;
use log::debug;
use mina_poseidon::constants::SpongeConstants;
use num_bigint::BigInt;
use num_integer::Integer;
use o1_utils::field_helpers::FieldHelpers;
use poly_commitment::commitment::CommitmentCurve;

use crate::{
    challenge::Challenges,
    column::Column,
    curve::{ArrabbiataCurve, PlonkSpongeConstants},
    interpreter::{Instruction, InterpreterEnv, Side, VERIFIER_STARTING_INSTRUCTION},
    setup2::IndexedRelation,
    zkapp_registry::{verifier::Verifier, VerifiableZkApp, ZkAppState},
    NUMBER_OF_COLUMNS, NUMBER_OF_VALUES_TO_ABSORB_PUBLIC_IO,
};

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
pub struct Env<Fp, Fq, E1, E2, ZkApp1, ZkApp2>
where
    Fp: PrimeField,
    Fq: PrimeField,
    E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
    E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
    E1::BaseField: PrimeField,
    E2::BaseField: PrimeField,
    <<E1 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
    <<E2 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
    ZkApp1: VerifiableZkApp<E1, Verifier = Verifier<E1>>,
    ZkApp2: VerifiableZkApp<E2, Verifier = Verifier<E2>>,
{
    /// The relation this witness environment is related to.
    pub indexed_relation: IndexedRelation<Fp, Fq, E1, E2, ZkApp1, ZkApp2>,

    pub zkapp1_state: ZkAppState<E1>,
    pub zkapp2_state: ZkAppState<E2>,

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

    /// While folding, we must keep track of the challenges the verifier would
    /// have sent in the SNARK, and we must aggregate them.
    // FIXME: nothing is done yet, and the challenges haven't been decided yet.
    // See top-level documentation of the interpreter for more information.
    pub challenges: Challenges<BigInt>,

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
}

impl<Fp, Fq, E1, E2, ZkApp1, ZkApp2> InterpreterEnv for Env<Fp, Fq, E1, E2, ZkApp1, ZkApp2>
where
    Fp: PrimeField,
    Fq: PrimeField,
    E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
    E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
    E1::BaseField: PrimeField,
    E2::BaseField: PrimeField,
    <<E1 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
    <<E2 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
    ZkApp1: VerifiableZkApp<E1, Verifier = Verifier<E1>>,
    ZkApp2: VerifiableZkApp<E2, Verifier = Verifier<E2>>,
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

    fn get_poseidon_round_constant(&self, round: usize, i: usize) -> Self::Variable {
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
                                let pt = self.zkapp2_state.previous_committed_state[i_comm].get_first_chunk();
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
                                let pt = self.zkapp1_state.previous_committed_state[i_comm].get_first_chunk();
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
                            let pt = self.zkapp2_state.accumulated_committed_state[i_comm].get_first_chunk();
                            let (x, y) = pt.to_coordinates().unwrap();
                            (x.to_biguint().into(), y.to_biguint().into())
                        } else {
                            let pt = self.zkapp1_state.accumulated_committed_state[i_comm].get_first_chunk();
                            let (x, y) = pt.to_coordinates().unwrap();
                            (x.to_biguint().into(), y.to_biguint().into())
                        }
                    }
                    Side::Right => {
                        if self.current_iteration % 2 == 0 {
                            let pt = self.zkapp2_state.previous_committed_state[i_comm].get_first_chunk();
                            let (x, y) = pt.to_coordinates().unwrap();
                            (x.to_biguint().into(), y.to_biguint().into())
                        } else {
                            let pt = self.zkapp1_state.previous_committed_state[i_comm].get_first_chunk();
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

impl<Fp, Fq, E1, E2, ZkApp1, ZkApp2> Env<Fp, Fq, E1, E2, ZkApp1, ZkApp2>
where
    Fp: PrimeField,
    Fq: PrimeField,
    E1: ArrabbiataCurve<ScalarField = Fp, BaseField = Fq>,
    E2: ArrabbiataCurve<ScalarField = Fq, BaseField = Fp>,
    E1::BaseField: PrimeField,
    E2::BaseField: PrimeField,
    <<E1 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
    <<E2 as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
    ZkApp1: VerifiableZkApp<E1, Verifier = Verifier<E1>>,
    ZkApp2: VerifiableZkApp<E2, Verifier = Verifier<E2>>,
{
    pub fn new(indexed_relation: IndexedRelation<Fp, Fq, E1, E2, ZkApp1, ZkApp2>) -> Self {
        let srs_size = indexed_relation.get_srs_size();
        let (_blinder_e1, _blinder_e2) = indexed_relation.get_srs_blinders();

        let mut witness: Vec<Vec<BigInt>> = Vec::with_capacity(NUMBER_OF_COLUMNS);
        {
            let mut vec: Vec<BigInt> = Vec::with_capacity(srs_size);
            (0..srs_size).for_each(|_| vec.push(BigInt::from(0_usize)));
            (0..NUMBER_OF_COLUMNS).for_each(|_| witness.push(vec.clone()));
        };

        // Initialize Program instances for both curves
        let zkapp1_state: ZkAppState<E1> = ZkAppState::new();
        let zkapp2_state: ZkAppState<E2> = ZkAppState::new();

        // FIXME: challenges
        let challenges: Challenges<BigInt> = Challenges::default();

        // FIXME: use setup
        let prover_sponge_state: [BigInt; PlonkSpongeConstants::SPONGE_WIDTH] =
            std::array::from_fn(|_| BigInt::from(0_u64));
        let verifier_sponge_state: [BigInt; PlonkSpongeConstants::SPONGE_WIDTH] =
            std::array::from_fn(|_| BigInt::from(0_u64));

        // FIXME: set this up correctly. Temporary as we're moving the initial
        // transcript state into the setup
        let sponge_e1 = indexed_relation.initial_sponge.clone();
        let sponge_e2 = indexed_relation.initial_sponge.clone();

        Self {
            // -------
            // Setup
            indexed_relation,
            // -------
            // Program state for each curve
            zkapp1_state,
            zkapp2_state,
            // ------
            // ------
            idx_var: 0,
            idx_var_next_row: 0,
            idx_var_pi: 0,
            current_row: 0,
            state: std::array::from_fn(|_| BigInt::from(0_usize)),
            next_state: std::array::from_fn(|_| BigInt::from(0_usize)),

            challenges,

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
            witness,
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

    pub fn fetch_instruction(&self) -> Instruction {
        self.current_instruction
    }
}
