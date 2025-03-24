//! This module contains a generic verifier for Arrabbiata.
//!
//! The verifier is implemented as a ZkApp, and is responsible to build the
//! verification of a previous execution trace.
//!
//! Considering the verifier as a ZkApp allows to reuse the same interface.
//! Also, it eases the development of other verifiers, as the interface is
//! generic and can be reused.
//!
//! The verifier circuit has the following structure:
//! - absorb the accumulators of each accumulator, and run the Poseidon hash
//!   after each absorbtion.
//! - [...] TBD
use crate::{
    curve::{ArrabbiataCurve, PlonkSpongeConstants},
    interpreter::{InterpreterEnv, Side},
    zkapp_registry::ZkApp,
    MAXIMUM_FIELD_SIZE_IN_BITS, NUMBER_OF_COLUMNS,
};
use ark_ff::PrimeField;
use core::hash::Hash;
use log::debug;
use mina_poseidon::constants::SpongeConstants;
use num_bigint::BigInt;

#[derive(Copy, Clone)]
pub enum Instruction {
    /// This gadget implements the Poseidon hash instance described in the
    /// top-level documentation of the interpreter [crate::interpreter]. In the
    /// current setup, with [NUMBER_OF_COLUMNS] columns, we can compute 5 full
    /// rounds per row.
    ///
    /// The first parameter is an index, which can be used by the environment to
    /// have more information on the values that have been absorbed previously.
    /// It can also be used by the control-flow method to know when to stop.
    ///
    /// We split the Poseidon gadget in 13 sub-gadgets, one for each set of 5
    /// full rounds and one for the absorbtion. The second parameter is the
    /// starting round of the permutation. It is expected to be a multiple of
    /// five. The absorption is defined by the instruction PoseidonSpongeAbsorb.
    PoseidonFullRound(usize, usize),
    /// Absorb [PlonkSpongeConstants::SPONGE_WIDTH - 1] elements into the
    /// sponge. The elements are absorbed into the last
    /// [PlonkSpongeConstants::SPONGE_WIDTH - 1] elements of the sponge state.
    ///
    /// The parameter can be used to know which value to absorb.
    PoseidonSpongeAbsorb(usize),

    EllipticCurveScaling(usize, u64),
    EllipticCurveAddition(usize),
    /// The NoOp will simply do nothing
    NoOp,
}

#[derive(Eq, Hash, PartialEq)]
pub enum Gadget {
    /// The following gadgets implement the Poseidon hash instance described in
    /// the top-level documentation. In the current setup, with
    /// [crate::NUMBER_OF_COLUMNS] columns, we can compute 5 full
    /// rounds per row.
    ///
    /// We split the Poseidon gadget in 13 sub-gadgets, one for each set of 5
    /// full rounds and one for the absorbtion. The parameter is the starting
    /// round of Poseidon. It is expected to be a multiple of five.
    PoseidonFullRound(usize),
    /// Absorb [PlonkSpongeConstants::SPONGE_WIDTH - 1] elements into the
    /// sponge. The elements are absorbed into the last
    /// [PlonkSpongeConstants::SPONGE_WIDTH - 1] elements of the permutation
    /// state.
    ///
    /// The values to be absorbed depend on the state of the environment while
    /// executing this instruction.
    PoseidonSpongeAbsorb,

    EllipticCurveScaling,
    EllipticCurveAddition,

    /// A dummy gadget, doing nothing. Use for padding.
    NoOp,
}

/// Convert an instruction into the corresponding gadget.
impl From<Instruction> for Gadget {
    fn from(val: Instruction) -> Gadget {
        match val {
            Instruction::NoOp => Gadget::NoOp,
            Instruction::PoseidonFullRound(_idx, starting_round) => {
                assert_eq!(starting_round % 5, 0);
                Gadget::PoseidonFullRound(starting_round)
            }
            Instruction::PoseidonSpongeAbsorb(_) => Gadget::PoseidonSpongeAbsorb,
            Instruction::EllipticCurveScaling(_i_comm, _s) => Gadget::EllipticCurveScaling,
            Instruction::EllipticCurveAddition(_i) => Gadget::EllipticCurveAddition,
        }
    }
}

pub struct Verifier<C> {
    _field: std::marker::PhantomData<C>,
}

impl<C> Default for Verifier<C> {
    fn default() -> Self {
        Self {
            _field: std::marker::PhantomData,
        }
    }
}

impl<C> ZkApp<C> for Verifier<C>
where
    C: ArrabbiataCurve,
    C::BaseField: PrimeField,
{
    type Instruction = Instruction;

    type Gadget = Gadget;

    fn dummy_witness(&self, _srs_size: usize) -> Vec<Vec<C::ScalarField>> {
        unimplemented!("Dummy witness for the verifier is not implemented yet")
    }

    /// Fetch the first instruction to execute.
    fn fetch_instruction(&self) -> Self::Instruction {
        Instruction::PoseidonSpongeAbsorb(0)
    }

    /// Describe the control-flow for the verifier circuit.
    fn fetch_next_instruction(
        &self,
        current_instruction: Self::Instruction,
    ) -> Option<Self::Instruction> {
        match current_instruction {
            Instruction::PoseidonFullRound(idx, starting_round) => {
                assert_eq!(starting_round % 5, 0);
                // Executing five full rounds of Poseidon until we reach the last
                // set of five rounds.
                if starting_round < PlonkSpongeConstants::PERM_ROUNDS_FULL - 5 {
                    Some(Instruction::PoseidonFullRound(idx, starting_round + 5))
                } else {
                    // When we reach the last set of five rounds, either we
                    // continue absorbing or we stop, for now.
                    if idx < NUMBER_OF_COLUMNS - 1 {
                        Some(Instruction::PoseidonSpongeAbsorb(idx + 1))
                    } else {
                        Some(Instruction::NoOp)
                    }
                }
            }
            Instruction::PoseidonSpongeAbsorb(idx) => {
                assert!(
                    idx < NUMBER_OF_COLUMNS,
                    "By construction, this case should not happen"
                );
                // After absorbing we automatically run the permutation.
                Some(Instruction::PoseidonFullRound(idx, 0))
            }
            Instruction::EllipticCurveScaling(i_comm, bit) => {
                // TODO: we still need to substract (or not?) the blinder.
                // Maybe we can avoid this by aggregating them.
                // TODO: we also need to aggregate the cross-terms.
                // Therefore i_comm must also take into the account the number
                // of cross-terms.
                assert!(i_comm < NUMBER_OF_COLUMNS, "Maximum number of columns reached ({NUMBER_OF_COLUMNS}), increase the number of columns");
                assert!(bit < MAXIMUM_FIELD_SIZE_IN_BITS, "Maximum number of bits reached ({MAXIMUM_FIELD_SIZE_IN_BITS}), increase the number of bits");
                if bit < 255 - 1 {
                    Some(Instruction::EllipticCurveScaling(i_comm, bit + 1))
                } else if i_comm < NUMBER_OF_COLUMNS - 1 {
                    Some(Instruction::EllipticCurveScaling(i_comm + 1, 0))
                } else {
                    // We have computed all the bits for all the columns
                    Some(Instruction::NoOp)
                }
            }
            Instruction::EllipticCurveAddition(i_comm) => {
                if i_comm < NUMBER_OF_COLUMNS - 1 {
                    Some(Instruction::EllipticCurveAddition(i_comm + 1))
                } else {
                    Some(Instruction::NoOp)
                }
            }
            // Whenever we reach a NoOp, we stop the execution.
            Instruction::NoOp => None,
        }
    }

    fn run<E: InterpreterEnv>(&self, env: &mut E, instr: Self::Instruction) {
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
                // FIXME: we do add the blinder. We must substract it at the end.
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
                    unsafe {
                        env.is_same_ec_point(pos, x1.clone(), y1.clone(), x2.clone(), y2.clone())
                    }
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
            Instruction::PoseidonFullRound(_idx, starting_round) => {
                assert!(
                    starting_round < PlonkSpongeConstants::PERM_ROUNDS_FULL,
                    "Invalid round index. Only values below {} are allowed.",
                    PlonkSpongeConstants::PERM_ROUNDS_FULL
                );
                assert!(
                    starting_round % 5 == 0,
                    "Invalid round index. Only values that are multiple of 5 are allowed."
                );
                debug!(
                    "Executing instruction Poseidon starting from round {starting_round} to {}",
                    starting_round + 5
                );

                let round_input_positions: Vec<E::Position> = (0
                    ..PlonkSpongeConstants::SPONGE_WIDTH)
                    .map(|_i| env.allocate())
                    .collect();

                let round_output_positions: Vec<E::Position> = (0
                    ..PlonkSpongeConstants::SPONGE_WIDTH)
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
            Instruction::PoseidonSpongeAbsorb(_idx) => {
                let round_input_positions: Vec<E::Position> = (0
                    ..PlonkSpongeConstants::SPONGE_WIDTH - 1)
                    .map(|_i| env.allocate())
                    .collect();

                let state: Vec<E::Variable> = round_input_positions
                    .iter()
                    .enumerate()
                    .map(|(i, pos)| env.load_poseidon_state(*pos, i + 1))
                    .collect();

                let values_to_absorb: Vec<E::Variable> = (0..PlonkSpongeConstants::SPONGE_WIDTH
                    - 1)
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
    }
}
