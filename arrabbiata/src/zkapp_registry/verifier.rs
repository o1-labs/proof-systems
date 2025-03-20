//! This module contains a generic verifier for Arrabbiata.
//!
//! The verifier is implemented as a ZkApp, and is responsible to build the
//! verification of a previous execution trace.
//!
//! Considering the verifier as a ZkApp allows to reuse the same interface.
//! Also, it eases the development of other verifiers, as the interface is
//! generic and can be reused.

use crate::{
    column::Gadget,
    curve::{ArrabbiataCurve, PlonkSpongeConstants},
    interpreter::{self, Instruction, InterpreterEnv, VERIFIER_STARTING_INSTRUCTION},
    zkapp_registry::ZkApp,
    MAXIMUM_FIELD_SIZE_IN_BITS, NUMBER_OF_COLUMNS, VERIFIER_CIRCUIT_SIZE,
};
use ark_ec::CurveConfig;
use ark_ff::PrimeField;
use mina_poseidon::constants::SpongeConstants;
use poly_commitment::commitment::CommitmentCurve;

pub struct Verifier<C: ArrabbiataCurve>
where
    C::BaseField: PrimeField,
    <<C as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
{
    pub _field: std::marker::PhantomData<C>,
}

impl<C: ArrabbiataCurve> ZkApp<C> for Verifier<C>
where
    C::BaseField: PrimeField,
    <<C as CommitmentCurve>::Params as CurveConfig>::BaseField: PrimeField,
{
    type Instruction = interpreter::Instruction;

    type Gadget = column::Gadget;

    fn dummy_witness(&self, _srs_size: usize) -> Vec<Vec<C::ScalarField>> {
        unimplemented!("Dummy witness for the verifier is not implemented yet")
    }

    /// Describe the control-flow for the verifier circuit.
    fn fetch_next_instruction(&self, current_instruction: Self::Instruction) -> Self::Instruction {
        match current_instruction {
            Self::Instruction::PoseidonFullRound(i) => {
                if i < PlonkSpongeConstants::PERM_ROUNDS_FULL - 5 {
                    Instruction::PoseidonFullRound(i + 5)
                } else {
                    // FIXME: for now, we continue absorbing because the current
                    // code, while fetching the values to absorb, raises an
                    // exception when we absorbed everythimg, and the main file
                    // handles the halt by filling as many rows as expected (see
                    // [VERIFIER_CIRCUIT_SIZE]).
                    Self::Instruction::PoseidonSpongeAbsorb
                }
            }
            Self::Instruction::PoseidonSpongeAbsorb => {
                // Whenever we absorbed a value, we run the permutation.
                Self::Instruction::PoseidonFullRound(0)
            }
            Self::Instruction::EllipticCurveScaling(i_comm, bit) => {
                // TODO: we still need to substract (or not?) the blinder.
                // Maybe we can avoid this by aggregating them.
                // TODO: we also need to aggregate the cross-terms.
                // Therefore i_comm must also take into the account the number
                // of cross-terms.
                assert!(i_comm < NUMBER_OF_COLUMNS, "Maximum number of columns reached ({NUMBER_OF_COLUMNS}), increase the number of columns");
                assert!(bit < MAXIMUM_FIELD_SIZE_IN_BITS, "Maximum number of bits reached ({MAXIMUM_FIELD_SIZE_IN_BITS}), increase the number of bits");
                if bit < 255 - 1 {
                    Self::Instruction::EllipticCurveScaling(i_comm, bit + 1)
                } else if i_comm < NUMBER_OF_COLUMNS - 1 {
                    Self::Instruction::EllipticCurveScaling(i_comm + 1, 0)
                } else {
                    // We have computed all the bits for all the columns
                    Self::Instruction::NoOp
                }
            }
            Self::Instruction::EllipticCurveAddition(i_comm) => {
                if i_comm < NUMBER_OF_COLUMNS - 1 {
                    Self::Instruction::EllipticCurveAddition(i_comm + 1)
                } else {
                    Self::Instruction::NoOp
                }
            }
            Self::Instruction::NoOp => Self::Instruction::NoOp,
        }
    }

    fn run<E: InterpreterEnv>(&self, env: &mut E, instr: Self::Instruction) {
        let mut current_instr = VERIFIER_STARTING_INSTRUCTION;
        for _i in 0..VERIFIER_CIRCUIT_SIZE - 1 {
            interpreter::run(env, current_instr);
            current_instr = self.fetch_next_instruction(current_instr);
            env.reset();
        }
        // FIXME: additional row for the Poseidon hash
        env.reset();
    }

    fn setup(&self, app_size: usize) -> Vec<Gadget> {
        let mut circuit: Vec<Gadget> = vec![];
        let mut curr_instruction = VERIFIER_STARTING_INSTRUCTION;
        for _i in 0..app_size - 1 {
            circuit.push(Gadget::from(curr_instruction));
            curr_instruction = self.fetch_next_instruction(curr_instruction);
        }
        // Additional row for the Poseidon hash
        circuit.push(Gadget::NoOp);
        assert_eq!(circuit.len(), app_size);
        circuit
    }
}
